using System.Collections.ObjectModel;
using Schipper.Io.Ssh.Transport;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Session;

/// <summary>
/// A single SSH "session" channel surfaced as a bidirectional byte stream that also reports terminal
/// size (<see cref="Columns"/>/<see cref="Rows"/>) and resize (<see cref="Resized"/>). A background
/// pump reads channel packets, demultiplexing data (buffered for <see cref="ReadAsync"/>),
/// flow-control window adjusts, <c>window-change</c> requests (which fire <see cref="Resized"/>), and
/// EOF/close. Outbound writes are chunked to the peer's maximum packet size and throttled by its
/// receive window. Sessions without a pty (subsystems, client-side sessions) report
/// <see cref="Columns"/>/<see cref="Rows"/> of 0 and a null <see cref="TerminalType"/>.
/// </summary>
public sealed class SshSession : IAsyncDisposable
{
    internal const int ReceiveWindowBytes = 1 << 20;
    private const int InitialBufferSize = 4096;

    private readonly SshTransport _transport;
    private readonly uint _remoteChannel;
    private readonly int _maxSendPacket;

    private readonly object _inLock = new();
    private byte[] _incoming = new byte[InitialBufferSize];
    private int _incomingStart;
    private int _incomingCount;
    private TaskCompletionSource? _dataWaiter;
    private bool _readEof;
    private bool _writesCompleted;
    private Exception? _transportError;

    private readonly object _winLock = new();
    private long _sendWindow;
    private TaskCompletionSource? _windowWaiter;

    private long _receiveWindow;
    private CancellationTokenSource? _cts;
    private Task? _pump;
    private IDisposable[] _ownedResources = [];

    internal SshSession(
        SshTransport transport,
        uint remoteChannel,
        long initialSendWindow,
        int maxSendPacket,
        long initialReceiveWindow,
        int columns,
        int rows,
        string? terminalType,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        _transport = transport;
        _remoteChannel = remoteChannel;
        _sendWindow = initialSendWindow;
        _maxSendPacket = Math.Clamp(maxSendPacket, 1024, 32768);
        _receiveWindow = initialReceiveWindow;
        Columns = columns;
        Rows = rows;
        TerminalType = terminalType;
        Environment = environment ?? ReadOnlyDictionary<string, string>.Empty;
    }

    internal uint RemoteChannel => _remoteChannel;

    internal int BufferedIncomingCount
    {
        get
        {
            lock (_inLock)
            {
                return _incomingCount;
            }
        }
    }

    public int Columns { get; private set; }

    public int Rows { get; private set; }

    public string? TerminalType { get; }

    /// <summary>
    /// The <c>env</c> name/value pairs the client sent before starting the shell or subsystem
    /// (case-sensitive keys). Empty when none were sent.
    /// </summary>
    public IReadOnlyDictionary<string, string> Environment { get; }

    public event Action? Resized;

    /// <summary>Starts the background receive pump. Call once before using the terminal.</summary>
    internal void Start(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _pump = Task.Run(() => ReceiveLoopAsync(_cts.Token));
    }

    /// <summary>Transfers ownership of connection resources disposed with the session (client side).</summary>
    internal void OwnResources(params IDisposable[] resources) => _ownedResources = resources;

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            Task wait;
            int count = 0;
            lock (_inLock)
            {
                if (_incomingCount > 0)
                {
                    count = Math.Min(buffer.Length, _incomingCount);
                    Span<byte> dest = buffer.Span[..count];
                    int first = Math.Min(count, _incoming.Length - _incomingStart);
                    _incoming.AsSpan(_incomingStart, first).CopyTo(dest);
                    if (count > first)
                    {
                        _incoming.AsSpan(0, count - first).CopyTo(dest[first..]);
                    }

                    _incomingStart = (_incomingStart + count) % _incoming.Length;
                    _incomingCount -= count;
                    if (_incomingCount == 0)
                    {
                        _incomingStart = 0;
                    }
                }
                else if (_readEof)
                {
                    return 0;
                }
                else if (_transportError is not null)
                {
                    throw WrapTransportError(_transportError);
                }
                else
                {
                    _dataWaiter = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    wait = _dataWaiter.Task;
                    goto AwaitData;
                }
            }

            if (count > 0)
            {
                if (_pump is not null)
                {
                    await CreditConsumedAsync(count, cancellationToken).ConfigureAwait(false);
                }

                return count;
            }

            continue;

        AwaitData:
            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
    {
        int offset = 0;
        while (offset < bytes.Length)
        {
            ThrowIfTransportDead();

            Task? wait = null;
            int chunk = 0;
            lock (_winLock)
            {
                if (_transportError is not null)
                {
                    wait = null;
                    chunk = -1;
                }
                else if (_sendWindow <= 0)
                {
                    _windowWaiter = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    wait = _windowWaiter.Task;
                }
                else
                {
                    chunk = (int)Math.Min(Math.Min(bytes.Length - offset, _maxSendPacket), _sendWindow);
                    _sendWindow -= chunk;
                }
            }

            if (chunk < 0)
            {
                ThrowIfTransportDead();
            }

            if (wait is not null)
            {
                await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
                ThrowIfTransportDead();
                continue;
            }

            var w = new SshWriter();
            w.WriteByte(SshMessage.ChannelData);
            w.WriteUInt32(_remoteChannel);
            w.WriteString(bytes.Slice(offset, chunk).Span);
            try
            {
                await _transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.AuthenticationTagMismatchException)
            {
                FailTransport(ex);
                throw WrapTransportError(ex);
            }

            offset += chunk;
        }
    }

    /// <summary>
    /// Sends <c>SSH_MSG_CHANNEL_EOF</c> so the peer's next <see cref="ReadAsync"/> returns 0 after
    /// buffered bytes. The connection stays open for incoming data and for further local writes.
    /// </summary>
    public async ValueTask CompleteWritesAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfTransportDead();
        lock (_inLock)
        {
            if (_writesCompleted)
            {
                return;
            }

            _writesCompleted = true;
        }

        var w = new SshWriter();
        w.WriteByte(SshMessage.ChannelEof);
        w.WriteUInt32(_remoteChannel);
        try
        {
            await _transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.AuthenticationTagMismatchException)
        {
            FailTransport(ex);
            throw WrapTransportError(ex);
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                byte[]? payload = await _transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
                if (payload is null || payload.Length == 0)
                {
                    FailTransport(new IOException("The SSH connection closed unexpectedly."));
                    return;
                }

                if (!await DispatchAsync(payload, cancellationToken).ConfigureAwait(false))
                {
                    return;
                }
            }

            FailTransport(new IOException("The SSH session was canceled."));
        }
        catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested)
        {
            FailTransport(new IOException("The SSH session was canceled.", ex));
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.AuthenticationTagMismatchException)
        {
            FailTransport(ex);
        }
    }

    /// <summary>
    /// Handles one channel message; returns false to end the session. All parsing of the (ref-struct)
    /// reader happens synchronously up front so no span lives across an await.
    /// </summary>
    private async Task<bool> DispatchAsync(byte[] payload, CancellationToken cancellationToken)
    {
        byte message = payload[0];
        switch (message)
        {
            case SshMessage.ChannelData:
            {
                ReadOnlySpan<byte> data;
                {
                    var r = new SshReader(payload);
                    r.ReadByte();
                    r.ReadUInt32(); // recipient channel (ours)
                    data = r.ReadString();
                }

                if (!TryAcceptIncoming(data, enqueue: true))
                {
                    await DisconnectWindowExceededAsync(cancellationToken).ConfigureAwait(false);
                    return false;
                }

                return true;
            }

            case SshMessage.ChannelExtendedData:
            {
                ReadOnlySpan<byte> data;
                {
                    var r = new SshReader(payload);
                    r.ReadByte();
                    r.ReadUInt32(); // recipient channel
                    r.ReadUInt32(); // data_type_code
                    data = r.ReadString();
                }

                int discarded = data.Length;
                if (!TryAcceptIncoming(data, enqueue: false))
                {
                    await DisconnectWindowExceededAsync(cancellationToken).ConfigureAwait(false);
                    return false;
                }

                await CreditConsumedAsync(discarded, cancellationToken).ConfigureAwait(false);
                return true;
            }

            case SshMessage.ChannelWindowAdjust:
            {
                var r = new SshReader(payload);
                r.ReadByte();
                r.ReadUInt32();
                AddSendWindow(r.ReadUInt32());
                return true;
            }

            case SshMessage.ChannelRequest:
                await HandleChannelRequestAsync(payload, cancellationToken).ConfigureAwait(false);
                return true;

            case SshMessage.ChannelEof:
                SignalReadEof();
                return true;

            case SshMessage.ChannelClose:
                SignalReadEof();
                FailTransport(new IOException("The SSH channel was closed."));
                return false;

            case SshMessage.Disconnect:
                FailTransport(new IOException("The SSH connection was disconnected."));
                return false;

            case SshMessage.GlobalRequest:
            {
                var r = new SshReader(payload);
                r.ReadByte();
                r.ReadStringText();
                bool wantReply = r.ReadBoolean();
                if (wantReply)
                {
                    await _transport.WritePayloadAsync(new[] { SshMessage.RequestFailure }, cancellationToken).ConfigureAwait(false);
                }

                return true;
            }

            default:
                return true; // ignore (IGNORE, DEBUG, unknown)
        }
    }

    private async Task HandleChannelRequestAsync(byte[] payload, CancellationToken cancellationToken)
    {
        string type;
        bool wantReply;
        bool isResize = false;
        uint cols = 0;
        uint rows = 0;
        {
            var r = new SshReader(payload);
            r.ReadByte();
            r.ReadUInt32(); // recipient channel
            type = r.ReadStringText();
            wantReply = r.ReadBoolean();
            if (type == "window-change")
            {
                isResize = true;
                cols = r.ReadUInt32();
                rows = r.ReadUInt32();
            }
        }

        if (isResize)
        {
            Columns = cols > 0 ? (int)cols : Columns;
            Rows = rows > 0 ? (int)rows : Rows;
            Resized?.Invoke();
            return;
        }

        if (wantReply)
        {
            var w = new SshWriter();
            w.WriteByte(SshMessage.ChannelFailure);
            w.WriteUInt32(_remoteChannel);
            await _transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
        }
    }

    private bool TryAcceptIncoming(ReadOnlySpan<byte> data, bool enqueue)
    {
        TaskCompletionSource? waiter = null;
        lock (_inLock)
        {
            if (data.Length > _receiveWindow)
            {
                return false;
            }

            _receiveWindow -= data.Length;
            if (enqueue && data.Length > 0)
            {
                EnsureCapacity(_incomingCount + data.Length);
                int writePos = (_incomingStart + _incomingCount) % _incoming.Length;
                int first = Math.Min(data.Length, _incoming.Length - writePos);
                data[..first].CopyTo(_incoming.AsSpan(writePos));
                if (data.Length > first)
                {
                    data[first..].CopyTo(_incoming);
                }

                _incomingCount += data.Length;
                waiter = _dataWaiter;
                _dataWaiter = null;
            }
        }

        waiter?.TrySetResult();
        return true;
    }

    private async Task CreditConsumedAsync(int count, CancellationToken cancellationToken)
    {
        if (count <= 0 || _transportError is not null)
        {
            return;
        }

        lock (_inLock)
        {
            _receiveWindow += count;
        }

        var w = new SshWriter();
        w.WriteByte(SshMessage.ChannelWindowAdjust);
        w.WriteUInt32(_remoteChannel);
        w.WriteUInt32((uint)count);
        try
        {
            await _transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.AuthenticationTagMismatchException)
        {
            FailTransport(ex);
            throw WrapTransportError(ex);
        }
    }

    private async Task DisconnectWindowExceededAsync(CancellationToken cancellationToken)
    {
        FailTransport(new IOException("The peer exceeded the SSH channel window."));
        try
        {
            var w = new SshWriter();
            w.WriteByte(SshMessage.Disconnect);
            w.WriteUInt32(2); // SSH_DISCONNECT_PROTOCOL_ERROR
            w.WriteString("channel window exceeded");
            w.WriteString("en");
            await _transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException)
        {
            // Peer may already be gone.
        }
    }

    /// <summary>Appends received bytes to the growable ring buffer and wakes a pending reader.</summary>
    internal void EnqueueIncoming(ReadOnlySpan<byte> data)
    {
        TaskCompletionSource? waiter;
        lock (_inLock)
        {
            if (data.Length > 0)
            {
                EnsureCapacity(_incomingCount + data.Length);
                int writePos = (_incomingStart + _incomingCount) % _incoming.Length;
                int first = Math.Min(data.Length, _incoming.Length - writePos);
                data[..first].CopyTo(_incoming.AsSpan(writePos));
                if (data.Length > first)
                {
                    data[first..].CopyTo(_incoming);
                }

                _incomingCount += data.Length;
            }

            waiter = _dataWaiter;
            _dataWaiter = null;
        }

        waiter?.TrySetResult();
    }

    /// <summary>Grows the ring buffer by doubling, linearizing the content to offset 0. Caller holds <see cref="_inLock"/>.</summary>
    private void EnsureCapacity(int needed)
    {
        if (needed > ReceiveWindowBytes)
        {
            throw new InvalidDataException("Incoming SSH channel data exceeded the receive window.");
        }

        if (needed <= _incoming.Length)
        {
            return;
        }

        int newSize = _incoming.Length;
        while (newSize < needed)
        {
            int doubled = newSize * 2;
            if (doubled > ReceiveWindowBytes || doubled < newSize)
            {
                newSize = ReceiveWindowBytes;
                break;
            }

            newSize = doubled;
        }

        var next = new byte[newSize];
        int first = Math.Min(_incomingCount, _incoming.Length - _incomingStart);
        Array.Copy(_incoming, _incomingStart, next, 0, first);
        Array.Copy(_incoming, 0, next, first, _incomingCount - first);
        _incoming = next;
        _incomingStart = 0;
    }

    internal void SignalEof() => SignalReadEof();

    private void SignalReadEof()
    {
        TaskCompletionSource? dataWaiter;
        lock (_inLock)
        {
            _readEof = true;
            dataWaiter = _dataWaiter;
            _dataWaiter = null;
        }

        dataWaiter?.TrySetResult();
    }

    internal async Task SendExtendedDataAsync(uint dataType, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        var w = new SshWriter();
        w.WriteByte(SshMessage.ChannelExtendedData);
        w.WriteUInt32(_remoteChannel);
        w.WriteUInt32(dataType);
        w.WriteString(data.Span);
        await _transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private void FailTransport(Exception error)
    {
        TaskCompletionSource? dataWaiter;
        lock (_inLock)
        {
            _transportError ??= error;
            dataWaiter = _dataWaiter;
            _dataWaiter = null;
        }

        dataWaiter?.TrySetResult();

        TaskCompletionSource? windowWaiter;
        lock (_winLock)
        {
            windowWaiter = _windowWaiter;
            _windowWaiter = null;
        }

        windowWaiter?.TrySetResult();
    }

    private void ThrowIfTransportDead()
    {
        Exception? error = _transportError;
        if (error is not null)
        {
            throw WrapTransportError(error);
        }
    }

    private static IOException WrapTransportError(Exception error) =>
        error as IOException ?? new IOException("The SSH connection failed.", error);

    private void AddSendWindow(uint amount)
    {
        TaskCompletionSource? waiter;
        lock (_winLock)
        {
            _sendWindow += amount;
            waiter = _windowWaiter;
            _windowWaiter = null;
        }

        waiter?.TrySetResult();
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        if (_pump is not null)
        {
            try
            {
                await _pump.ConfigureAwait(false);
            }
            catch
            {
                // Pump already faulted/cancelled.
            }
        }

        _cts?.Dispose();

        foreach (IDisposable resource in _ownedResources)
        {
            resource.Dispose();
        }
    }
}
