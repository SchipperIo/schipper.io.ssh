using System.Net;
using Schipper.Io.Ssh.Server;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Transport;

namespace Schipper.Io.Ssh.Tests;

/// <summary>Hosts an <see cref="SshServer"/> on an ephemeral loopback port for the duration of a test.</summary>
internal sealed class TestServer : IAsyncDisposable
{
    private readonly CancellationTokenSource _cts;
    private readonly Task _run;
    private bool _disposed;

    private TestServer(SshServer server, CancellationTokenSource cts, Task run)
    {
        Server = server;
        _cts = cts;
        _run = run;
    }

    public SshServer Server { get; }

    public int Port => Server.Port;

    public static async Task<TestServer> StartAsync(SshHostKey hostKey, SshConnectionHandler handler, SshServerOptions? options = null)
    {
        var cts = new CancellationTokenSource();
        SshServer server = options is null
            ? new SshServer(new IPEndPoint(IPAddress.Loopback, 0), handler, hostKey)
            : new SshServer(new IPEndPoint(IPAddress.Loopback, 0), handler, hostKey, options);

        Task run = server.RunAsync(cts.Token);
        while (server.Port == 0)
        {
            if (run.IsCompleted)
            {
                await run; // surfaces the startup failure
                throw new InvalidOperationException("The SSH server stopped before binding.");
            }

            await Task.Delay(10);
        }

        return new TestServer(server, cts, run);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _cts.CancelAsync();
        try
        {
            await _run;
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }

        _cts.Dispose();
    }
}

internal static class TestSessionExtensions
{
    /// <summary>Reads exactly <paramref name="count"/> bytes from the session or throws at EOF.</summary>
    public static async Task<byte[]> ReadExactlyAsync(this SshSession session, int count, CancellationToken cancellationToken = default)
    {
        var buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = await session.ReadAsync(buffer.AsMemory(offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException($"Session ended after {offset} of {count} bytes.");
            }

            offset += read;
        }

        return buffer;
    }
}
