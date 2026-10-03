using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Transport;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Server;

/// <summary>
/// A minimal SSH-2 server (RFC 4252–4254, RFC 5656) that speaks exactly the BCL-backed algorithm set
/// in <see cref="SshAlgorithms"/>: <c>ecdh-sha2-nistp256</c> key exchange, an <c>ecdsa-sha2-nistp256</c>
/// host key, and <c>aes256-gcm@openssh.com</c> for the transport. By default authentication is
/// accepted with any method — the application does its own login — and a single <c>session</c>
/// channel with a pty becomes an <see cref="SshSession"/> handed to the connection handler.
/// <see cref="SshServerOptions"/> optionally adds verified <c>publickey</c> auth and named
/// <c>subsystem</c> channels (no pty) dispatched to their own handlers.
/// </summary>
public sealed class SshServer
{
    private const string ServerVersion = "SSH-2.0-Shelly_0.1";
    private const int LocalChannel = 0;
    private const long ReceiveWindow = 1 << 20;
    private const int OurMaxPacket = 32768;

    private readonly IPEndPoint _endPoint;
    private readonly SshConnectionHandler _handler;
    private readonly SshHostKey _hostKey;
    private readonly SshServerOptions _options;
    private readonly Action<string>? _log;

    public SshServer(IPEndPoint endPoint, SshConnectionHandler handler, SshHostKey hostKey, Action<string>? log = null)
        : this(endPoint, handler, hostKey, new SshServerOptions(), log)
    {
    }

    public SshServer(IPEndPoint endPoint, SshConnectionHandler handler, SshHostKey hostKey, SshServerOptions options, Action<string>? log = null)
    {
        ArgumentNullException.ThrowIfNull(endPoint);
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(hostKey);
        ArgumentNullException.ThrowIfNull(options);
        _endPoint = endPoint;
        _handler = handler;
        _hostKey = hostKey;
        _options = options;
        _log = log;
    }

    /// <summary>
    /// The actual bound port once <see cref="RunAsync"/> is listening (useful when constructed with
    /// port 0 for an ephemeral port); 0 until then.
    /// </summary>
    public int Port { get; private set; }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(_endPoint);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _log?.Invoke($"SSH listening on {listener.LocalEndpoint}");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                _ = HandleClientAsync(client, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        string remote = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        try
        {
            client.NoDelay = true;
            await using NetworkStream stream = client.GetStream();
            using var transport = new SshTransport(stream);

            (SshSession Session, string? Subsystem, string? Username, string? Fingerprint)? result =
                await HandshakeAsync(stream, transport, remote, cts.Token).ConfigureAwait(false);
            if (result is null)
            {
                return;
            }

            (SshSession session, string? subsystem, string? username, string? fingerprint) = result.Value;
            await using (session)
            {
                session.Start(cts.Token);
                var context = new ConnectionContext("ssh", remote, session.TerminalType)
                {
                    Username = username,
                    PublicKeyFingerprint = fingerprint,
                };

                if (subsystem is not null && _options.Subsystems.TryGetValue(subsystem, out SshSubsystemHandler? subsystemHandler))
                {
                    await subsystemHandler(session, context, cts.Token).ConfigureAwait(false);
                }
                else
                {
                    await _handler(session, context, cts.Token).ConfigureAwait(false);
                }

                await CloseChannelAsync(transport, session, cts.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or InvalidDataException or AuthenticationTagMismatchException)
        {
            // Disconnect, protocol error, or forged packet — expected, end quietly.
        }
        catch (Exception ex)
        {
            _log?.Invoke($"SSH session error ({remote}): {ex.Message}");
        }
        finally
        {
            client.Dispose();
            _log?.Invoke($"SSH disconnect {remote}");
        }
    }

    /// <summary>Runs version exchange, key exchange, auth, and channel setup; returns a ready session.</summary>
    private async Task<(SshSession Session, string? Subsystem, string? Username, string? Fingerprint)?> HandshakeAsync(
        NetworkStream stream, SshTransport transport, string remote, CancellationToken cancellationToken)
    {
        await SshPacket.WriteVersionLineAsync(stream, ServerVersion, cancellationToken).ConfigureAwait(false);
        string? clientVersion = await SshPacket.ReadVersionLineAsync(stream, cancellationToken).ConfigureAwait(false);
        if (clientVersion is null)
        {
            return null;
        }

        // --- Key exchange ------------------------------------------------------------------------
        byte[] serverKexInit = SshKex.BuildServerKexInit();
        await transport.WritePayloadAsync(serverKexInit, cancellationToken).ConfigureAwait(false);

        byte[]? clientKexInit = await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
        if (clientKexInit is null || clientKexInit[0] != SshMessage.KexInit)
        {
            return null;
        }

        if (!SshKex.ClientSupportsOurAlgorithms(clientKexInit, out bool guessedKex, out bool firstKexFollows))
        {
            await DisconnectAsync(transport, "no matching algorithms", cancellationToken).ConfigureAwait(false);
            return null;
        }

        if (firstKexFollows && !guessedKex)
        {
            await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false); // discard wrong guess
        }

        byte[]? ecdhInit = await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
        if (ecdhInit is null || ecdhInit[0] != SshMessage.KexEcdhInit)
        {
            return null;
        }

        var initReader = new SshReader(ecdhInit);
        initReader.ReadByte();
        byte[] clientEphemeral = initReader.ReadString().ToArray();

        using var serverEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters serverParams = serverEcdh.ExportParameters(includePrivateParameters: false);
        byte[] serverEphemeral = SshKex.EncodePoint(serverParams.Q.X!, serverParams.Q.Y!);

        byte[] sharedBytes = SshKex.DeriveSharedSecret(serverEcdh, clientEphemeral);
        var shared = new BigInteger(sharedBytes, isUnsigned: true, isBigEndian: true);

        byte[] hostKeyBlob = _hostKey.PublicKeyBlob();
        byte[] exchangeHash = SshKex.ComputeExchangeHash(
            clientVersion, ServerVersion, clientKexInit, serverKexInit, hostKeyBlob, clientEphemeral, serverEphemeral, shared);
        byte[] signature = _hostKey.SignExchangeHash(exchangeHash);

        var reply = new SshWriter();
        reply.WriteByte(SshMessage.KexEcdhReply);
        reply.WriteString(hostKeyBlob);
        reply.WriteString(serverEphemeral);
        reply.WriteString(signature);
        await transport.WritePayloadAsync(reply.ToArray(), cancellationToken).ConfigureAwait(false);

        await transport.WritePayloadAsync(new[] { SshMessage.NewKeys }, cancellationToken).ConfigureAwait(false);
        byte[]? clientNewKeys = await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
        if (clientNewKeys is null || clientNewKeys[0] != SshMessage.NewKeys)
        {
            return null;
        }

        (byte[] ivCs, byte[] ivSc, byte[] keyCs, byte[] keySc) = SshKex.DeriveKeys(shared, exchangeHash, exchangeHash);
        transport.EnableEncryption(keySc, ivSc, keyCs, ivCs);

        // --- Authentication ----------------------------------------------------------------------
        // The session id is the first exchange hash (RFC 4253 §7.2) — publickey signatures cover it.
        (bool authenticated, string? username, string? fingerprint) =
            await AuthenticateAsync(transport, exchangeHash, cancellationToken).ConfigureAwait(false);
        if (!authenticated)
        {
            return null;
        }

        // --- Channel + pty + shell/subsystem -------------------------------------------------------
        (SshSession Session, string? Subsystem)? channel = await OpenSessionChannelAsync(transport, cancellationToken).ConfigureAwait(false);
        if (channel is null)
        {
            return null;
        }

        return (channel.Value.Session, channel.Value.Subsystem, username, fingerprint);
    }

    private async Task<(bool Authenticated, string? Username, string? Fingerprint)> AuthenticateAsync(
        SshTransport transport, byte[] sessionId, CancellationToken cancellationToken)
    {
        byte[]? service = await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
        if (service is null || service[0] != SshMessage.ServiceRequest)
        {
            return (false, null, null);
        }

        var accept = new SshWriter();
        accept.WriteByte(SshMessage.ServiceAccept);
        accept.WriteString("ssh-userauth");
        await transport.WritePayloadAsync(accept.ToArray(), cancellationToken).ConfigureAwait(false);

        while (true)
        {
            byte[]? request = await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
            if (request is null)
            {
                return (false, null, null);
            }

            if (request[0] != SshMessage.UserAuthRequest)
            {
                continue;
            }

            if (_options.PublicKeyAuth is null)
            {
                // Historic behavior: accept the first auth request of any method — the BBS performs
                // its own login. Record the username when the request parses.
                await transport.WritePayloadAsync(new[] { SshMessage.UserAuthSuccess }, cancellationToken).ConfigureAwait(false);
                return (true, TryParseUsername(request), null);
            }

            AuthRequest? parsed = ParseAuthRequest(request);
            if (parsed is null)
            {
                await SendAuthFailureAsync(transport, cancellationToken).ConfigureAwait(false);
                continue;
            }

            AuthRequest auth = parsed.Value;
            if (auth.Method != "publickey")
            {
                // none/password still succeed (application-level login), but without a fingerprint.
                await transport.WritePayloadAsync(new[] { SshMessage.UserAuthSuccess }, cancellationToken).ConfigureAwait(false);
                return (true, auth.Username, null);
            }

            if (auth.Algorithm != SshAlgorithms.HostKey || auth.KeyBlob is null)
            {
                await SendAuthFailureAsync(transport, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (!auth.HasSignature)
            {
                // Query phase (RFC 4252 §7): tell the client whether this key is worth signing with.
                if (_options.PublicKeyAuth(auth.Username, auth.KeyBlob))
                {
                    var pkOk = new SshWriter();
                    pkOk.WriteByte(SshMessage.UserAuthPkOk);
                    pkOk.WriteString(auth.Algorithm);
                    pkOk.WriteString(auth.KeyBlob);
                    await transport.WritePayloadAsync(pkOk.ToArray(), cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await SendAuthFailureAsync(transport, cancellationToken).ConfigureAwait(false);
                }

                continue;
            }

            // Signed phase: the signature covers string(session-id) || the request up to the signature.
            byte[] signedData = new SshWriter()
                .WriteString(sessionId)
                .WriteRaw(request.AsSpan(0, auth.SignedLength))
                .ToArray();

            if (auth.Signature is not null
                && SshHostKey.VerifySshSignature(auth.KeyBlob, signedData, auth.Signature)
                && _options.PublicKeyAuth(auth.Username, auth.KeyBlob))
            {
                await transport.WritePayloadAsync(new[] { SshMessage.UserAuthSuccess }, cancellationToken).ConfigureAwait(false);
                return (true, auth.Username, Convert.ToHexStringLower(SHA256.HashData(auth.KeyBlob)));
            }

            await SendAuthFailureAsync(transport, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task SendAuthFailureAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        var failure = new SshWriter();
        failure.WriteByte(SshMessage.UserAuthFailure);
        failure.WriteNameList(["publickey", "password"]);
        failure.WriteBoolean(false); // partial success
        await transport.WritePayloadAsync(failure.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private static string? TryParseUsername(byte[] request)
    {
        try
        {
            var r = new SshReader(request);
            r.ReadByte();
            return r.ReadStringText();
        }
        catch (EndOfStreamException)
        {
            return null;
        }
    }

    private readonly record struct AuthRequest(
        string Username,
        string Method,
        bool HasSignature,
        string Algorithm,
        byte[]? KeyBlob,
        byte[]? Signature,
        int SignedLength);

    /// <summary>Parses an <c>SSH_MSG_USERAUTH_REQUEST</c>, including the publickey fields; null when malformed.</summary>
    private static AuthRequest? ParseAuthRequest(byte[] request)
    {
        try
        {
            var r = new SshReader(request);
            r.ReadByte();
            string username = r.ReadStringText();
            r.ReadStringText(); // service name ("ssh-connection")
            string method = r.ReadStringText();

            if (method != "publickey")
            {
                return new AuthRequest(username, method, false, "", null, null, 0);
            }

            bool hasSignature = r.ReadBoolean();
            string algorithm = r.ReadStringText();
            byte[] keyBlob = r.ReadString().ToArray();
            if (!hasSignature)
            {
                return new AuthRequest(username, method, false, algorithm, keyBlob, null, 0);
            }

            int signedLength = r.Position; // everything before the signature field is signed
            byte[] signature = r.ReadString().ToArray();
            return new AuthRequest(username, method, true, algorithm, keyBlob, signature, signedLength);
        }
        catch (EndOfStreamException)
        {
            return null;
        }
    }

    private async Task<(SshSession Session, string? Subsystem)?> OpenSessionChannelAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        uint remoteChannel = 0;
        long sendWindow = 0;
        int maxSendPacket = OurMaxPacket;
        int cols = 80;
        int rows = 24;
        string? term = null;
        bool channelOpen = false;
        Dictionary<string, string>? environment = null;

        while (true)
        {
            byte[]? payload = await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
            if (payload is null)
            {
                return null;
            }

            var r = new SshReader(payload);
            byte message = r.ReadByte();

            switch (message)
            {
                case SshMessage.ChannelOpen:
                {
                    string type = r.ReadStringText();
                    uint sender = r.ReadUInt32();
                    uint initialWindow = r.ReadUInt32();
                    uint peerMaxPacket = r.ReadUInt32();

                    if (type != "session")
                    {
                        await ChannelOpenFailureAsync(transport, sender, cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    remoteChannel = sender;
                    sendWindow = initialWindow;
                    maxSendPacket = (int)Math.Min(peerMaxPacket, OurMaxPacket);
                    channelOpen = true;

                    var confirm = new SshWriter();
                    confirm.WriteByte(SshMessage.ChannelOpenConfirmation);
                    confirm.WriteUInt32(sender);
                    confirm.WriteUInt32(LocalChannel);
                    confirm.WriteUInt32((uint)ReceiveWindow);
                    confirm.WriteUInt32(OurMaxPacket);
                    await transport.WritePayloadAsync(confirm.ToArray(), cancellationToken).ConfigureAwait(false);
                    break;
                }

                case SshMessage.ChannelRequest when channelOpen:
                {
                    r.ReadUInt32(); // recipient (ours)
                    string type = r.ReadStringText();
                    bool wantReply = r.ReadBoolean();

                    if (type == "pty-req")
                    {
                        term = r.ReadStringText();
                        uint ptyCols = r.ReadUInt32();
                        uint ptyRows = r.ReadUInt32();
                        cols = ptyCols > 0 ? (int)ptyCols : 80;
                        rows = ptyRows > 0 ? (int)ptyRows : 24;
                        await ChannelReplyAsync(transport, remoteChannel, success: true, wantReply, cancellationToken).ConfigureAwait(false);
                    }
                    else if (type == "shell")
                    {
                        await ChannelReplyAsync(transport, remoteChannel, success: true, wantReply, cancellationToken).ConfigureAwait(false);
                        return (new SshSession(transport, remoteChannel, sendWindow, maxSendPacket, ReceiveWindow, cols, rows, term, environment), null);
                    }
                    else if (type == "subsystem")
                    {
                        string name = r.ReadStringText();
                        if (_options.Subsystems.ContainsKey(name))
                        {
                            await ChannelReplyAsync(transport, remoteChannel, success: true, wantReply, cancellationToken).ConfigureAwait(false);
                            // Subsystem sessions have no pty: Columns/Rows are 0 and TerminalType is null.
                            return (new SshSession(transport, remoteChannel, sendWindow, maxSendPacket, ReceiveWindow, 0, 0, null, environment), name);
                        }

                        await ChannelReplyAsync(transport, remoteChannel, success: false, wantReply, cancellationToken).ConfigureAwait(false);
                    }
                    else if (type == "env")
                    {
                        string name = r.ReadStringText();
                        string value = r.ReadStringText();
                        (environment ??= new Dictionary<string, string>(StringComparer.Ordinal))[name] = value;
                        await ChannelReplyAsync(transport, remoteChannel, success: true, wantReply, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await ChannelReplyAsync(transport, remoteChannel, success: false, wantReply, cancellationToken).ConfigureAwait(false);
                    }

                    break;
                }

                case SshMessage.GlobalRequest:
                {
                    r.ReadStringText();
                    if (r.ReadBoolean())
                    {
                        await transport.WritePayloadAsync(new[] { SshMessage.RequestFailure }, cancellationToken).ConfigureAwait(false);
                    }

                    break;
                }
            }
        }
    }

    private static async Task ChannelReplyAsync(SshTransport transport, uint channel, bool success, bool wantReply, CancellationToken cancellationToken)
    {
        if (!wantReply)
        {
            return;
        }

        var w = new SshWriter();
        w.WriteByte(success ? SshMessage.ChannelSuccess : SshMessage.ChannelFailure);
        w.WriteUInt32(channel);
        await transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private static async Task ChannelOpenFailureAsync(SshTransport transport, uint sender, CancellationToken cancellationToken)
    {
        var w = new SshWriter();
        w.WriteByte(SshMessage.ChannelOpenFailure);
        w.WriteUInt32(sender);
        w.WriteUInt32(3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
        w.WriteString("only session channels are supported");
        w.WriteString("en");
        await transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private static async Task CloseChannelAsync(SshTransport transport, SshSession session, CancellationToken cancellationToken)
    {
        try
        {
            var eof = new SshWriter();
            eof.WriteByte(SshMessage.ChannelEof);
            eof.WriteUInt32(session.RemoteChannel);
            await transport.WritePayloadAsync(eof.ToArray(), cancellationToken).ConfigureAwait(false);

            var close = new SshWriter();
            close.WriteByte(SshMessage.ChannelClose);
            close.WriteUInt32(session.RemoteChannel);
            await transport.WritePayloadAsync(close.ToArray(), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
            // The client may already be gone.
        }
    }

    private static async Task DisconnectAsync(SshTransport transport, string reason, CancellationToken cancellationToken)
    {
        var w = new SshWriter();
        w.WriteByte(SshMessage.Disconnect);
        w.WriteUInt32(2); // SSH_DISCONNECT_PROTOCOL_ERROR
        w.WriteString(reason);
        w.WriteString("en");
        await transport.WritePayloadAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);
    }
}
