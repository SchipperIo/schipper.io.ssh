using System.Net.Sockets;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Transport;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Client;

/// <summary>
/// Verifies a server host key during connect. Receives the host key blob in SSH wire form (the
/// <see cref="SshHostKey.PublicKeyBlob"/> encoding) after its kex signature has already been checked;
/// the caller typically compares its SHA-256 fingerprint against a pinned value. Return false to
/// abort the connection.
/// </summary>
public delegate bool SshHostKeyVerifier(ReadOnlyMemory<byte> hostKeyBlob);

/// <summary>
/// A minimal SSH-2 client for the same single algorithm set as <see cref="SshServer"/>
/// (<c>ecdh-sha2-nistp256</c>, <c>ecdsa-sha2-nistp256</c> host keys, <c>aes256-gcm@openssh.com</c>).
/// Connects, verifies the host key via the caller's verifier, authenticates with <c>publickey</c>
/// (falling back to <c>none</c>), opens one <c>session</c> channel running a shell or a named
/// subsystem, and returns it as an <see cref="SshSession"/>. Client sessions have no pty:
/// <see cref="SshSession.Columns"/>/<see cref="SshSession.Rows"/> are 0.
/// </summary>
public static class SshClient
{
    private const string ClientVersion = "SSH-2.0-Shelly_0.1";
    private const int LocalChannel = 0;
    private const long ReceiveWindow = 1 << 20;
    private const int OurMaxPacket = 32768;

    /// <summary>Test hook: mutates the userauth signature blob before it is sent (tamper injection).</summary>
    internal static Func<byte[], byte[]>? UserAuthSignatureMutator { get; set; }

    /// <summary>
    /// Connects to an SSH server and returns a ready session. <paramref name="subsystem"/> selects a
    /// named subsystem instead of a shell; <paramref name="environment"/> pairs are sent as <c>env</c>
    /// requests before the shell/subsystem starts. Disposing the returned session closes the connection.
    /// </summary>
    /// <exception cref="AuthenticationException">
    /// The host key signature failed, the verifier rejected the host key, or user authentication failed.
    /// </exception>
    /// <exception cref="InvalidOperationException">The shell/subsystem or channel request was rejected.</exception>
    /// <exception cref="InvalidDataException">The server violated the protocol.</exception>
    public static async Task<SshSession> ConnectAsync(
        string host,
        int port,
        string username,
        SshHostKey clientKey,
        SshHostKeyVerifier hostKeyVerifier,
        string? subsystem = null,
        IReadOnlyDictionary<string, string>? environment = null,
        Action<string>? log = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentNullException.ThrowIfNull(clientKey);
        ArgumentNullException.ThrowIfNull(hostKeyVerifier);

        var client = new TcpClient();
        SshTransport? transport = null;
        try
        {
            await client.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            client.NoDelay = true;
            NetworkStream stream = client.GetStream();
            transport = new SshTransport(stream);

            // --- Version exchange ------------------------------------------------------------------
            await SshPacket.WriteVersionLineAsync(stream, ClientVersion, cancellationToken).ConfigureAwait(false);
            string serverVersion = await SshPacket.ReadVersionLineAsync(stream, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("The server sent no SSH identification line.");
            log?.Invoke($"SSH server version: {serverVersion}");

            // --- Key exchange ----------------------------------------------------------------------
            byte[] sessionId = await KeyExchangeAsync(transport, serverVersion, hostKeyVerifier, cancellationToken).ConfigureAwait(false);

            // --- Authentication --------------------------------------------------------------------
            await AuthenticateAsync(transport, username, clientKey, sessionId, log, cancellationToken).ConfigureAwait(false);

            // --- Session channel + shell/subsystem ---------------------------------------------------
            SshSession session = await OpenChannelAsync(transport, subsystem, environment, cancellationToken).ConfigureAwait(false);
            session.OwnResources(transport, client);
            session.Start(CancellationToken.None); // session lifetime is governed by DisposeAsync
            return session;
        }
        catch
        {
            transport?.Dispose();
            client.Dispose();
            throw;
        }
    }

    /// <summary>Runs the client side of KEXINIT + ECDH + NEWKEYS; returns the session id (first exchange hash H).</summary>
    private static async Task<byte[]> KeyExchangeAsync(
        SshTransport transport, string serverVersion, SshHostKeyVerifier hostKeyVerifier, CancellationToken cancellationToken)
    {
        byte[] clientKexInit = SshKex.BuildServerKexInit(); // the KEXINIT payload is role-agnostic
        await transport.WritePayloadAsync(clientKexInit, cancellationToken).ConfigureAwait(false);

        byte[] serverKexInit = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
        if (serverKexInit[0] != SshMessage.KexInit)
        {
            throw new InvalidDataException("Expected SSH_MSG_KEXINIT from the server.");
        }

        if (!SshKex.ClientSupportsOurAlgorithms(serverKexInit, out bool guessedKex, out bool firstKexFollows))
        {
            throw new InvalidDataException("The server offers no matching SSH algorithms.");
        }

        if (firstKexFollows && !guessedKex)
        {
            await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false); // discard wrong guess
        }

        using var clientEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters clientParams = clientEcdh.ExportParameters(includePrivateParameters: false);
        byte[] clientEphemeral = SshKex.EncodePoint(clientParams.Q.X!, clientParams.Q.Y!);

        var init = new SshWriter();
        init.WriteByte(SshMessage.KexEcdhInit);
        init.WriteString(clientEphemeral);
        await transport.WritePayloadAsync(init.ToArray(), cancellationToken).ConfigureAwait(false);

        byte[] reply = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
        if (reply[0] != SshMessage.KexEcdhReply)
        {
            throw new InvalidDataException("Expected SSH_MSG_KEX_ECDH_REPLY from the server.");
        }

        byte[] hostKeyBlob;
        byte[] serverEphemeral;
        byte[] signature;
        {
            var r = new SshReader(reply);
            r.ReadByte();
            hostKeyBlob = r.ReadString().ToArray();
            serverEphemeral = r.ReadString().ToArray();
            signature = r.ReadString().ToArray();
        }

        byte[] sharedBytes = SshKex.DeriveSharedSecret(clientEcdh, serverEphemeral);
        var shared = new BigInteger(sharedBytes, isUnsigned: true, isBigEndian: true);

        byte[] exchangeHash = SshKex.ComputeExchangeHash(
            ClientVersion, serverVersion, clientKexInit, serverKexInit, hostKeyBlob, clientEphemeral, serverEphemeral, shared);

        if (!SshHostKey.VerifySshSignature(hostKeyBlob, exchangeHash, signature))
        {
            throw new AuthenticationException("The server's host key signature is invalid.");
        }

        if (!hostKeyVerifier(hostKeyBlob))
        {
            throw new AuthenticationException("The server's host key was rejected by the verifier.");
        }

        await transport.WritePayloadAsync(new[] { SshMessage.NewKeys }, cancellationToken).ConfigureAwait(false);
        byte[] serverNewKeys = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
        if (serverNewKeys[0] != SshMessage.NewKeys)
        {
            throw new InvalidDataException("Expected SSH_MSG_NEWKEYS from the server.");
        }

        // Client role: client-to-server secrets are our send direction, server-to-client our receive.
        (byte[] ivCs, byte[] ivSc, byte[] keyCs, byte[] keySc) = SshKex.DeriveKeys(shared, exchangeHash, exchangeHash);
        transport.EnableEncryption(keyCs, ivCs, keySc, ivSc);

        return exchangeHash;
    }

    private static async Task AuthenticateAsync(
        SshTransport transport, string username, SshHostKey clientKey, byte[] sessionId, Action<string>? log, CancellationToken cancellationToken)
    {
        var serviceRequest = new SshWriter();
        serviceRequest.WriteByte(SshMessage.ServiceRequest);
        serviceRequest.WriteString("ssh-userauth");
        await transport.WritePayloadAsync(serviceRequest.ToArray(), cancellationToken).ConfigureAwait(false);

        byte[] serviceReply = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
        if (serviceReply[0] != SshMessage.ServiceAccept)
        {
            throw new InvalidDataException("The server did not accept the ssh-userauth service.");
        }

        // Signed publickey attempt (RFC 4252 §7): the signature covers string(session-id) || request.
        byte[] keyBlob = clientKey.PublicKeyBlob();
        var body = new SshWriter();
        body.WriteByte(SshMessage.UserAuthRequest);
        body.WriteString(username);
        body.WriteString("ssh-connection");
        body.WriteString("publickey");
        body.WriteBoolean(true);
        body.WriteString(SshAlgorithms.HostKey);
        body.WriteString(keyBlob);
        byte[] bodyBytes = body.ToArray();

        byte[] signedData = new SshWriter().WriteString(sessionId).WriteRaw(bodyBytes).ToArray();
        byte[] signature = clientKey.SignSshBlob(signedData);
        if (UserAuthSignatureMutator is not null)
        {
            signature = UserAuthSignatureMutator(signature);
        }

        byte[] pkRequest = new SshWriter().WriteRaw(bodyBytes).WriteString(signature).ToArray();
        await transport.WritePayloadAsync(pkRequest, cancellationToken).ConfigureAwait(false);

        byte[] response = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
        if (response[0] == SshMessage.UserAuthSuccess)
        {
            return;
        }

        if (response[0] != SshMessage.UserAuthFailure)
        {
            throw new InvalidDataException($"Unexpected userauth response message {response[0]}.");
        }

        // Fall back to "none" — the server may accept anything (application-level login).
        log?.Invoke("SSH publickey auth rejected; falling back to none.");
        var none = new SshWriter();
        none.WriteByte(SshMessage.UserAuthRequest);
        none.WriteString(username);
        none.WriteString("ssh-connection");
        none.WriteString("none");
        await transport.WritePayloadAsync(none.ToArray(), cancellationToken).ConfigureAwait(false);

        response = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
        if (response[0] != SshMessage.UserAuthSuccess)
        {
            throw new AuthenticationException("SSH user authentication failed.");
        }
    }

    private static async Task<SshSession> OpenChannelAsync(
        SshTransport transport, string? subsystem, IReadOnlyDictionary<string, string>? environment, CancellationToken cancellationToken)
    {
        var open = new SshWriter();
        open.WriteByte(SshMessage.ChannelOpen);
        open.WriteString("session");
        open.WriteUInt32(LocalChannel);
        open.WriteUInt32((uint)ReceiveWindow);
        open.WriteUInt32(OurMaxPacket);
        await transport.WritePayloadAsync(open.ToArray(), cancellationToken).ConfigureAwait(false);

        byte[] confirm = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
        if (confirm[0] == SshMessage.ChannelOpenFailure)
        {
            throw new InvalidOperationException("The server rejected the session channel.");
        }

        if (confirm[0] != SshMessage.ChannelOpenConfirmation)
        {
            throw new InvalidDataException("Expected SSH_MSG_CHANNEL_OPEN_CONFIRMATION from the server.");
        }

        uint remoteChannel;
        long sendWindow;
        int maxSendPacket;
        {
            var r = new SshReader(confirm);
            r.ReadByte();
            r.ReadUInt32(); // recipient channel (ours)
            remoteChannel = r.ReadUInt32();
            sendWindow = r.ReadUInt32();
            maxSendPacket = (int)Math.Min(r.ReadUInt32(), OurMaxPacket);
        }

        // env requests (no reply wanted) must precede the shell/subsystem start request.
        if (environment is not null)
        {
            foreach ((string name, string value) in environment)
            {
                var env = new SshWriter();
                env.WriteByte(SshMessage.ChannelRequest);
                env.WriteUInt32(remoteChannel);
                env.WriteString("env");
                env.WriteBoolean(false);
                env.WriteString(name);
                env.WriteString(value);
                await transport.WritePayloadAsync(env.ToArray(), cancellationToken).ConfigureAwait(false);
            }
        }

        var start = new SshWriter();
        start.WriteByte(SshMessage.ChannelRequest);
        start.WriteUInt32(remoteChannel);
        if (subsystem is not null)
        {
            start.WriteString("subsystem");
            start.WriteBoolean(true);
            start.WriteString(subsystem);
        }
        else
        {
            start.WriteString("shell");
            start.WriteBoolean(true);
        }

        await transport.WritePayloadAsync(start.ToArray(), cancellationToken).ConfigureAwait(false);

        // Wait for the start reply, folding any early window adjusts into the send window.
        while (true)
        {
            byte[] reply = await ReadMessageAsync(transport, cancellationToken).ConfigureAwait(false);
            byte message = reply[0];

            if (message == SshMessage.ChannelSuccess)
            {
                break;
            }

            if (message == SshMessage.ChannelFailure)
            {
                throw new InvalidOperationException(subsystem is null
                    ? "The server rejected the shell request."
                    : $"The server rejected the '{subsystem}' subsystem request.");
            }

            if (message == SshMessage.ChannelWindowAdjust)
            {
                var r = new SshReader(reply);
                r.ReadByte();
                r.ReadUInt32();
                sendWindow += r.ReadUInt32();
                continue;
            }

            // Anything else before the reply (global requests, etc.) is ignored.
        }

        // Client sessions carry no pty: Columns/Rows are 0 and TerminalType is null.
        return new SshSession(transport, remoteChannel, sendWindow, maxSendPacket, ReceiveWindow, 0, 0, null, environment);
    }

    /// <summary>Reads the next payload, skipping IGNORE/DEBUG/banner messages; throws at end of stream.</summary>
    private static async Task<byte[]> ReadMessageAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        while (true)
        {
            byte[]? payload = await transport.ReadPayloadAsync(cancellationToken).ConfigureAwait(false);
            if (payload is null || payload.Length == 0)
            {
                throw new InvalidDataException("The connection closed during the SSH handshake.");
            }

            byte message = payload[0];
            if (message is SshMessage.Ignore or SshMessage.Debug or SshMessage.UserAuthBanner)
            {
                continue;
            }

            if (message == SshMessage.Disconnect)
            {
                throw new InvalidDataException("The server disconnected during the SSH handshake.");
            }

            return payload;
        }
    }
}
