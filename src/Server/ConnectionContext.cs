using Schipper.Io.Ssh.Session;

namespace Schipper.Io.Ssh.Server;

/// <summary>Metadata about an inbound connection, passed to the connection handler alongside the session.</summary>
public sealed record ConnectionContext(string Transport, string RemoteEndPoint, string? TerminalType = null)
{
    /// <summary>The username presented in the SSH userauth request, when one was parsed.</summary>
    public string? Username { get; init; }

    /// <summary>
    /// When the client authenticated with a verified <c>publickey</c> signature, the lowercase-hex
    /// SHA-256 fingerprint of its public key blob (same form as <see cref="SshHostKey.Fingerprint"/>);
    /// null for <c>none</c>/<c>password</c> auth or when no public-key authenticator is configured.
    /// </summary>
    public string? PublicKeyFingerprint { get; init; }
}

/// <summary>
/// Handles a fully established SSH session for one connection. The session is a bidirectional byte
/// channel that also reports terminal size and resize events; the application adapts it to whatever
/// terminal/rendering abstraction it uses.
/// </summary>
public delegate Task SshConnectionHandler(SshSession session, ConnectionContext context, CancellationToken cancellationToken);
