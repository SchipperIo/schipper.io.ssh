using System.Collections.ObjectModel;

namespace Schipper.Io.Ssh.Server;

/// <summary>
/// Optional server behavior beyond the classic pty/shell path: named <c>subsystem</c> handlers and
/// <c>publickey</c> user authentication. The parameterless <see cref="SshServer"/> constructor uses
/// the defaults (no subsystems, accept-anything auth).
/// </summary>
public sealed class SshServerOptions
{
    /// <summary>
    /// Subsystem name → handler. A <c>subsystem</c> channel request naming a registered subsystem is
    /// confirmed and its <see cref="SshSession"/> (no pty; Columns/Rows 0) is dispatched to the
    /// handler instead of the shell handler; unknown names get a channel failure. Keys are case-sensitive.
    /// </summary>
    public IReadOnlyDictionary<string, SshSubsystemHandler> Subsystems { get; init; } =
        ReadOnlyDictionary<string, SshSubsystemHandler>.Empty;

    /// <summary>
    /// When null (default) authentication keeps the historic accept-anything behavior. When set,
    /// <c>publickey</c> attempts are signature-verified and passed to this authenticator (success
    /// records <see cref="ConnectionContext.Username"/> and
    /// <see cref="ConnectionContext.PublicKeyFingerprint"/>); <c>none</c>/<c>password</c> attempts
    /// still succeed (the application does its own login) but leave the fingerprint null.
    /// </summary>
    public SshPublicKeyAuthenticator? PublicKeyAuth { get; init; }
}
