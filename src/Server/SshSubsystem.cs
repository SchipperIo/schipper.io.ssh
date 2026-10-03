using Schipper.Io.Ssh.Session;

namespace Schipper.Io.Ssh.Server;

/// <summary>
/// Handles a fully established SSH <c>subsystem</c> channel for one connection. Subsystem sessions
/// carry no pty: <see cref="SshSession.Columns"/>/<see cref="SshSession.Rows"/> are 0 and
/// <see cref="SshSession.TerminalType"/> is null; the session is a plain bidirectional byte channel.
/// </summary>
public delegate Task SshSubsystemHandler(SshSession session, ConnectionContext context, CancellationToken cancellationToken);
