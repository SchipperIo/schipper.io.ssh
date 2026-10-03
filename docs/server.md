# Server

[Index](README.md)

`SshServer` listens, completes key exchange, accepts one `session` channel, and hands you an `SshSession`.

```csharp
using System.Net;
using Schipper.Io.Ssh.Server;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Transport;

SshHostKey hostKey = SshHostKey.LoadOrCreate("host.key");

var server = new SshServer(
    new IPEndPoint(IPAddress.Any, 2222),
    HandleShellAsync,
    hostKey,
    log: line => logger.LogInformation("{Line}", line));

await server.RunAsync(cancellationToken);

static async Task HandleShellAsync(SshSession session, ConnectionContext context, CancellationToken cancellationToken)
{
    var buffer = new byte[4096];
    while (true)
    {
        int read = await session.ReadAsync(buffer, cancellationToken);
        if (read == 0)
        {
            // Peer sent SSH_MSG_CHANNEL_EOF. Writes can still go out until you return.
            return;
        }

        await session.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
    }
}
```

`RunAsync` binds the endpoint and accepts until the token is cancelled. `Port` is `0` until listen starts, then the bound port. Construct the endpoint with port `0` when you want an ephemeral port and read `Port` after accept has begun.

Each connection runs the handler on its own task. The handler returns when the session is finished. Dispose is owned by the server for an accepted shell. On the client, disposing the session closes the connection. See [Sessions and host keys](sessions-and-keys.md).

## ConnectionContext

| Member | When it is set |
| --- | --- |
| `Transport` | The literal `"ssh"` |
| `RemoteEndPoint` | `RemoteEndPoint.ToString()` of the accepted socket, or `"unknown"` |
| `TerminalType` | The pty terminal type. Null when the channel has no pty |
| `Username` | The username from the userauth request, when one was parsed |
| `PublicKeyFingerprint` | Lowercase hex SHA-256 of the client's public key blob, after a verified `publickey` authentication. Null otherwise |

The server disposes the session after the handler returns. The handler reads and writes, then returns. It does not call `DisposeAsync`.

`PublicKeyFingerprint` uses the same hex form as `SshHostKey.Fingerprint`.

## Authentication

The default constructor accepts every authentication method. The application then performs its own login on the session.

```csharp
var options = new SshServerOptions
{
    PublicKeyAuth = (username, publicKeyBlob) =>
        username == "ada" && Allow(publicKeyBlob),
};

var server = new SshServer(endpoint, HandleShellAsync, hostKey, options, log);
```

When `PublicKeyAuth` is set:

- A `publickey` attempt (`ecdsa-sha2-nistp256`) is signature-checked, then passed to the callback. Success stores `Username` and `PublicKeyFingerprint` on the context.
- `none` and `password` still succeed. They leave `PublicKeyFingerprint` null so the application can run its own login.

A connected handler is not proof of public-key authentication. Read `PublicKeyFingerprint` when that is the credential you require, or complete your own login before treating the channel as authenticated.

## Subsystems

A named subsystem is a `session` channel with no pty. `Columns` and `Rows` stay `0`, and `TerminalType` is null.

```csharp
var options = new SshServerOptions
{
    Subsystems = new Dictionary<string, SshSubsystemHandler>
    {
        ["example"] = HandleSubsystemAsync,
    },
};

static Task HandleSubsystemAsync(SshSession session, ConnectionContext context, CancellationToken cancellationToken)
{
    return PumpAsync(session, cancellationToken);
}
```

Names are case-sensitive. A request for an unknown name fails the channel. A request with no subsystem name takes the shell handler and the pty path.

The shell handler still runs for clients that open a shell. Subsystem handlers replace it only for their name.

## What the server speaks

One `session` channel. The algorithm set in the package index is the entire offer. A client that cannot agree on `ecdh-sha2-nistp256`, `ecdsa-sha2-nistp256`, and `aes256-gcm@openssh.com` fails the handshake. The server does not open forwarded ports.
