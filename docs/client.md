# Client

[Index](README.md)

`SshClient.ConnectAsync` dials a server that speaks the same algorithm set, checks the host key, authenticates, and returns an `SshSession`.

```csharp
using System.Security.Cryptography;
using Schipper.Io.Ssh.Client;
using Schipper.Io.Ssh.Transport;

SshHostKey identity = SshHostKey.LoadOrCreate("client.key");

await using var session = await SshClient.ConnectAsync(
    host: "localhost",
    port: 2222,
    username: "ada",
    clientKey: identity,
    hostKeyVerifier: blob =>
        Convert.ToHexStringLower(SHA256.HashData(blob.Span)) == pinnedServerFingerprint,
    environment: new Dictionary<string, string>
    {
        ["LANG"] = "C.UTF-8",
    },
    log: line => logger.LogInformation("{Line}", line),
    cancellationToken: cancellationToken);

await session.WriteAsync("ping"u8.ToArray(), cancellationToken);
await session.CompleteWritesAsync(cancellationToken);
```

`CompleteWritesAsync` sends `SSH_MSG_CHANNEL_EOF` so the server can finish reading and still write a reply. Disposing the session closes the TCP connection. `await using` is the lifetime.

## Host key

The verifier runs after the server's exchange-hash signature has been checked against the key blob. Return false to abort. `ConnectAsync` then throws `AuthenticationException`.

The blob is the SSH wire public key (`SshHostKey.PublicKeyBlob` layout). Pin the SHA-256 of that blob, in lowercase hex, which is what `SshHostKey.Fingerprint` prints for a key you loaded locally:

```csharp
SshHostKey serverKey = SshHostKey.LoadOrCreate("host.key");
string pinnedServerFingerprint = serverKey.Fingerprint;
```

Pin a key you received out of band. The fingerprint of `clientKey` is the user identity, not the server.

## Authentication

The client signs with `clientKey` and offers `publickey`. If the server rejects it, the client falls back to `none`. Both failures throw `AuthenticationException`. A server built with this package accepts `none` even when `PublicKeyAuth` is set, and records a fingerprint only for a verified `publickey`. See [Server](server.md).

## Shell and subsystem

`subsystem: null` requests a shell. Client sessions are opened without a pty, so `Columns` and `Rows` are `0` and `TerminalType` is null.

```csharp
await using var session = await SshClient.ConnectAsync(
    host, port, username, identity, verifier,
    subsystem: "example",
    cancellationToken: cancellationToken);
```

`environment` pairs are sent as `env` requests before the shell or subsystem starts. The server copies them onto `SshSession.Environment`. Keys are case-sensitive.

## Failures

| Exception | Cause |
| --- | --- |
| `AuthenticationException` | The host-key signature failed, the verifier returned false, or user authentication failed |
| `InvalidOperationException` | The server rejected the channel, the shell, or the subsystem |
| `InvalidDataException` | The server sent a message the client cannot parse, or offered no matching algorithms |
| `IOException` | The connection dropped, a packet failed to decrypt, or the peer exceeded the channel window |

`log` receives the server identification line and authentication progress. Pass a logger when a handshake fails closed.
