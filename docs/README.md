# Schipper.Io.Ssh

A from-scratch SSH-2 client and server for .NET 10. One session channel, one algorithm set, BCL cryptography only.

| Role | Algorithm |
| --- | --- |
| Key exchange | `ecdh-sha2-nistp256` |
| Host key | `ecdsa-sha2-nistp256` |
| Cipher | `aes256-gcm@openssh.com` |
| Compression | `none` |

The identification string is `SSH-2.0-Shelly_0.1` on both sides. There is no port forwarding and no terminal emulation. `SshSession` is a byte channel plus window size.

## Guides

| Guide | What it covers |
| --- | --- |
| [Server](server.md) | `SshServer`, authentication, subsystems |
| [Client](client.md) | `SshClient.ConnectAsync` |
| [Sessions and host keys](sessions-and-keys.md) | `SshSession`, `SshHostKey`, wire helpers |

## Namespaces

| Namespace | Types |
| --- | --- |
| `Schipper.Io.Ssh.Server` | `SshServer`, `SshServerOptions`, `ConnectionContext`, `SshConnectionHandler`, `SshSubsystemHandler`, `SshPublicKeyAuthenticator` |
| `Schipper.Io.Ssh.Client` | `SshClient`, `SshHostKeyVerifier` |
| `Schipper.Io.Ssh.Session` | `SshSession` |
| `Schipper.Io.Ssh.Transport` | `SshHostKey`, `SshTransport`, `SshKex` |
| `Schipper.Io.Ssh.Wire` | `SshPacket`, `SshReader`, `SshWriter` |

## Package

```xml
<PackageReference Include="Schipper.Io.Ssh" Version="0.1.0-dev" />
```

Target framework: `net10.0`. The package has no dependencies.
