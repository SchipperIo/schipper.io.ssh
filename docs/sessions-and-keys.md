# Sessions and host keys

[Index](README.md)

`SshSession` is the channel. `SshHostKey` is the ECDSA P-256 key used as a server host key and as a client identity.

## SshSession

| Member | Meaning |
| --- | --- |
| `ReadAsync` | Copies buffered channel data. Returns `0` after `SSH_MSG_CHANNEL_EOF` once the buffer is empty. Throws `IOException` when the connection fails |
| `WriteAsync` | Sends bytes, split to the peer's max packet and throttled by its window. Throws `IOException` if the connection dies, including while waiting for window credit |
| `CompleteWritesAsync` | Sends `SSH_MSG_CHANNEL_EOF` without closing the socket. The peer then sees read EOF; local writes still work |
| `Columns`, `Rows` | Pty size in cells. `0` when the channel has no pty |
| `TerminalType` | Pty name. Null when there is no pty |
| `Environment` | `env` pairs the client sent. Empty when none were sent |
| `Resized` | Raised after a `window-change` request updates `Columns` and `Rows` |
| `DisposeAsync` | Closes the channel. On a client session, also closes the connection |

```csharp
session.Resized += () =>
{
    int columns = session.Columns;
    int rows = session.Rows;
};

var buffer = new byte[8192];
int n = await session.ReadAsync(buffer, cancellationToken);
if (n > 0)
{
    await session.WriteAsync(buffer.AsMemory(0, n), cancellationToken);
}
```

Reads block until data arrives, the peer sends `SSH_MSG_CHANNEL_EOF`, or the token fires. A dropped TCP connection, a short read, or a decryption failure throws `IOException` instead of returning `0`. Writes wait when the peer's receive window is empty, then continue; they throw if the transport dies while waiting. `CompleteWritesAsync` is the half-close: it tells the peer that this side will send no more channel data.

The advertised receive window is 1 MiB. Incoming `CHANNEL_DATA` and `CHANNEL_EXTENDED_DATA` count against it. Extended data is discarded and credited immediately. Stdout is credited only after `ReadAsync` copies those bytes to the caller. A peer that sends more than the outstanding window is disconnected.

Adapt the session to a terminal library at the edge of your application. This package does not decode ANSI or draw a screen. `Schipper.Io.Ansi.ITerminal` and `Schipper.Io.Xterm.Transport.ITerminal` are separate types. A thin adapter implements one of them by forwarding `ReadAsync`, `WriteAsync`, `Columns`, `Rows`, and `Resized`.

## SshHostKey

```csharp
SshHostKey key = SshHostKey.LoadOrCreate("host.key");
SshHostKey ephemeral = SshHostKey.CreateEphemeral();

string fingerprint = key.Fingerprint;       // lowercase hex SHA-256 of the public blob
byte[] blob = key.PublicKeyBlob();          // SSH wire public key
byte[] signature = key.SignSshBlob(data);   // SSH signature over data
bool ok = SshHostKey.VerifySshSignature(blob, data, signature);
```

`LoadOrCreate` reads a DER `ECPrivateKey` from `path`, or generates a P-256 key and writes that file. The directory is created when it is missing. The same file across restarts is what clients pin in `known_hosts`.

`CreateEphemeral` is an in-memory key. Use it in tests. A server that uses a new ephemeral key on every process start presents a different host key each time.

| Method | Use |
| --- | --- |
| `Algorithm` | `"ecdsa-sha2-nistp256"` |
| `PublicKeyBlob` | The blob the verifier and `PublicKeyAuth` receive |
| `SignSshBlob` / `VerifySshSignature` | SSH wire signatures |
| `SignExchangeHash` / `VerifyExchangeHash` | The key-exchange hash, signed the same way |
| `SignData` / `VerifyData` | Raw ECDSA over the bytes |
| `ImportPublicKeyBlob` | Parses a blob back to an `ECDsa` public key, or null when the blob is not this algorithm |

`Fingerprint` hashes `PublicKeyBlob()` with SHA-256 and prints lowercase hex. Compare fingerprints with that encoding on both sides.

The private key stays inside `SshHostKey`. Callers that need to prove identity use `SignSshBlob`. Callers that need to check a peer use `VerifySshSignature` or `VerifyData`.

## Wire helpers

Application code uses `SshServer` and `SshClient`. The types below are public because the handshake and the packet loop are built from them.

| Type | Role |
| --- | --- |
| `SshPacket` | `EncodeUnencrypted`, `DecodeUnencrypted`, `WriteUnencryptedAsync`, and `ReadUnencryptedAsync` for the cleartext packet frame |
| `SshReader` | A `ref struct` over an SSH payload: `byte`, `bool`, `uint`, `ulong`, `string`, name-list, `mpint` |
| `SshWriter` | The matching builder. `ToArray` returns the payload |
| `SshTransport` | A stream plus `EnableEncryption`, `WritePayloadAsync`, and `ReadPayloadAsync` after keys are installed |
| `SshKex` | The ECDH P-256 handshake: `KEXINIT`, point encode, shared secret, exchange hash, and the IV and key derivation |

`SshReader` and `SshWriter` follow SSH wire strings (a `uint32` length, then bytes) and `mpint`. `SshPacket.EncodeUnencrypted` and `DecodeUnencrypted` frame a payload before encryption is enabled. After `NEWKEYS`, `SshTransport` frames `aes256-gcm@openssh.com` packets.

Message numbers and algorithm name constants used inside the handshake are internal. The public contract is the algorithm set in the [index](README.md) and the methods above.
