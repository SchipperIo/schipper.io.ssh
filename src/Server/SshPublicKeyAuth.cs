namespace Schipper.Io.Ssh.Server;

/// <summary>
/// Decides whether an <c>ecdsa-sha2-nistp256</c> public key may authenticate as
/// <paramref name="username"/>. The key blob is in SSH wire form (the
/// <see cref="SshHostKey.PublicKeyBlob"/> encoding); the server has already verified the client's
/// signature over the session before this is consulted for the final decision, and also calls it
/// during the RFC 4252 §7 query phase (no signature yet) to answer <c>SSH_MSG_USERAUTH_PK_OK</c>.
/// </summary>
public delegate bool SshPublicKeyAuthenticator(string username, ReadOnlyMemory<byte> publicKeyBlob);
