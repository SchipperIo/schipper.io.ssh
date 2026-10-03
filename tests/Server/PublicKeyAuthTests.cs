using System.Security.Cryptography;
using Schipper.Io.Ssh.Client;
using Schipper.Io.Ssh.Server;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Tests;
using Schipper.Io.Ssh.Transport;

namespace Schipper.Io.Ssh.Tests.Server;

[TestClass]
public sealed class PublicKeyAuthTests
{
    private const int TestTimeout = 30000;
    private const string Username = "chris";

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task AllowedKeyAuthenticatesAndRecordsFingerprint()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();
        byte[] allowedBlob = clientKey.PublicKeyBlob();

        var contextTcs = new TaskCompletionSource<ConnectionContext>(TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new SshServerOptions
        {
            PublicKeyAuth = (user, blob) => user == Username && blob.Span.SequenceEqual(allowedBlob),
        };

        await using TestServer server = await TestServer.StartAsync(
            hostKey,
            (session, context, ct) =>
            {
                contextTcs.TrySetResult(context);
                return Task.CompletedTask;
            },
            options);

        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, Username, clientKey, _ => true);

        ConnectionContext context = await contextTcs.Task;
        Assert.AreEqual(Username, context.Username);
        Assert.AreEqual(Convert.ToHexStringLower(SHA256.HashData(allowedBlob)), context.PublicKeyFingerprint);
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task DisallowedKeyFallsBackToNoneWithoutFingerprint()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        var contextTcs = new TaskCompletionSource<ConnectionContext>(TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new SshServerOptions
        {
            PublicKeyAuth = (user, blob) => false, // no key is allowed
        };

        await using TestServer server = await TestServer.StartAsync(
            hostKey,
            (session, context, ct) =>
            {
                contextTcs.TrySetResult(context);
                return Task.CompletedTask;
            },
            options);

        // The publickey attempt is refused; the client's "none" fallback still succeeds (the
        // application performs its own login), but no fingerprint is recorded.
        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, Username, clientKey, _ => true);

        ConnectionContext context = await contextTcs.Task;
        Assert.AreEqual(Username, context.Username);
        Assert.IsNull(context.PublicKeyFingerprint);
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task TamperedSignatureIsRejected()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();
        byte[] allowedBlob = clientKey.PublicKeyBlob();

        bool authenticatorSawSignedAttempt = false;
        var contextTcs = new TaskCompletionSource<ConnectionContext>(TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new SshServerOptions
        {
            PublicKeyAuth = (user, blob) =>
            {
                authenticatorSawSignedAttempt = true;
                return true;
            },
        };

        await using TestServer server = await TestServer.StartAsync(
            hostKey,
            (session, context, ct) =>
            {
                contextTcs.TrySetResult(context);
                return Task.CompletedTask;
            },
            options);

        SshClient.UserAuthSignatureMutator = signature =>
        {
            signature[^1] ^= 0xFF; // corrupt the ECDSA signature
            return signature;
        };

        try
        {
            await using SshSession session = await SshClient.ConnectAsync(
                "127.0.0.1", server.Port, Username, clientKey, _ => true);

            ConnectionContext context = await contextTcs.Task;

            // The forged signature must not authenticate the key: the server rejects it before ever
            // consulting the authenticator, and the client ends up on the "none" path.
            Assert.IsFalse(authenticatorSawSignedAttempt, "the authenticator must not be consulted for a bad signature");
            Assert.IsNull(context.PublicKeyFingerprint);
        }
        finally
        {
            SshClient.UserAuthSignatureMutator = null;
        }
    }

    [TestMethod]
    public void VerifySshSignatureRejectsMalformedAndForeignInput()
    {
        var key = SshHostKey.CreateEphemeral();
        byte[] data = RandomNumberGenerator.GetBytes(48);
        byte[] signature = key.SignSshBlob(data);
        byte[] blob = key.PublicKeyBlob();

        Assert.IsTrue(SshHostKey.VerifySshSignature(blob, data, signature));

        byte[] tamperedData = (byte[])data.Clone();
        tamperedData[0] ^= 0x01;
        Assert.IsFalse(SshHostKey.VerifySshSignature(blob, tamperedData, signature));

        byte[] otherBlob = SshHostKey.CreateEphemeral().PublicKeyBlob();
        Assert.IsFalse(SshHostKey.VerifySshSignature(otherBlob, data, signature));

        Assert.IsFalse(SshHostKey.VerifySshSignature(blob, data, new byte[] { 1, 2, 3 }));
        Assert.IsFalse(SshHostKey.VerifySshSignature(new byte[] { 9, 9 }, data, signature));
    }
}
