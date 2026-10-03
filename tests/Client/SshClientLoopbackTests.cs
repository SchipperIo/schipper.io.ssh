using System.Security.Authentication;
using System.Security.Cryptography;
using Schipper.Io.Ssh.Client;
using Schipper.Io.Ssh.Server;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Tests;
using Schipper.Io.Ssh.Transport;

namespace Schipper.Io.Ssh.Tests.Client;

[TestClass]
public sealed class SshClientLoopbackTests
{
    private const int TestTimeout = 30000;

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task ShellSessionRoundTripsBytesBothWays()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            await session.WriteAsync("hi!"u8.ToArray(), ct);
            byte[] echoed = await session.ReadExactlyAsync(5, ct);
            await session.WriteAsync(echoed, ct);
        });

        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);

        CollectionAssert.AreEqual("hi!"u8.ToArray(), await session.ReadExactlyAsync(3));
        await session.WriteAsync("hello"u8.ToArray());
        CollectionAssert.AreEqual("hello"u8.ToArray(), await session.ReadExactlyAsync(5));

        // The server handler returns and closes the channel — the client sees EOF.
        var one = new byte[1];
        Assert.AreEqual(0, await session.ReadAsync(one));
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task HostKeyVerifierReceivesTheServerKeyBlob()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, (session, context, ct) => Task.CompletedTask);

        byte[]? seenBlob = null;
        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey,
            blob =>
            {
                seenBlob = blob.ToArray();
                return true;
            });

        Assert.IsNotNull(seenBlob);
        CollectionAssert.AreEqual(hostKey.PublicKeyBlob(), seenBlob);
        Assert.AreEqual(hostKey.Fingerprint, Convert.ToHexStringLower(SHA256.HashData(seenBlob)));
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task RejectingHostKeyVerifierAbortsTheConnection()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, (session, context, ct) => Task.CompletedTask);

        await Assert.ThrowsExactlyAsync<AuthenticationException>(async () =>
            await SshClient.ConnectAsync("127.0.0.1", server.Port, "tester", clientKey, _ => false));
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task SubsystemSessionRoundTripsBytes()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        var options = new SshServerOptions
        {
            Subsystems = new Dictionary<string, SshSubsystemHandler>(StringComparer.Ordinal)
            {
                ["echo"] = async (session, context, ct) =>
                {
                    byte[] data = await session.ReadExactlyAsync(4, ct);
                    await session.WriteAsync(data, ct);
                },
            },
        };

        await using TestServer server = await TestServer.StartAsync(
            hostKey, (session, context, ct) => Task.CompletedTask, options);

        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true, subsystem: "echo");

        Assert.AreEqual(0, session.Columns);
        Assert.AreEqual(0, session.Rows);
        Assert.IsNull(session.TerminalType);

        await session.WriteAsync("ping"u8.ToArray());
        CollectionAssert.AreEqual("ping"u8.ToArray(), await session.ReadExactlyAsync(4));
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task UnknownSubsystemSurfacesAsAnException()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, (session, context, ct) => Task.CompletedTask);

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await SshClient.ConnectAsync("127.0.0.1", server.Port, "tester", clientKey, _ => true, subsystem: "no-such-subsystem"));
    }
}
