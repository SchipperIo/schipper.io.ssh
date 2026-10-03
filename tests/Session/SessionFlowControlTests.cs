using Schipper.Io.Ssh.Client;
using Schipper.Io.Ssh.Server;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Tests;
using Schipper.Io.Ssh.Transport;

namespace Schipper.Io.Ssh.Tests.Session;

[TestClass]
public sealed class SessionFlowControlTests
{
    private const int TestTimeout = 30000;
    private const int ReceiveWindow = SshSession.ReceiveWindowBytes;

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task WriteBlocksWhenPeerHasNotConsumedTheWindow()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();
        var serverReady = new TaskCompletionSource<SshSession>(TaskCreationOptions.RunContinuationsAsynchronously);
        var allowRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            serverReady.SetResult(session);
            await allowRead.Task.WaitAsync(ct);
            byte[] drained = await session.ReadExactlyAsync(4 << 20, ct);
            Assert.AreEqual(4 << 20, drained.Length);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);
        SshSession serverSession = await serverReady.Task;

        ValueTask write = client.WriteAsync(new byte[4 << 20]);
        await WaitUntilAsync(() => serverSession.BufferedIncomingCount == ReceiveWindow);
        Assert.IsFalse(write.IsCompleted);
        Assert.AreEqual(ReceiveWindow, serverSession.BufferedIncomingCount);

        allowRead.SetResult();
        await write;
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task WindowOpensOnlyAsTheApplicationReads()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();
        var serverReady = new TaskCompletionSource<SshSession>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            serverReady.SetResult(session);
            await Task.Delay(Timeout.Infinite, ct);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);
        SshSession serverSession = await serverReady.Task;

        ValueTask first = client.WriteAsync(new byte[ReceiveWindow]);
        await WaitUntilAsync(() => serverSession.BufferedIncomingCount == ReceiveWindow);
        await first;

        ValueTask extra = client.WriteAsync(new byte[100]);
        await Task.Delay(100);
        Assert.IsFalse(extra.IsCompleted);
        Assert.AreEqual(ReceiveWindow, serverSession.BufferedIncomingCount);

        var one = new byte[1];
        Assert.AreEqual(1, await serverSession.ReadAsync(one));
        await WaitUntilAsync(() => serverSession.BufferedIncomingCount == ReceiveWindow);
        Assert.IsFalse(extra.IsCompleted);

        var drain = new byte[8192];
        int remaining = ReceiveWindow + 99;
        while (remaining > 0)
        {
            int read = await serverSession.ReadAsync(drain);
            Assert.IsTrue(read > 0);
            remaining -= read;
        }

        await extra;
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task ChannelEofIsReadEofAndWritesStillWork()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            await session.WriteAsync("HEAD"u8.ToArray(), ct);
            await session.CompleteWritesAsync(ct);
            byte[] reply = await session.ReadExactlyAsync(4, ct);
            CollectionAssert.AreEqual("TAIL"u8.ToArray(), reply);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);

        CollectionAssert.AreEqual("HEAD"u8.ToArray(), await client.ReadExactlyAsync(4));
        var one = new byte[1];
        Assert.AreEqual(0, await client.ReadAsync(one));
        await client.WriteAsync("TAIL"u8.ToArray());
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task ClientHalfCloseLetsTheServerReply()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            var buffer = new byte[16];
            var received = new List<byte>();
            while (true)
            {
                int read = await session.ReadAsync(buffer, ct);
                if (read == 0)
                {
                    break;
                }

                received.AddRange(buffer.AsSpan(0, read).ToArray());
            }

            CollectionAssert.AreEqual("ping"u8.ToArray(), received.ToArray());
            await session.WriteAsync("pong"u8.ToArray(), ct);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);
        await client.WriteAsync("ping"u8.ToArray());
        await client.CompleteWritesAsync();
        CollectionAssert.AreEqual("pong"u8.ToArray(), await client.ReadExactlyAsync(4));
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task TransportDropThrowsFromReadAsync()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            connected.SetResult();
            await Task.Delay(Timeout.Infinite, ct);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);
        await connected.Task;

        ValueTask<int> pending = client.ReadAsync(new byte[16]);
        await server.DisposeAsync();
        await Assert.ThrowsExactlyAsync<IOException>(async () => await pending);
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task ExtendedDataCountsAgainstTheWindowAndIsCredited()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            int remaining = ReceiveWindow + 1;
            var chunk = new byte[32768];
            while (remaining > 0)
            {
                int n = Math.Min(remaining, chunk.Length);
                await session.SendExtendedDataAsync(1, chunk.AsMemory(0, n), ct);
                remaining -= n;
            }

            await session.WriteAsync(new byte[] { 42 }, ct);
            await Task.Delay(Timeout.Infinite, ct);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);
        var one = new byte[1];
        Assert.AreEqual(1, await client.ReadAsync(one));
        Assert.AreEqual(42, one[0]);
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task WriteAsyncThrowsWhenTheConnectionDiesOnAnEmptySendWindow()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();
        var serverReady = new TaskCompletionSource<SshSession>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            serverReady.SetResult(session);
            await Task.Delay(Timeout.Infinite, ct);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);
        SshSession serverSession = await serverReady.Task;

        ValueTask first = client.WriteAsync(new byte[ReceiveWindow]);
        await WaitUntilAsync(() => serverSession.BufferedIncomingCount == ReceiveWindow);
        await first;

        ValueTask blocked = client.WriteAsync(new byte[64 * 1024]);
        await Task.Delay(100);
        Assert.IsFalse(blocked.IsCompleted);

        await server.DisposeAsync();
        await Assert.ThrowsExactlyAsync<IOException>(async () => await blocked);
        await Assert.ThrowsExactlyAsync<IOException>(async () => await client.ReadAsync(new byte[1]));
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task DirectionalEofDoesNotFailWrites()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        await using TestServer server = await TestServer.StartAsync(hostKey, async (session, context, ct) =>
        {
            await session.CompleteWritesAsync(ct);
            byte[] body = await session.ReadExactlyAsync(3, ct);
            CollectionAssert.AreEqual("xyz"u8.ToArray(), body);
        });

        await using SshSession client = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);
        var one = new byte[1];
        Assert.AreEqual(0, await client.ReadAsync(one));
        await client.WriteAsync("xyz"u8.ToArray());
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (int i = 0; i < 200; i++)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(25);
        }

        Assert.Fail("Timed out waiting for the session condition.");
    }
}
