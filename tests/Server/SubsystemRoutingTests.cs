using Schipper.Io.Ssh.Client;
using Schipper.Io.Ssh.Server;
using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Tests;
using Schipper.Io.Ssh.Transport;

namespace Schipper.Io.Ssh.Tests.Server;

[TestClass]
public sealed class SubsystemRoutingTests
{
    private const int TestTimeout = 30000;

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task ShellAndSubsystemRequestsReachTheirOwnHandlers()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        int shellCalls = 0;
        int subsystemCalls = 0;
        var options = new SshServerOptions
        {
            Subsystems = new Dictionary<string, SshSubsystemHandler>(StringComparer.Ordinal)
            {
                ["data"] = (session, context, ct) =>
                {
                    Interlocked.Increment(ref subsystemCalls);
                    return Task.CompletedTask;
                },
            },
        };

        await using TestServer server = await TestServer.StartAsync(
            hostKey,
            (session, context, ct) =>
            {
                Interlocked.Increment(ref shellCalls);
                return Task.CompletedTask;
            },
            options);

        await using (SshSession shell = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true))
        {
            var one = new byte[1];
            Assert.AreEqual(0, await shell.ReadAsync(one)); // handler done, channel closed
        }

        Assert.AreEqual(1, shellCalls);
        Assert.AreEqual(0, subsystemCalls);

        await using (SshSession subsystem = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true, subsystem: "data"))
        {
            var one = new byte[1];
            Assert.AreEqual(0, await subsystem.ReadAsync(one));
        }

        Assert.AreEqual(1, shellCalls);
        Assert.AreEqual(1, subsystemCalls);
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task EnvRequestsBeforeShellAppearInSessionEnvironment()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        var environmentTcs = new TaskCompletionSource<IReadOnlyDictionary<string, string>>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using TestServer server = await TestServer.StartAsync(
            hostKey,
            (session, context, ct) =>
            {
                environmentTcs.TrySetResult(session.Environment);
                return Task.CompletedTask;
            });

        var sent = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["LANG"] = "en_US.UTF-8",
            ["SHELLY"] = "1",
        };

        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true, environment: sent);

        IReadOnlyDictionary<string, string> received = await environmentTcs.Task;
        Assert.AreEqual(2, received.Count);
        Assert.AreEqual("en_US.UTF-8", received["LANG"]);
        Assert.AreEqual("1", received["SHELLY"]);
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task EnvironmentIsEmptyWhenNoEnvRequestsWereSent()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        var environmentTcs = new TaskCompletionSource<IReadOnlyDictionary<string, string>>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using TestServer server = await TestServer.StartAsync(
            hostKey,
            (session, context, ct) =>
            {
                environmentTcs.TrySetResult(session.Environment);
                return Task.CompletedTask;
            });

        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true);

        IReadOnlyDictionary<string, string> received = await environmentTcs.Task;
        Assert.AreEqual(0, received.Count);
    }

    [TestMethod]
    [Timeout(TestTimeout)]
    public async Task EnvRequestsAlsoReachSubsystemSessions()
    {
        var hostKey = SshHostKey.CreateEphemeral();
        var clientKey = SshHostKey.CreateEphemeral();

        var sessionTcs = new TaskCompletionSource<(IReadOnlyDictionary<string, string> Environment, int Columns, int Rows, string? Term)>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new SshServerOptions
        {
            Subsystems = new Dictionary<string, SshSubsystemHandler>(StringComparer.Ordinal)
            {
                ["data"] = (session, context, ct) =>
                {
                    sessionTcs.TrySetResult((session.Environment, session.Columns, session.Rows, session.TerminalType));
                    return Task.CompletedTask;
                },
            },
        };

        await using TestServer server = await TestServer.StartAsync(
            hostKey, (session, context, ct) => Task.CompletedTask, options);

        var sent = new Dictionary<string, string>(StringComparer.Ordinal) { ["MODE"] = "sync" };
        await using SshSession session = await SshClient.ConnectAsync(
            "127.0.0.1", server.Port, "tester", clientKey, _ => true, subsystem: "data", environment: sent);

        (IReadOnlyDictionary<string, string> environment, int columns, int rows, string? term) = await sessionTcs.Task;
        Assert.AreEqual("sync", environment["MODE"]);
        Assert.AreEqual(0, columns);   // subsystem sessions have no pty
        Assert.AreEqual(0, rows);
        Assert.IsNull(term);
    }
}
