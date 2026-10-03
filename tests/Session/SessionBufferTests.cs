using Schipper.Io.Ssh.Session;
using Schipper.Io.Ssh.Tests;
using Schipper.Io.Ssh.Transport;

namespace Schipper.Io.Ssh.Tests.Session;

/// <summary>
/// Exercises the growable ring buffer behind <see cref="SshSession.ReadAsync"/>: bulk write/read,
/// wrap-around, growth, and EOF semantics. The session is constructed over a throwaway transport;
/// bytes are injected directly through the internal <c>EnqueueIncoming</c>/<c>SignalEof</c> hooks.
/// </summary>
[TestClass]
public sealed class SessionBufferTests
{
    private static SshSession CreateSession() =>
        new(new SshTransport(new MemoryStream()), 0, 1 << 20, 32768, 1 << 20, 80, 24, null);

    private static byte[] Pattern(int offset, int count)
    {
        var bytes = new byte[count];
        for (int i = 0; i < count; i++)
        {
            bytes[i] = (byte)((offset + i) % 251); // prime modulus: no accidental 4096-alignment
        }

        return bytes;
    }

    [TestMethod]
    public async Task BulkEnqueueThenPiecewiseReadRoundTrips()
    {
        await using SshSession session = CreateSession();
        byte[] data = Pattern(0, 300);
        session.EnqueueIncoming(data);

        var all = new List<byte>(300);
        var chunk = new byte[100];
        while (all.Count < 300)
        {
            int read = await session.ReadAsync(chunk);
            Assert.IsTrue(read > 0);
            all.AddRange(chunk.AsSpan(0, read).ToArray());
        }

        CollectionAssert.AreEqual(data, all.ToArray());
    }

    [TestMethod]
    public async Task WrapAroundPreservesByteOrder()
    {
        await using SshSession session = CreateSession();

        // Advance the ring's read position, then enqueue enough to wrap past the end of the
        // initial 4096-byte buffer without triggering growth.
        session.EnqueueIncoming(Pattern(0, 3000));
        CollectionAssert.AreEqual(Pattern(0, 3000), await session.ReadExactlyAsync(3000));

        session.EnqueueIncoming(Pattern(3000, 1500));
        session.EnqueueIncoming(Pattern(4500, 1500));
        CollectionAssert.AreEqual(Pattern(3000, 3000), await session.ReadExactlyAsync(3000));
    }

    [TestMethod]
    public async Task GrowthLinearizesAndPreservesPendingBytes()
    {
        await using SshSession session = CreateSession();

        // Leave 2000 unread bytes mid-ring, then force growth past 4096.
        session.EnqueueIncoming(Pattern(0, 3000));
        CollectionAssert.AreEqual(Pattern(0, 1000), await session.ReadExactlyAsync(1000));
        session.EnqueueIncoming(Pattern(3000, 6000)); // 2000 + 6000 = 8000 > 4096 → grow

        CollectionAssert.AreEqual(Pattern(1000, 8000), await session.ReadExactlyAsync(8000));
    }

    [TestMethod]
    public async Task PendingReadWakesWhenDataArrives()
    {
        await using SshSession session = CreateSession();

        var buffer = new byte[16];
        ValueTask<int> pending = session.ReadAsync(buffer);
        Assert.IsFalse(pending.IsCompleted);

        session.EnqueueIncoming(new byte[] { 7, 8, 9 });
        int read = await pending;
        Assert.AreEqual(3, read);
        CollectionAssert.AreEqual(new byte[] { 7, 8, 9 }, buffer.AsSpan(0, 3).ToArray());
    }

    [TestMethod]
    public async Task EofWakesPendingReadWithZero()
    {
        await using SshSession session = CreateSession();

        var buffer = new byte[16];
        ValueTask<int> pending = session.ReadAsync(buffer);
        Assert.IsFalse(pending.IsCompleted);

        session.SignalEof();
        Assert.AreEqual(0, await pending);
    }

    [TestMethod]
    public async Task BufferedBytesRemainReadableAfterEof()
    {
        await using SshSession session = CreateSession();

        session.EnqueueIncoming(new byte[] { 1, 2, 3, 4 });
        session.SignalEof();

        CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, await session.ReadExactlyAsync(4));
        var one = new byte[1];
        Assert.AreEqual(0, await session.ReadAsync(one));
    }

    [TestMethod]
    public async Task EmptyEnqueueDoesNotWakeReaderWithZeroBytes()
    {
        await using SshSession session = CreateSession();

        session.EnqueueIncoming(ReadOnlySpan<byte>.Empty);
        session.EnqueueIncoming(new byte[] { 42 });

        var one = new byte[1];
        Assert.AreEqual(1, await session.ReadAsync(one));
        Assert.AreEqual(42, one[0]);
    }
}
