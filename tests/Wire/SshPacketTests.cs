using System.Buffers.Binary;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Tests.Wire;

[TestClass]
public sealed class SshPacketTests
{
    [TestMethod]
    public void EncodedPacketIsBlockAligned()
    {
        byte[] packet = SshPacket.EncodeUnencrypted("hello world"u8);
        // Total length must be a multiple of 8.
        Assert.AreEqual(0, packet.Length % 8);
    }

    [TestMethod]
    public void EncodeHasAtLeastFourPaddingBytes()
    {
        byte[] packet = SshPacket.EncodeUnencrypted("x"u8);
        Assert.IsTrue(packet[4] >= 4, "padding length must be at least 4");
    }

    [TestMethod]
    public void PacketLengthFieldMatchesBody()
    {
        byte[] packet = SshPacket.EncodeUnencrypted("payload"u8);
        uint declared = BinaryPrimitives.ReadUInt32BigEndian(packet);
        Assert.AreEqual(packet.Length - 4, (int)declared);
    }

    [TestMethod]
    public void RoundTripsPayload()
    {
        byte[] original = "the quick brown fox"u8.ToArray();
        byte[] packet = SshPacket.EncodeUnencrypted(original);
        byte[] decoded = SshPacket.DecodeUnencrypted(packet);
        CollectionAssert.AreEqual(original, decoded);
    }

    [TestMethod]
    public void RoundTripsEmptyPayload()
    {
        byte[] packet = SshPacket.EncodeUnencrypted([]);
        byte[] decoded = SshPacket.DecodeUnencrypted(packet);
        Assert.AreEqual(0, decoded.Length);
    }

    [TestMethod]
    public async Task StreamRoundTrip()
    {
        byte[] payload = "SSH-over-stream"u8.ToArray();
        using var ms = new MemoryStream();
        await SshPacket.WriteUnencryptedAsync(ms, payload);
        ms.Position = 0;
        byte[]? read = await SshPacket.ReadUnencryptedAsync(ms);
        Assert.IsNotNull(read);
        CollectionAssert.AreEqual(payload, read);
    }
}
