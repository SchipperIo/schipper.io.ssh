using System.Numerics;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Tests.Wire;

[TestClass]
public sealed class SshWireTests
{
    [TestMethod]
    public void RoundTripsPrimitives()
    {
        byte[] payload = new SshWriter()
            .WriteByte(42)
            .WriteBoolean(true)
            .WriteUInt32(0xDEADBEEF)
            .WriteUInt64(0x0102030405060708)
            .WriteString("hello")
            .ToArray();

        var reader = new SshReader(payload);
        Assert.AreEqual((byte)42, reader.ReadByte());
        Assert.IsTrue(reader.ReadBoolean());
        Assert.AreEqual(0xDEADBEEFu, reader.ReadUInt32());
        Assert.AreEqual(0x0102030405060708ul, reader.ReadUInt64());
        Assert.AreEqual("hello", reader.ReadStringText());
        Assert.AreEqual(0, reader.Remaining);
    }

    [TestMethod]
    public void NameListRoundTrips()
    {
        byte[] payload = new SshWriter().WriteNameList(["ssh-ed25519", "ecdsa-sha2-nistp256"]).ToArray();
        var reader = new SshReader(payload);
        CollectionAssert.AreEqual(new[] { "ssh-ed25519", "ecdsa-sha2-nistp256" }, reader.ReadNameList());
    }

    [TestMethod]
    public void EmptyNameListRoundTrips()
    {
        byte[] payload = new SshWriter().WriteNameList([]).ToArray();
        var reader = new SshReader(payload);
        Assert.AreEqual(0, reader.ReadNameList().Length);
    }

    [TestMethod]
    public void MpintZeroIsEmptyString()
    {
        byte[] payload = new SshWriter().WriteMpint(BigInteger.Zero).ToArray();
        // uint32 length prefix of 0 => four zero bytes.
        CollectionAssert.AreEqual(new byte[] { 0, 0, 0, 0 }, payload);
    }

    [TestMethod]
    public void MpintInsertsLeadingZeroWhenHighBitSet()
    {
        // 0x80 has the high bit set, so the encoding must prepend a 0x00 padding byte.
        byte[] payload = new SshWriter().WriteMpint(new BigInteger(0x80)).ToArray();
        CollectionAssert.AreEqual(new byte[] { 0, 0, 0, 2, 0x00, 0x80 }, payload);
    }

    [TestMethod]
    public void MpintRoundTripsLargeValue()
    {
        var value = BigInteger.Parse("1234567890123456789012345678901234567890");
        byte[] payload = new SshWriter().WriteMpint(value).ToArray();
        var reader = new SshReader(payload);
        Assert.AreEqual(value, reader.ReadMpint());
    }

    [TestMethod]
    public void MpintMatchesRfc4251Vectors()
    {
        // RFC 4251 example: 0x09a378f9b2e332a7 encodes with no leading zero.
        // The leading "0" keeps NumberStyles.HexNumber from reading the high bit as a sign.
        var value = BigInteger.Parse("09a378f9b2e332a7", System.Globalization.NumberStyles.HexNumber);
        byte[] payload = new SshWriter().WriteMpint(value).ToArray();
        CollectionAssert.AreEqual(
            new byte[] { 0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 },
            payload);
    }

    [TestMethod]
    public void ReaderThrowsWhenTruncated()
    {
        byte[] payload = new SshWriter().WriteUInt32(100).ToArray(); // claims a 100-byte string, has none
        Assert.ThrowsExactly<EndOfStreamException>(() =>
        {
            var reader = new SshReader(payload);
            reader.ReadString();
        });
    }
}
