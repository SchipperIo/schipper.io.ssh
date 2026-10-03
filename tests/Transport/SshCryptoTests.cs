using System.Numerics;
using System.Security.Cryptography;
using Schipper.Io.Ssh.Transport;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Tests.Transport;

[TestClass]
public sealed class SshCryptoTests
{
    [TestMethod]
    public void HostKeySignatureRoundTripsAndPublicBlobIsWellFormed()
    {
        var key = SshHostKey.CreateEphemeral();
        byte[] h = RandomNumberGenerator.GetBytes(32);

        byte[] signature = key.SignExchangeHash(h);
        Assert.IsTrue(key.VerifyExchangeHash(h, signature), "the host key should verify its own signature");

        byte[] tampered = (byte[])h.Clone();
        tampered[0] ^= 0xFF;
        Assert.IsFalse(key.VerifyExchangeHash(tampered, signature), "a different hash must not verify");

        var r = new SshReader(key.PublicKeyBlob());
        Assert.AreEqual("ecdsa-sha2-nistp256", r.ReadStringText());
        Assert.AreEqual("nistp256", r.ReadStringText());
        ReadOnlySpan<byte> point = r.ReadString();
        Assert.AreEqual(65, point.Length);     // uncompressed P-256 point
        Assert.AreEqual(0x04, point[0]);
    }

    [TestMethod]
    public async Task GcmTransportRoundTripsMultiplePackets()
    {
        byte[] keyServerToClient = RandomNumberGenerator.GetBytes(32);
        byte[] keyClientToServer = RandomNumberGenerator.GetBytes(32);
        byte[] ivServerToClient = RandomNumberGenerator.GetBytes(12);
        byte[] ivClientToServer = RandomNumberGenerator.GetBytes(12);

        using var pipe = new MemoryStream();
        var server = new SshTransport(pipe);
        server.EnableEncryption(keyServerToClient, ivServerToClient, keyClientToServer, ivClientToServer);

        byte[][] payloads =
        {
            new byte[] { 1, 2, 3 },
            Enumerable.Range(0, 200).Select(i => (byte)i).ToArray(),
            Array.Empty<byte>(),
            new byte[] { 42 },
        };

        foreach (byte[] payload in payloads)
        {
            await server.WritePayloadAsync(payload, CancellationToken.None);
        }

        pipe.Position = 0;
        var client = new SshTransport(pipe);
        // The client's receive direction uses the server's send key/IV.
        client.EnableEncryption(keyClientToServer, ivClientToServer, keyServerToClient, ivServerToClient);

        foreach (byte[] expected in payloads)
        {
            byte[]? got = await client.ReadPayloadAsync(CancellationToken.None);
            CollectionAssert.AreEqual(expected, got);
        }
    }

    [TestMethod]
    public void GcmDecryptRejectsTamperedCiphertext()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(12);

        using var pipe = new MemoryStream();
        var writer = new SshTransport(pipe);
        writer.EnableEncryption(key, iv, key, iv);
        writer.WritePayloadAsync(new byte[] { 9, 9, 9, 9 }, CancellationToken.None).GetAwaiter().GetResult();

        byte[] wire = pipe.ToArray();
        wire[^1] ^= 0xFF; // corrupt the authentication tag

        var reader = new SshTransport(new MemoryStream(wire));
        reader.EnableEncryption(key, iv, key, iv);
        Assert.ThrowsExactly<AuthenticationTagMismatchException>(
            () => reader.ReadPayloadAsync(CancellationToken.None).GetAwaiter().GetResult());
    }

    [TestMethod]
    public void ServerKexInitIsAcceptedByOurOwnNegotiator()
    {
        byte[] kexInit = SshKex.BuildServerKexInit();
        Assert.AreEqual(SshMessage.KexInit, kexInit[0]);

        bool ok = SshKex.ClientSupportsOurAlgorithms(kexInit, out bool guessed, out bool firstFollows);
        Assert.IsTrue(ok);
        Assert.IsTrue(guessed);        // our single kex is first in the list
        Assert.IsFalse(firstFollows);
    }

    [TestMethod]
    public void KeyDerivationIsDeterministicAndDirectionDistinct()
    {
        var shared = BigInteger.Parse("123456789012345678901234567890");
        byte[] hash = RandomNumberGenerator.GetBytes(32);

        var a = SshKex.DeriveKeys(shared, hash, hash);
        var b = SshKex.DeriveKeys(shared, hash, hash);

        CollectionAssert.AreEqual(a.IvClientToServer, b.IvClientToServer);
        CollectionAssert.AreEqual(a.KeyServerToClient, b.KeyServerToClient);

        Assert.AreEqual(12, a.IvClientToServer.Length);
        Assert.AreEqual(32, a.KeyServerToClient.Length);
        CollectionAssert.AreNotEqual(a.KeyClientToServer, a.KeyServerToClient);
        CollectionAssert.AreNotEqual(a.IvClientToServer, a.IvServerToClient);
    }

    [TestMethod]
    public void ExchangeHashIsStableForFixedInputs()
    {
        byte[] kexC = SshKex.BuildServerKexInit();
        byte[] kexS = SshKex.BuildServerKexInit();
        byte[] ks = SshHostKey.CreateEphemeral().PublicKeyBlob();
        byte[] qc = RandomNumberGenerator.GetBytes(65);
        byte[] qs = RandomNumberGenerator.GetBytes(65);
        var k = BigInteger.Parse("987654321987654321");

        byte[] h1 = SshKex.ComputeExchangeHash("SSH-2.0-A", "SSH-2.0-Shelly_0.1", kexC, kexS, ks, qc, qs, k);
        byte[] h2 = SshKex.ComputeExchangeHash("SSH-2.0-A", "SSH-2.0-Shelly_0.1", kexC, kexS, ks, qc, qs, k);
        byte[] h3 = SshKex.ComputeExchangeHash("SSH-2.0-B", "SSH-2.0-Shelly_0.1", kexC, kexS, ks, qc, qs, k);

        Assert.AreEqual(32, h1.Length);
        CollectionAssert.AreEqual(h1, h2);
        CollectionAssert.AreNotEqual(h1, h3);
    }
}
