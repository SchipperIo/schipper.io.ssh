using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Transport;

/// <summary>
/// Key-exchange math for <c>ecdh-sha2-nistp256</c>: building the server's KEXINIT, computing the
/// exchange hash <c>H</c> (RFC 5656 §4), and deriving the per-direction keys and IVs from the shared
/// secret (RFC 4253 §7.2). The hash and KDF are SHA-256.
/// </summary>
internal static class SshKex
{
    /// <summary>
    /// Builds an <c>SSH_MSG_KEXINIT</c> payload offering Shelly's single algorithm set. The payload
    /// is role-agnostic, so both <see cref="SshServer"/> and <see cref="SshClient"/> send it.
    /// </summary>
    public static byte[] BuildServerKexInit()
    {
        var cookie = new byte[16];
        RandomNumberGenerator.Fill(cookie);

        var w = new SshWriter();
        w.WriteByte(SshMessage.KexInit);
        w.WriteRaw(cookie);
        w.WriteNameList([SshAlgorithms.Kex]);
        w.WriteNameList([SshAlgorithms.HostKey]);
        w.WriteNameList([SshAlgorithms.Cipher]);       // enc c->s
        w.WriteNameList([SshAlgorithms.Cipher]);       // enc s->c
        w.WriteNameList([SshAlgorithms.Mac]);          // mac c->s (ignored under GCM)
        w.WriteNameList([SshAlgorithms.Mac]);          // mac s->c
        w.WriteNameList([SshAlgorithms.Compression]);  // comp c->s
        w.WriteNameList([SshAlgorithms.Compression]);  // comp s->c
        w.WriteNameList([]);                            // languages c->s
        w.WriteNameList([]);                            // languages s->c
        w.WriteBoolean(false);                          // first_kex_packet_follows
        w.WriteUInt32(0);                               // reserved
        return w.ToArray();
    }

    /// <summary>
    /// True when the peer's preference lists all contain Shelly's chosen algorithm. Works on either
    /// side's KEXINIT (the checked name-lists are symmetric for our single algorithm set).
    /// </summary>
    public static bool ClientSupportsOurAlgorithms(ReadOnlySpan<byte> clientKexInit, out bool clientGuessedKex, out bool clientFirstKexFollows)
    {
        var r = new SshReader(clientKexInit);
        r.ReadByte();          // message id
        r.ReadBytes(16);       // cookie
        string[] kex = r.ReadNameList();
        string[] hostKeys = r.ReadNameList();
        string[] encCs = r.ReadNameList();
        string[] encSc = r.ReadNameList();
        r.ReadNameList();      // mac c->s
        r.ReadNameList();      // mac s->c
        r.ReadNameList();      // comp c->s
        r.ReadNameList();      // comp s->c
        r.ReadNameList();      // languages c->s
        r.ReadNameList();      // languages s->c
        clientFirstKexFollows = r.ReadBoolean();

        clientGuessedKex = kex.Length > 0 && kex[0] == SshAlgorithms.Kex;

        return Array.IndexOf(kex, SshAlgorithms.Kex) >= 0
            && Array.IndexOf(hostKeys, SshAlgorithms.HostKey) >= 0
            && Array.IndexOf(encCs, SshAlgorithms.Cipher) >= 0
            && Array.IndexOf(encSc, SshAlgorithms.Cipher) >= 0;
    }

    /// <summary>Encodes an uncompressed P-256 point (<c>0x04 || X || Y</c>) for the wire.</summary>
    public static byte[] EncodePoint(byte[] x, byte[] y)
    {
        var point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04;
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);
        return point;
    }

    /// <summary>Derives the raw ECDH shared secret from our ephemeral key and the peer's encoded point.</summary>
    public static byte[] DeriveSharedSecret(ECDiffieHellman local, ReadOnlySpan<byte> peerPoint)
    {
        if (peerPoint.Length != 65 || peerPoint[0] != 0x04)
        {
            throw new InvalidDataException("Unexpected peer ECDH point.");
        }

        var peerParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = peerPoint.Slice(1, 32).ToArray(),
                Y = peerPoint.Slice(33, 32).ToArray(),
            },
        };

        using var peer = ECDiffieHellman.Create(peerParams);
        return local.DeriveRawSecretAgreement(peer.PublicKey);
    }

    /// <summary>Computes the exchange hash H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K).</summary>
    public static byte[] ComputeExchangeHash(
        string clientVersion,
        string serverVersion,
        ReadOnlySpan<byte> clientKexInit,
        ReadOnlySpan<byte> serverKexInit,
        ReadOnlySpan<byte> hostKeyBlob,
        ReadOnlySpan<byte> clientEphemeral,
        ReadOnlySpan<byte> serverEphemeral,
        BigInteger sharedSecret)
    {
        var w = new SshWriter();
        w.WriteString(Encoding.UTF8.GetBytes(clientVersion));
        w.WriteString(Encoding.UTF8.GetBytes(serverVersion));
        w.WriteString(clientKexInit);
        w.WriteString(serverKexInit);
        w.WriteString(hostKeyBlob);
        w.WriteString(clientEphemeral);
        w.WriteString(serverEphemeral);
        w.WriteMpint(sharedSecret);
        return SHA256.HashData(w.ToArray());
    }

    /// <summary>Derives the four directional secrets the GCM transport needs (IVs are 12 bytes, keys 32).</summary>
    public static (byte[] IvClientToServer, byte[] IvServerToClient, byte[] KeyClientToServer, byte[] KeyServerToClient)
        DeriveKeys(BigInteger sharedSecret, byte[] exchangeHash, byte[] sessionId)
    {
        byte[] k = new SshWriter().WriteMpint(sharedSecret).ToArray();
        return (
            Derive(k, exchangeHash, (byte)'A', sessionId, 12),
            Derive(k, exchangeHash, (byte)'B', sessionId, 12),
            Derive(k, exchangeHash, (byte)'C', sessionId, 32),
            Derive(k, exchangeHash, (byte)'D', sessionId, 32));
    }

    private static byte[] Derive(byte[] k, byte[] h, byte letter, byte[] sessionId, int needed)
    {
        // K1 = HASH(K || H || letter || session_id); extend with HASH(K || H || K1..Kn) until long enough.
        byte[] block = SHA256.HashData(Concat(k, h, new[] { letter }, sessionId));
        byte[] result = block;
        while (result.Length < needed)
        {
            byte[] next = SHA256.HashData(Concat(k, h, result));
            result = Concat(result, next);
        }

        return result.AsSpan(0, needed).ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts)
        {
            total += p.Length;
        }

        var buffer = new byte[total];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            p.CopyTo(buffer, offset);
            offset += p.Length;
        }

        return buffer;
    }
}
