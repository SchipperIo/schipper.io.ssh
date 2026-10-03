using System.Numerics;
using System.Security.Cryptography;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Transport;

/// <summary>
/// The server's persistent <c>ecdsa-sha2-nistp256</c> host key. Generated on first use and stored as
/// a DER <c>ECPrivateKey</c> so the host identity is stable across restarts (clients remember it in
/// <c>known_hosts</c>). Provides the public-key blob and exchange-hash signature in SSH wire form
/// (RFC 5656 §3), using only the in-box <see cref="ECDsa"/> — no third-party SSH library.
/// </summary>
public sealed class SshHostKey
{
    private readonly ECDsa _ecdsa;

    private SshHostKey(ECDsa ecdsa) => _ecdsa = ecdsa;

    public string Algorithm => SshAlgorithms.HostKey;

    /// <summary>
    /// The board's stable ShellyNet identity fingerprint: lowercase hex of <c>SHA-256</c> over the
    /// public key blob. Used to pin and compare boards out of band (like an SSH fingerprint).
    /// </summary>
    public string Fingerprint => Convert.ToHexStringLower(SHA256.HashData(PublicKeyBlob()));

    /// <summary>Loads the host key from <paramref name="path"/>, generating and saving one if absent.</summary>
    public static SshHostKey LoadOrCreate(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        if (File.Exists(path))
        {
            ecdsa.ImportECPrivateKey(File.ReadAllBytes(path), out _);
            return new SshHostKey(ecdsa);
        }

        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllBytes(path, ecdsa.ExportECPrivateKey());
        return new SshHostKey(ecdsa);
    }

    /// <summary>Creates an in-memory host key (used by tests).</summary>
    public static SshHostKey CreateEphemeral() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    /// <summary>
    /// The public key blob <c>K_S</c>: <c>string "ecdsa-sha2-nistp256", string "nistp256",
    /// string Q</c> where Q is the uncompressed EC point (<c>0x04 || X || Y</c>).
    /// </summary>
    public byte[] PublicKeyBlob()
    {
        ECParameters p = _ecdsa.ExportParameters(includePrivateParameters: false);
        return new SshWriter()
            .WriteString(SshAlgorithms.HostKey)
            .WriteString("nistp256")
            .WriteString(EncodePoint(p.Q.X!, p.Q.Y!))
            .ToArray();
    }

    /// <summary>
    /// Signs the exchange hash and returns the SSH signature blob:
    /// <c>string "ecdsa-sha2-nistp256", string (mpint r, mpint s)</c> (RFC 5656 §3.1.2).
    /// </summary>
    public byte[] SignExchangeHash(ReadOnlySpan<byte> exchangeHash) => SignSshBlob(exchangeHash);

    /// <summary>
    /// Signs arbitrary data and returns the SSH signature blob
    /// <c>string "ecdsa-sha2-nistp256", string (mpint r, mpint s)</c> (RFC 5656 §3.1.2) — the form
    /// used for both the kex exchange hash and <c>publickey</c> userauth signatures.
    /// </summary>
    public byte[] SignSshBlob(ReadOnlySpan<byte> data)
    {
        // SignData hashes the input with SHA-256 and signs it; P1363 gives fixed-width r||s.
        byte[] rs = _ecdsa.SignData(data.ToArray(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        int half = rs.Length / 2;
        var r = new BigInteger(rs.AsSpan(0, half), isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(rs.AsSpan(half), isUnsigned: true, isBigEndian: true);

        byte[] signatureBlob = new SshWriter().WriteMpint(r).WriteMpint(s).ToArray();
        return new SshWriter()
            .WriteString(SshAlgorithms.HostKey)
            .WriteString(signatureBlob)
            .ToArray();
    }

    /// <summary>
    /// Signs arbitrary data with the board's identity key (SHA-256 + ECDSA, fixed-width <c>r‖s</c>).
    /// Used by ShellyNet to authenticate the peer handshake and sign IRC envelopes.
    /// </summary>
    public byte[] SignData(ReadOnlySpan<byte> data) =>
        _ecdsa.SignData(data.ToArray(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <summary>
    /// Verifies a <see cref="SignData"/> signature against a peer's public key blob (the
    /// <see cref="PublicKeyBlob"/> form). Returns false on any malformed input rather than throwing.
    /// </summary>
    public static bool VerifyData(ReadOnlySpan<byte> publicKeyBlob, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using ECDsa? ecdsa = ImportPublicKeyBlob(publicKeyBlob);
        return ecdsa is not null &&
            ecdsa.VerifyData(data.ToArray(), signature.ToArray(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>Parses a <see cref="PublicKeyBlob"/> into an <see cref="ECDsa"/>, or null if malformed.</summary>
    public static ECDsa? ImportPublicKeyBlob(ReadOnlySpan<byte> publicKeyBlob)
    {
        try
        {
            var reader = new SshReader(publicKeyBlob);
            if (reader.ReadStringText() != SshAlgorithms.HostKey)
            {
                return null;
            }

            reader.ReadString(); // curve name "nistp256"
            ReadOnlySpan<byte> q = reader.ReadString();
            if (q.Length != 65 || q[0] != 0x04)
            {
                return null;
            }

            var parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = q.Slice(1, 32).ToArray(), Y = q.Slice(33, 32).ToArray() },
            };
            return ECDsa.Create(parameters);
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (EndOfStreamException)
        {
            // Truncated blob — a field's declared length runs past the end.
            return null;
        }
    }

    /// <summary>Verifies a signature produced by <see cref="SignExchangeHash"/> (used by tests).</summary>
    public bool VerifyExchangeHash(ReadOnlySpan<byte> exchangeHash, ReadOnlySpan<byte> signature)
    {
        byte[]? rs = DecodeSshSignatureBlob(signature);
        return rs is not null &&
            _ecdsa.VerifyData(exchangeHash.ToArray(), rs, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// Verifies an SSH signature blob (the <see cref="SignSshBlob"/> form) over <paramref name="data"/>
    /// against a peer's public key blob (the <see cref="PublicKeyBlob"/> form). Returns false on any
    /// malformed input rather than throwing.
    /// </summary>
    public static bool VerifySshSignature(ReadOnlySpan<byte> publicKeyBlob, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        byte[]? rs = DecodeSshSignatureBlob(signatureBlob);
        if (rs is null)
        {
            return false;
        }

        using ECDsa? ecdsa = ImportPublicKeyBlob(publicKeyBlob);
        return ecdsa is not null &&
            ecdsa.VerifyData(data.ToArray(), rs, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// Decodes an SSH ECDSA signature blob (<c>string alg, string (mpint r, mpint s)</c>) into the
    /// fixed-width IEEE P1363 <c>r‖s</c> form, or null when malformed.
    /// </summary>
    private static byte[]? DecodeSshSignatureBlob(ReadOnlySpan<byte> signatureBlob)
    {
        try
        {
            var reader = new SshReader(signatureBlob);
            if (reader.ReadStringText() != SshAlgorithms.HostKey)
            {
                return null;
            }

            var inner = new SshReader(reader.ReadString());
            BigInteger r = inner.ReadMpint();
            BigInteger s = inner.ReadMpint();
            byte[] rs = new byte[64];
            WriteFixed(r, rs.AsSpan(0, 32));
            WriteFixed(s, rs.AsSpan(32, 32));
            return rs;
        }
        catch (EndOfStreamException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            // r or s wider than 32 bytes — not a valid P-256 signature.
            return null;
        }
    }

    private static byte[] EncodePoint(byte[] x, byte[] y)
    {
        var point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04; // uncompressed
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);
        return point;
    }

    private static void WriteFixed(BigInteger value, Span<byte> destination)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        destination.Clear();
        bytes.CopyTo(destination[(destination.Length - bytes.Length)..]);
    }
}
