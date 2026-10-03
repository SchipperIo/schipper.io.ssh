using System.Buffers.Binary;
using System.Numerics;
using System.Text;

namespace Schipper.Io.Ssh.Wire;

/// <summary>
/// Builds an SSH packet payload using the wire data types from RFC 4251 §5 (byte, boolean, uint32,
/// uint64, string, mpint, name-list). All multi-byte integers are big-endian.
/// </summary>
public sealed class SshWriter
{
    private readonly List<byte> _buffer = new();

    public int Length => _buffer.Count;

    public SshWriter WriteByte(byte value)
    {
        _buffer.Add(value);
        return this;
    }

    public SshWriter WriteBoolean(bool value)
    {
        _buffer.Add(value ? (byte)1 : (byte)0);
        return this;
    }

    public SshWriter WriteUInt32(uint value)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tmp, value);
        _buffer.AddRange(tmp);
        return this;
    }

    public SshWriter WriteUInt64(ulong value)
    {
        Span<byte> tmp = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(tmp, value);
        _buffer.AddRange(tmp);
        return this;
    }

    /// <summary>Appends raw bytes with no length prefix.</summary>
    public SshWriter WriteRaw(ReadOnlySpan<byte> bytes)
    {
        _buffer.AddRange(bytes);
        return this;
    }

    /// <summary>Writes a length-prefixed binary string (uint32 length + bytes).</summary>
    public SshWriter WriteString(ReadOnlySpan<byte> bytes)
    {
        WriteUInt32((uint)bytes.Length);
        _buffer.AddRange(bytes);
        return this;
    }

    /// <summary>Writes a length-prefixed UTF-8 string.</summary>
    public SshWriter WriteString(string text) => WriteString(Encoding.UTF8.GetBytes(text));

    /// <summary>Writes a multiple-precision integer (non-negative) in SSH mpint form.</summary>
    public SshWriter WriteMpint(BigInteger value)
    {
        if (value.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "SSH mpint values must be non-negative here.");
        }

        if (value.IsZero)
        {
            return WriteUInt32(0);
        }

        byte[] magnitude = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        // A leading zero is required when the top bit is set, to keep the value positive.
        if ((magnitude[0] & 0x80) != 0)
        {
            WriteUInt32((uint)(magnitude.Length + 1));
            _buffer.Add(0);
            _buffer.AddRange(magnitude);
        }
        else
        {
            WriteString(magnitude);
        }

        return this;
    }

    /// <summary>Writes a name-list: comma-separated names encoded as a single string.</summary>
    public SshWriter WriteNameList(IEnumerable<string> names) => WriteString(string.Join(',', names));

    public byte[] ToArray() => _buffer.ToArray();
}
