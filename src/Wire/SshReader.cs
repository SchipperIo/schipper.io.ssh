using System.Buffers.Binary;
using System.Numerics;
using System.Text;

namespace Schipper.Io.Ssh.Wire;

/// <summary>
/// Reads SSH wire data types (RFC 4251 §5) from a payload buffer, advancing a cursor. Throws
/// <see cref="EndOfStreamException"/> if a field runs past the end of the buffer.
/// </summary>
public ref struct SshReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _position;

    public SshReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _position = 0;
    }

    public readonly int Position => _position;

    public readonly int Remaining => _data.Length - _position;

    public byte ReadByte()
    {
        EnsureAvailable(1);
        return _data[_position++];
    }

    public bool ReadBoolean() => ReadByte() != 0;

    public uint ReadUInt32()
    {
        EnsureAvailable(4);
        uint value = BinaryPrimitives.ReadUInt32BigEndian(_data.Slice(_position, 4));
        _position += 4;
        return value;
    }

    public ulong ReadUInt64()
    {
        EnsureAvailable(8);
        ulong value = BinaryPrimitives.ReadUInt64BigEndian(_data.Slice(_position, 8));
        _position += 8;
        return value;
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        EnsureAvailable(count);
        ReadOnlySpan<byte> slice = _data.Slice(_position, count);
        _position += count;
        return slice;
    }

    /// <summary>Reads a length-prefixed binary string.</summary>
    public ReadOnlySpan<byte> ReadString()
    {
        uint length = ReadUInt32();
        return ReadBytes(checked((int)length));
    }

    /// <summary>Reads a length-prefixed string as UTF-8 text.</summary>
    public string ReadStringText() => Encoding.UTF8.GetString(ReadString());

    /// <summary>Reads a name-list as an array of names.</summary>
    public string[] ReadNameList()
    {
        string joined = ReadStringText();
        return joined.Length == 0 ? [] : joined.Split(',');
    }

    /// <summary>Reads a multiple-precision integer as a non-negative <see cref="BigInteger"/>.</summary>
    public BigInteger ReadMpint()
    {
        ReadOnlySpan<byte> bytes = ReadString();
        return bytes.Length == 0 ? BigInteger.Zero : new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    private readonly void EnsureAvailable(int count)
    {
        if (count < 0 || _position + count > _data.Length)
        {
            throw new EndOfStreamException("SSH packet ended before the requested field was complete.");
        }
    }
}
