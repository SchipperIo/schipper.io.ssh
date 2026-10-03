using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Schipper.Io.Ssh.Wire;

/// <summary>
/// Encodes and decodes the SSH binary packet framing (RFC 4253 §6) used before encryption is
/// negotiated: <c>uint32 packet_length</c>, <c>byte padding_length</c>, payload, then random padding
/// so the whole packet (excluding the length field's MAC, which is absent pre-KEX) is a multiple of 8
/// with at least 4 padding bytes. The encrypted/AEAD path is layered on top once keys are derived.
/// </summary>
public static class SshPacket
{
    private const int BlockSize = 8;
    private const int MinPadding = 4;

    /// <summary>Frames a payload into an unencrypted binary packet.</summary>
    public static byte[] EncodeUnencrypted(ReadOnlySpan<byte> payload)
    {
        // length field (4) + padding_length (1) + payload + padding must be a multiple of BlockSize.
        int unpadded = 1 + payload.Length;
        int padding = BlockSize - ((4 + unpadded) % BlockSize);
        if (padding < MinPadding)
        {
            padding += BlockSize;
        }

        uint packetLength = (uint)(unpadded + padding);
        var packet = new byte[4 + packetLength];

        BinaryPrimitives.WriteUInt32BigEndian(packet, packetLength);
        packet[4] = (byte)padding;
        payload.CopyTo(packet.AsSpan(5));
        RandomNumberGenerator.Fill(packet.AsSpan(5 + payload.Length, padding));

        return packet;
    }

    /// <summary>Extracts the payload from a complete unencrypted packet produced by <see cref="EncodeUnencrypted"/>.</summary>
    public static byte[] DecodeUnencrypted(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 5)
        {
            throw new InvalidDataException("SSH packet too short.");
        }

        uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(packet);
        if (packet.Length < 4 + packetLength)
        {
            throw new InvalidDataException("SSH packet shorter than its declared length.");
        }

        byte paddingLength = packet[4];
        int payloadLength = (int)packetLength - 1 - paddingLength;
        if (payloadLength < 0)
        {
            throw new InvalidDataException("SSH packet padding exceeds its length.");
        }

        return packet.Slice(5, payloadLength).ToArray();
    }

    /// <summary>Writes an unencrypted packet to a stream.</summary>
    public static async Task WriteUnencryptedAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        byte[] packet = EncodeUnencrypted(payload.Span);
        await stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one unencrypted packet from a stream and returns its payload, or null at end of stream.</summary>
    public static async Task<byte[]?> ReadUnencryptedAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        byte[] header = new byte[4];
        if (!await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (packetLength is 0 or > 35000)
        {
            throw new InvalidDataException($"Implausible SSH packet length {packetLength}.");
        }

        byte[] body = new byte[packetLength];
        if (!await ReadExactAsync(stream, body, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        byte paddingLength = body[0];
        int payloadLength = (int)packetLength - 1 - paddingLength;
        if (payloadLength < 0)
        {
            throw new InvalidDataException("SSH packet padding exceeds its length.");
        }

        return body.AsSpan(1, payloadLength).ToArray();
    }

    /// <summary>Writes an SSH identification line (RFC 4253 §4.2) terminated with CRLF.</summary>
    internal static async Task WriteVersionLineAsync(Stream stream, string line, CancellationToken cancellationToken)
    {
        byte[] bytes = System.Text.Encoding.ASCII.GetBytes(line + "\r\n");
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the peer's identification line, skipping any pre-banner lines (RFC 4253 §4.2).</summary>
    internal static async Task<string?> ReadVersionLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        var line = new List<byte>(64);
        var one = new byte[1];

        for (int guard = 0; guard < 100; guard++)
        {
            line.Clear();
            while (true)
            {
                int read = await stream.ReadAsync(one, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return null;
                }

                if (one[0] == (byte)'\n')
                {
                    break;
                }

                if (one[0] != (byte)'\r' && line.Count < 255)
                {
                    line.Add(one[0]);
                }
            }

            string text = System.Text.Encoding.ASCII.GetString(line.ToArray());
            if (text.StartsWith("SSH-", StringComparison.Ordinal))
            {
                return text;
            }
        }

        return null;
    }

    private static async Task<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }
}
