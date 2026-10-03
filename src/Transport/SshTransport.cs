using System.Buffers.Binary;
using System.Security.Cryptography;
using Schipper.Io.Ssh.Wire;

namespace Schipper.Io.Ssh.Transport;

/// <summary>
/// The SSH binary packet protocol over a duplex stream. Before key exchange completes it uses the
/// cleartext framing in <see cref="SshPacket"/>; after <c>SSH_MSG_NEWKEYS</c> it switches to
/// <c>aes256-gcm@openssh.com</c> (RFC 5647): the 4-byte length is sent in clear and authenticated as
/// AAD, the rest is encrypted, and a 16-byte tag follows. The 12-byte nonce is a fixed 4-byte prefix
/// plus an 8-byte invocation counter that increments per packet, per direction.
/// </summary>
internal sealed class SshTransport : IDisposable
{
    private const int BlockSize = 16;
    private const int MinPadding = 4;
    private const int TagSize = 16;
    private const int MaxPacket = 35000;

    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private bool _encrypted;
    private GcmDirection _send;
    private GcmDirection _recv;

    public SshTransport(Stream stream) => _stream = stream;

    /// <summary>Installs the per-direction GCM keys/IVs and turns on encryption for subsequent packets.</summary>
    public void EnableEncryption(byte[] sendKey, byte[] sendIv, byte[] recvKey, byte[] recvIv)
    {
        _send = new GcmDirection(sendKey, sendIv);
        _recv = new GcmDirection(recvKey, recvIv);
        _encrypted = true;
    }

    /// <summary>Sends one packet payload, framing (and encrypting, once keys are set) it.</summary>
    public async Task WritePayloadAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] packet = _encrypted ? EncryptPacket(payload.Span) : SshPacket.EncodeUnencrypted(payload.Span);
            await _stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Reads one packet payload, or null at end of stream.</summary>
    public async Task<byte[]?> ReadPayloadAsync(CancellationToken cancellationToken)
    {
        if (!_encrypted)
        {
            return await SshPacket.ReadUnencryptedAsync(_stream, cancellationToken).ConfigureAwait(false);
        }

        var lengthField = new byte[4];
        if (!await ReadExactAsync(lengthField, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(lengthField);
        if (packetLength is 0 or > MaxPacket)
        {
            throw new InvalidDataException($"Implausible SSH packet length {packetLength}.");
        }

        var cipherAndTag = new byte[packetLength + TagSize];
        if (!await ReadExactAsync(cipherAndTag, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var plaintext = new byte[packetLength];
        ReadOnlySpan<byte> ciphertext = cipherAndTag.AsSpan(0, (int)packetLength);
        ReadOnlySpan<byte> tag = cipherAndTag.AsSpan((int)packetLength, TagSize);
        _recv.Cipher.Decrypt(_recv.Nonce, ciphertext, tag, plaintext, lengthField);
        _recv.IncrementCounter();

        byte paddingLength = plaintext[0];
        int payloadLength = (int)packetLength - 1 - paddingLength;
        if (payloadLength < 0)
        {
            throw new InvalidDataException("SSH packet padding exceeds its length.");
        }

        return plaintext.AsSpan(1, payloadLength).ToArray();
    }

    private byte[] EncryptPacket(ReadOnlySpan<byte> payload)
    {
        int unpadded = 1 + payload.Length;
        int padding = BlockSize - (unpadded % BlockSize); // GCM: length field is NOT part of this block
        if (padding < MinPadding)
        {
            padding += BlockSize;
        }

        int packetLength = unpadded + padding;
        var plaintext = new byte[packetLength];
        plaintext[0] = (byte)padding;
        payload.CopyTo(plaintext.AsSpan(1));
        RandomNumberGenerator.Fill(plaintext.AsSpan(1 + payload.Length, padding));

        var output = new byte[4 + packetLength + TagSize];
        BinaryPrimitives.WriteUInt32BigEndian(output, (uint)packetLength);
        Span<byte> ciphertext = output.AsSpan(4, packetLength);
        Span<byte> tag = output.AsSpan(4 + packetLength, TagSize);
        _send.Cipher.Encrypt(_send.Nonce, plaintext, ciphertext, tag, output.AsSpan(0, 4));
        _send.IncrementCounter();

        return output;
    }

    private async Task<bool> ReadExactAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await _stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    public void Dispose()
    {
        _writeLock.Dispose();
        _send.Cipher?.Dispose();
        _recv.Cipher?.Dispose();
    }

    /// <summary>One direction's AEAD state: the cipher plus the 12-byte nonce (4 fixed + 8 counter).</summary>
    private struct GcmDirection
    {
        private readonly byte[] _nonce;

        public GcmDirection(byte[] key, byte[] iv)
        {
            Cipher = new AesGcm(key, TagSize);
            _nonce = new byte[12];
            iv.AsSpan(0, 12).CopyTo(_nonce);
        }

        public readonly AesGcm Cipher { get; }

        public readonly ReadOnlySpan<byte> Nonce => _nonce;

        /// <summary>Increments the 8-byte invocation counter (the trailing part of the nonce).</summary>
        public readonly void IncrementCounter()
        {
            Span<byte> counter = _nonce.AsSpan(4, 8);
            ulong value = BinaryPrimitives.ReadUInt64BigEndian(counter) + 1;
            BinaryPrimitives.WriteUInt64BigEndian(counter, value);
        }
    }
}
