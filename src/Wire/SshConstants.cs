namespace Schipper.Io.Ssh.Wire;

/// <summary>SSH message numbers (RFC 4253 §12, RFC 4254 §9, RFC 5656) used by the server.</summary>
internal static class SshMessage
{
    public const byte Disconnect = 1;
    public const byte Ignore = 2;
    public const byte Unimplemented = 3;
    public const byte Debug = 4;
    public const byte ServiceRequest = 5;
    public const byte ServiceAccept = 6;
    public const byte KexInit = 20;
    public const byte NewKeys = 21;

    // ecdh (RFC 5656 / curve25519 share the 30/31 slots within a KEX).
    public const byte KexEcdhInit = 30;
    public const byte KexEcdhReply = 31;

    public const byte UserAuthRequest = 50;
    public const byte UserAuthFailure = 51;
    public const byte UserAuthSuccess = 52;
    public const byte UserAuthBanner = 53;

    // publickey method-specific (RFC 4252 §7).
    public const byte UserAuthPkOk = 60;

    public const byte GlobalRequest = 80;
    public const byte RequestSuccess = 81;
    public const byte RequestFailure = 82;

    public const byte ChannelOpen = 90;
    public const byte ChannelOpenConfirmation = 91;
    public const byte ChannelOpenFailure = 92;
    public const byte ChannelWindowAdjust = 93;
    public const byte ChannelData = 94;
    public const byte ChannelExtendedData = 95;
    public const byte ChannelEof = 96;
    public const byte ChannelClose = 97;
    public const byte ChannelRequest = 98;
    public const byte ChannelSuccess = 99;
    public const byte ChannelFailure = 100;
}

/// <summary>The single set of algorithms Shelly negotiates — all backed by the .NET BCL.</summary>
internal static class SshAlgorithms
{
    public const string Kex = "ecdh-sha2-nistp256";
    public const string HostKey = "ecdsa-sha2-nistp256";
    public const string Cipher = "aes256-gcm@openssh.com";
    public const string Mac = "hmac-sha2-256"; // ignored under GCM (AEAD), but offered for negotiation
    public const string Compression = "none";
}
