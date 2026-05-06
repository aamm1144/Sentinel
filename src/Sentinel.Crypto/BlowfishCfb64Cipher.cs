using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Sentinel.Crypto.Interfaces;

namespace Sentinel.Crypto;

/// <summary>
/// Blowfish CFB64 cipher matching OpenSSL's BF_cfb64_encrypt behaviour.
///
/// Two operating modes:
///
///   Standard mode (SetKey):
///     Uses BouncyCastle's BlowfishEngine — standard 16-round BF with Pi S-boxes.
///     Used for game-traffic encryption (key "x97ra5i8D6uZz").
///
///   Raw-schedule mode (SetRawKeySchedule):
///     Accepts a pre-computed 16-entry P-array directly, bypassing BF_set_key.
///     Block encryption uses zero S-boxes (F=0 every round) and 14 Feistel rounds.
///     Used for the handshake cipher whose P-array is captured from memory because
///     CO 7xxx runs a modified key schedule that BouncyCastle cannot replicate.
/// </summary>
public sealed class BlowfishCfb64Cipher : ICipher
{
    private static readonly byte[] DefaultKey = "DR654dt34trg4UI6"u8.ToArray();

    private readonly bool _encrypting;
    private BlowfishEngine _engine;
    private byte[] _iv;
    private int _num;
    private bool _disposed;

    // Raw-schedule mode state.  Non-null when SetRawKeySchedule has been called.
    private uint[]? _rawP;
    // S-boxes for raw mode.  Non-null when SetRawState has been called.
    private uint[]? _rawS0, _rawS1, _rawS2, _rawS3;

    /// <param name="encrypting">true for encrypt mode, false for decrypt mode</param>
    public BlowfishCfb64Cipher(bool encrypting)
    {
        _encrypting = encrypting;
        _iv = new byte[8];
        _engine = new BlowfishEngine();
        _engine.Init(true, new KeyParameter(DefaultKey)); // CFB always uses encrypt direction for ECB
    }

    public void SetKey(ReadOnlySpan<byte> key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _rawP = null; // switch back to standard mode if previously in raw mode
        _engine = new BlowfishEngine();
        _engine.Init(true, new KeyParameter(key.ToArray()));
        _num = 0;
    }

    /// <summary>
    /// Inject a pre-computed 16-entry P-array (captured from the game's memory)
    /// and switch to 14-round zero-S-box mode.  The P-array must contain exactly
    /// 16 entries (P[0]–P[15]).  No BF_set_key is run.
    /// </summary>
    /// <param name="p14">16-entry P-array, e.g. from a Frida memory dump.</param>
    public void SetRawKeySchedule(ReadOnlySpan<uint> p14)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (p14.Length != 16)
            throw new ArgumentException("Raw key schedule requires exactly 16 P-array entries.", nameof(p14));

        _rawP  = p14.ToArray();
        _rawS0 = _rawS1 = _rawS2 = _rawS3 = null; // revert to zero-S-box mode
        _num = 0;
    }

    /// <summary>
    /// Inject a pre-computed P-array AND S-boxes captured from the game's memory.
    /// Enables full Blowfish with real S-boxes. 
    /// 
    /// If p.Length is 16, it uses 14-round mode (CO 7xxx modified).
    /// If p.Length is 18, it uses standard 16-round mode.
    ///
    /// S-boxes may be any power-of-2 length; a bitmask is derived automatically.
    /// All four S-boxes must be the same length.
    /// </summary>
    public void SetRawState(
        ReadOnlySpan<uint> p,
        ReadOnlySpan<uint> s0, ReadOnlySpan<uint> s1,
        ReadOnlySpan<uint> s2, ReadOnlySpan<uint> s3)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (p.Length != 16 && p.Length != 18)
            throw new ArgumentException("P-array must have exactly 16 (14-round) or 18 (16-round) entries.", nameof(p));
        if (s0.Length == 0 || (s0.Length & (s0.Length - 1)) != 0)
            throw new ArgumentException("S-box length must be a non-zero power of 2.", nameof(s0));
        if (s1.Length != s0.Length || s2.Length != s0.Length || s3.Length != s0.Length)
            throw new ArgumentException("All four S-boxes must be the same length.", nameof(s1));

        _rawP  = p.ToArray();
        _rawS0 = s0.ToArray();
        _rawS1 = s1.ToArray();
        _rawS2 = s2.ToArray();
        _rawS3 = s3.ToArray();
        _num = 0;
    }

    public void SetIv(ReadOnlySpan<byte> iv)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (iv.Length != 8)
            throw new ArgumentException("IV must be exactly 8 bytes for Blowfish CFB64.", nameof(iv));
        iv.CopyTo(_iv);
        _num = 0;
    }

    public void Encrypt(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_encrypting)
            throw new InvalidOperationException("This cipher instance is configured for decryption.");

        for (var i = 0; i < data.Length; i++)
        {
            if (_num == 0)
                EncryptIvBlock();

            // CFB64 encrypt: ivec[num] ^= plaintext; output = ivec[num]
            _iv[_num] ^= data[i];
            data[i] = _iv[_num];
            _num = (_num + 1) & 7;
        }
    }

    public void Decrypt(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_encrypting)
            throw new InvalidOperationException("This cipher instance is configured for encryption.");

        for (var i = 0; i < data.Length; i++)
        {
            if (_num == 0)
                EncryptIvBlock();

            // CFB64 decrypt: save ciphertext, output = ivec[num] ^ ciphertext, ivec[num] = ciphertext
            var c = data[i];
            data[i] = (byte)(_iv[_num] ^ c);
            _iv[_num] = c;
            _num = (_num + 1) & 7;
        }
    }

    public void Reset()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Array.Clear(_iv);
        _num = 0;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Array.Clear(_iv);
        _rawP = null;
        _rawS0 = _rawS1 = _rawS2 = _rawS3 = null;
    }

    /// <summary>
    /// Encrypt the 8-byte IV block in-place.  This is the CFB64 feedback step —
    /// called whenever the 8-byte keystream block is exhausted.
    ///
    /// Standard mode:  BouncyCastle BlowfishEngine (16-round, Pi S-boxes)
    /// Raw mode:       14-round zero-S-box BF (F=0, pure XOR rounds)
    /// </summary>
    private void EncryptIvBlock()
    {
        if (_rawP is not null)
        {
            var xl = ReadBE(_iv, 0);
            var xr = ReadBE(_iv, 4);

            xl ^= _rawP[0];

            var numRounds = _rawP.Length - 2;

            if (_rawS0 is not null)
            {
                // Full rounds with real S-boxes.
                var s0 = _rawS0; var s1 = _rawS1!; var s2 = _rawS2!; var s3 = _rawS3!;
                var mask = (uint)(s0.Length - 1);
                for (var i = 1; i <= numRounds - 1; i += 2)
                {
                    xr ^= BfF(xl, s0, s1, s2, s3, mask) ^ _rawP[i];
                    xl ^= BfF(xr, s0, s1, s2, s3, mask) ^ _rawP[i + 1];
                }
            }
            else
            {
                // Zero-S-box mode (F=0): each round reduces to XOR with P values.
                for (var i = 1; i <= numRounds - 1; i += 2)
                {
                    xr ^= _rawP[i];
                    xl ^= _rawP[i + 1];
                }
            }

            xr ^= _rawP[numRounds + 1]; // final whitening

            // BF output swap: left output ← xr, right output ← xl
            WriteBE(_iv, 0, xr);
            WriteBE(_iv, 4, xl);
        }
        else
        {
            // Standard mode: BouncyCastle BlowfishEngine
            var output = new byte[8];
            _engine.ProcessBlock(_iv, 0, output, 0);
            Buffer.BlockCopy(output, 0, _iv, 0, 8);
        }
    }

    private static uint BfF(uint x, uint[] s0, uint[] s1, uint[] s2, uint[] s3, uint mask) =>
        ((s0[(x >> 24) & mask] + s1[(x >> 16) & mask]) ^ s2[(x >> 8) & mask]) + s3[x & mask];

    private static uint ReadBE(byte[] b, int off) =>
        ((uint)b[off] << 24) | ((uint)b[off + 1] << 16) | ((uint)b[off + 2] << 8) | b[off + 3];

    private static void WriteBE(byte[] b, int off, uint v)
    {
        b[off]     = (byte)(v >> 24);
        b[off + 1] = (byte)(v >> 16);
        b[off + 2] = (byte)(v >> 8);
        b[off + 3] = (byte) v;
    }
}
