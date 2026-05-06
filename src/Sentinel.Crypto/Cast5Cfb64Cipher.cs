using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Sentinel.Crypto.Interfaces;

namespace Sentinel.Crypto;

/// <summary>
/// CAST5 (CAST-128) CFB64 cipher matching OpenSSL's CAST_cfb64_encrypt behavior.
/// Standard 16-round CAST5 with provided S-boxes.
/// </summary>
public sealed class Cast5Cfb64Cipher : ICipher
{
    private readonly bool _encrypting;
    private Cast5Engine _engine;
    private readonly byte[] _iv = new byte[8];
    private int _num;
    private bool _disposed;

    public Cast5Cfb64Cipher(bool encrypting)
    {
        _encrypting = encrypting;
        _engine = new Cast5Engine();
    }

    public void SetKey(ReadOnlySpan<byte> key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _engine = new Cast5Engine();
        _engine.Init(true, new KeyParameter(key.ToArray()));
        _num = 0;
    }

    public void SetIv(ReadOnlySpan<byte> iv)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (iv.Length != 8)
            throw new ArgumentException("IV must be exactly 8 bytes for CAST5 CFB64.", nameof(iv));
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
    }

    private void EncryptIvBlock()
    {
        var output = new byte[8];
        _engine.ProcessBlock(_iv, 0, output, 0);
        Buffer.BlockCopy(output, 0, _iv, 0, 8);
    }
}
