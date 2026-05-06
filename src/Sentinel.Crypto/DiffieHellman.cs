using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Sentinel.Crypto.Interfaces;

namespace Sentinel.Crypto;

/// <summary>
/// Diffie-Hellman key exchange implementation using BouncyCastle.
/// Generates ephemeral keypairs and computes shared secrets for the DH MITM.
/// </summary>
public sealed class DiffieHellman : IKeyExchange
{
    // Default P/G from Elitepvpers thread (used by many private servers)
    private const string KnownP = 
        "A320A85EDD79171C341459E94807D71D39BB3B3F" +
        "3B5161CA84894F3AC3FC7FEC317A2DDEC83B66D3" +
        "0C29261C6492643061AECFCF4A051816D7C359A6" +
        "A7B7D8FB";
    private const string KnownG = "05";

    private DHParameters? _parameters;
    private DHPrivateKeyParameters? _privateKey;
    private DHPublicKeyParameters? _publicKey;
    private bool _disposed;

    public void Initialize(ReadOnlySpan<byte> prime, ReadOnlySpan<byte> generator)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        BigInteger p;
        if (prime.Length > 0)
            p = new BigInteger(1, prime.ToArray());
        else
            p = new BigInteger(KnownP, 16);

        BigInteger g;
        if (generator.Length > 0)
            g = new BigInteger(1, generator.ToArray());
        else
            g = new BigInteger(KnownG, 16);

        _parameters = new DHParameters(p, g);
    }

    public byte[] GeneratePublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_parameters is null)
            throw new InvalidOperationException("Call Initialize(prime, generator) before GeneratePublicKey().");

        var keyGen = new DHKeyPairGenerator();
        keyGen.Init(new DHKeyGenerationParameters(new SecureRandom(), _parameters));

        var keyPair = keyGen.GenerateKeyPair();
        _privateKey = (DHPrivateKeyParameters)keyPair.Private;
        _publicKey = (DHPublicKeyParameters)keyPair.Public;

        return _publicKey.Y.ToByteArrayUnsigned();
    }

    public byte[] ComputeSharedSecret(ReadOnlySpan<byte> remotePublicKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_privateKey is null || _parameters is null)
            throw new InvalidOperationException("Call GeneratePublicKey() before ComputeSharedSecret().");

        var remotePubKey = new DHPublicKeyParameters(
            new BigInteger(1, remotePublicKey.ToArray()),
            _parameters);

        var agreement = new DHBasicAgreement();
        agreement.Init(_privateKey);

        var sharedSecret = agreement.CalculateAgreement(remotePubKey);
        return sharedSecret.ToByteArrayUnsigned();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _privateKey = null;
        _publicKey = null;
        _parameters = null;
    }
}
