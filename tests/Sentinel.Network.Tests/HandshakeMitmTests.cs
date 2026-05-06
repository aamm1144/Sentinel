using Microsoft.Extensions.Logging;
using Sentinel.Crypto;
using Sentinel.Crypto.Interfaces;

namespace Sentinel.Network.Handshake;

/// <summary>
/// Four BF-CFB64 ciphers established after a successful MITM handshake.
/// Ownership of the ciphers transfers to the caller; the caller is responsible
/// for disposing them.
/// </summary>
public readonly record struct HandshakeResult(
    ICipher ClientDecrypt,
    ICipher ClientEncrypt,
    ICipher ServerDecrypt,
    ICipher ServerEncrypt);

/// <summary>
/// Performs the CO 7xxx DH man-in-the-middle handshake.
///
/// CO 7xxx flow (client-first, reversed from 5xxx):
///   1. Client sends DH init  (P, G, ClientPub, ClientIvec, ServerIvec)
///   2. Server sends DH reply (ServerPub)
///
/// The proxy intercepts both packets, replaces the public keys with its own
/// ephemeral keys, and derives two independent shared secrets:
///   - sharedSecretClient = DH(proxyPriv_c, realClientPub)
///   - sharedSecretServer = DH(proxyPriv_s, realServerPub)
///
/// After the handshake, all game traffic uses standard BF-CFB64 keyed with
/// the derived shared secrets and the IVecs exchanged during the init packet.
/// </summary>
public sealed class HandshakeMitm(
    Func<bool, string, ICipher> handshakeCipherFactory,
    ILogger? logger = null)
{
    private static readonly string[] TrialTypes = ["blowfish", "cast5", "chaintable"];

    public async Task<HandshakeResult> PerformAsync(
        Stream clientStream,
        Stream serverStream,
        CancellationToken ct)
    {
        // ── Step 1: Read the client's DH init packet ──────────────────────────
        logger?.LogDebug("MITM: waiting for client DH init...");

        var clientHsRaw = await ReadPacketAsync(clientStream, ct);

        // ── Step 2: Decrypt (Trial and Error) ─────────────────────────────────
        ICipher? successfulCipher = null;
        byte[]? decryptedHs = null;
        string? successfulType = null;

        foreach (var type in TrialTypes)
        {
            var trialCipher = handshakeCipherFactory(false, type);
            var buffer = clientHsRaw.ToArray(); // Work on a copy
            trialCipher.SetIv(new byte[8]);
            trialCipher.Decrypt(buffer);

            if (IsValidHandshake(buffer))
            {
                successfulCipher = trialCipher;
                decryptedHs = buffer;
                successfulType = type;
                logger?.LogInformation("MITM: Successfully detected handshake type: {Type}", type);
                break;
            }
            trialCipher.Dispose();
        }

        if (successfulCipher == null)
        {
            logger?.LogError("MITM: Failed to detect handshake type. Tried: {Types}. " +
                           "Likely causes: incorrect P-array/S-boxes, or the server uses a completely different cipher. " +
                           "Raw packet start: {Hex}", string.Join(", ", TrialTypes), 
                           BitConverter.ToString(clientHsRaw[..Math.Min(clientHsRaw.Length, 16)]));
            throw new InvalidOperationException("Could not decrypt client handshake.");
        }

        // ── Step 3: Parse the client's handshake ──────────────────────────────
        var clientHs = HandshakeParser.ParseServerHandshake(decryptedHs);

        var realClientPubKey = clientHs.ServerPublicKey;

        logger?.LogDebug(
            "MITM: client init parsed — P={P}B G={G}B PubKey={K}B ClientIvec={CI}B ServerIvec={SI}B",
            clientHs.Prime.Length, clientHs.Generator.Length, realClientPubKey.Length,
            clientHs.ClientIvec.Length, clientHs.ServerIvec.Length);

        // ── Step 4: Generate proxy→server ephemeral DH keypair ────────────────
        using var dhForServer = new DiffieHellman();
        dhForServer.Initialize(clientHs.Prime, clientHs.Generator);
        var proxyPubKeyForServer = dhForServer.GeneratePublicKey();

        // ── Step 5: Substitute proxy's pubkey and forward to server ───────────
        clientHs.ServerPublicKey = proxyPubKeyForServer;
        var modifiedClientHs = HandshakeParser.BuildServerHandshake(clientHs);

        using var initEncryptToServer = handshakeCipherFactory(true, successfulType!);
        initEncryptToServer.SetIv(new byte[8]);
        initEncryptToServer.Encrypt(modifiedClientHs);
        await serverStream.WriteAsync(modifiedClientHs, ct);

        logger?.LogDebug("MITM: modified init forwarded to server ({Bytes}B)", modifiedClientHs.Length);

        // ── Step 6: Read the server's DH reply ────────────────────────────────
        logger?.LogDebug("MITM: waiting for server DH reply...");

        var serverReplyRaw = await ReadPacketAsync(serverStream, ct);

        // The server reply is formatted as the 5xxx ClientHandshakeReply:
        // Header + Data + PublicKey + TqClient.
        // The "ClientPublicKey" slot carries the SERVER'S public key here.
        // Try parsing as plaintext first; if that throws, decrypt and retry.
        ClientHandshakeReply serverReply;
        try
        {
            serverReply = HandshakeParser.ParseClientReply(serverReplyRaw);
        }
        catch (Exception ex)
        {
            logger?.LogWarning("MITM: Plaintext parse failed, attempting decryption... ({Msg})", ex.Message);
            using var replyDecrypt = handshakeCipherFactory(false, successfulType!);
            replyDecrypt.SetIv(new byte[8]);
            replyDecrypt.Decrypt(serverReplyRaw);
            try
            {
                serverReply = HandshakeParser.ParseClientReply(serverReplyRaw);
            }
            catch (Exception ex2)
            {
                logger?.LogError("MITM: Failed to parse server reply even after decryption. " +
                               "The handshake cipher used might be incorrect, or the P-array/S-boxes don't match. " +
                               "Details: {Msg}", ex2.Message);
                throw;
            }
        }

        var realServerPubKey = serverReply.ClientPublicKey;

        logger?.LogDebug("MITM: server reply parsed — PubKey={K}B", realServerPubKey.Length);

        // ── Step 7: Generate proxy→client ephemeral DH keypair ────────────────
        using var dhForClient = new DiffieHellman();
        dhForClient.Initialize(clientHs.Prime, clientHs.Generator);
        var proxyPubKeyForClient = dhForClient.GeneratePublicKey();

        // ── Step 8: Substitute proxy's pubkey and forward to client ───────────
        serverReply.ClientPublicKey = proxyPubKeyForClient;
        var modifiedServerReply = HandshakeParser.BuildClientReply(serverReply);

        // Server replies in the same encryption style as the init packet.
        // Re-encrypt for the client before forwarding.
        using var replyEncryptToClient = handshakeCipherFactory(true, successfulType!);
        replyEncryptToClient.SetIv(new byte[8]);
        replyEncryptToClient.Encrypt(modifiedServerReply);
        await clientStream.WriteAsync(modifiedServerReply, ct);

        logger?.LogDebug("MITM: modified reply forwarded to client ({Bytes}B)", modifiedServerReply.Length);

        // ── Step 9: Compute shared secrets ────────────────────────────────────
        var sharedSecretServer = dhForServer.ComputeSharedSecret(realServerPubKey);
        var sharedSecretClient = dhForClient.ComputeSharedSecret(realClientPubKey);

        logger?.LogDebug(
            "MITM: shared secrets — client={CLen}B server={SLen}B",
            sharedSecretClient.Length, sharedSecretServer.Length);

        // ── Step 10: Initialise 4 session ciphers (standard BF, NOT chain table) ─
        //
        // IV assignment (from gProxy reference):
        //   Proxy←Client (decrypt): IV = ClientIvec   ← client encrypts outbound with ClientIvec
        //   Proxy→Client (encrypt): IV = ServerIvec   ← client decrypts inbound with ServerIvec
        //   Proxy←Server (decrypt): IV = ServerIvec   ← server encrypts outbound with ServerIvec
        //   Proxy→Server (encrypt): IV = ClientIvec   ← server decrypts inbound with ClientIvec
        //
        // Key size: Blowfish accepts 4–56 bytes. Clamp the shared secret to that range.
        // TODO: confirm whether CO 7xxx uses raw DH output, a hash, or a fixed-size slice.
        var clientKey = TrimToKeySize(sharedSecretClient, successfulType!);
        var serverKey = TrimToKeySize(sharedSecretServer, successfulType!);

        // Factory creates the session ciphers. We try to match the handshake cipher type.
        var clientDecrypt = handshakeCipherFactory(false, successfulType!);
        clientDecrypt.SetKey(clientKey);
        clientDecrypt.SetIv(clientHs.ClientIvec);

        var clientEncrypt = handshakeCipherFactory(true, successfulType!);
        clientEncrypt.SetKey(clientKey);
        clientEncrypt.SetIv(clientHs.ServerIvec);

        var serverDecrypt = handshakeCipherFactory(false, successfulType!);
        serverDecrypt.SetKey(serverKey);
        serverDecrypt.SetIv(clientHs.ServerIvec);

        var serverEncrypt = handshakeCipherFactory(true, successfulType!);
        serverEncrypt.SetKey(serverKey);
        serverEncrypt.SetIv(clientHs.ClientIvec);

        logger?.LogDebug("MITM: 4 session ciphers initialised ({Type})", clientDecrypt.GetType().Name);

        successfulCipher.Dispose(); // Done with the temporary one
        return new HandshakeResult(clientDecrypt, clientEncrypt, serverDecrypt, serverEncrypt);
    }

    /// <summary>
    /// Checks if the decrypted buffer looks like a valid TQ handshake.
    /// It should start with "TQServer" or have a plausible length prefix.
    /// </summary>
    private static bool IsValidHandshake(ReadOnlySpan<byte> data)
    {
        if (data.Length < 11) return false;
        // Check for TQ header magic (e.g. 11 bytes)
        // Usually ends with "TqServer" or contains some recognizable pattern.
        // For now, let's assume if HandshakeParser doesn't throw, it's valid.
        try {
            var hs = HandshakeParser.ParseServerHandshake(data);
            return hs.Header.Length == 11 && hs.Prime.Length > 0;
        } catch {
            return false;
        }
    }

    /// <summary>
    /// Clamp the session key to the maximum allowed by the cipher.
    /// CO standard uses the first 64 bytes of the DH shared secret.
    /// Blowfish accepts up to 56–72 bytes. CAST5 accepts 5–16 bytes.
    /// </summary>
    private static ReadOnlySpan<byte> TrimToKeySize(byte[] key, string type)
    {
        if (type.ToLowerInvariant().Contains("cast5"))
            return key.Length <= 16 ? key : key.AsSpan(0, 16);
        
        // Blowfish / Default
        return key.Length <= 64 ? key : key.AsSpan(0, 64);
    }

    /// <summary>
    /// Read one handshake packet from <paramref name="stream"/>.
    /// Performs a single ReadAsync call — handshake packets arrive in a single
    /// TCP segment, so one read captures the complete packet.
    /// </summary>
    private static async Task<byte[]> ReadPacketAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[4096];
        var n = await stream.ReadAsync(buffer.AsMemory(), ct);
        if (n == 0)
            throw new IOException("Stream closed before handshake packet was received.");
        return buffer[..n];
    }
}
