namespace Sentinel.Core.Models;

/// <summary>
/// Configuration for a single proxy listener (auth or game).
/// </summary>
public sealed class ProxyEndpointConfig
{
    /// <summary>Local port to listen on for client connections.</summary>
    public int ListenPort { get; set; }

    /// <summary>Remote server hostname or IP to forward traffic to.</summary>
    public string RemoteHost { get; set; } = "127.0.0.1";

    /// <summary>Remote server port to forward traffic to.</summary>
    public int RemotePort { get; set; }

    /// <summary>Human-readable name for logging (e.g. "Auth", "Game").</summary>
    public string Name { get; set; } = "";

    /// <summary>Whether to perform DH MITM on this endpoint to decrypt traffic.</summary>
    public bool EnableMitm { get; set; }

    /// <summary>
    /// Whether to apply the CO 7xxx gameplay cipher to server→client packets for
    /// read-only decryption logging. The original encrypted bytes are always forwarded
    /// unchanged — only the logged copy is decrypted. Mutually exclusive with
    /// <see cref="EnableMitm"/>; if both are set, MITM takes precedence.
    /// </summary>
    public bool EnableGameplayDecrypt { get; set; }

    /// <summary>
    /// Handshake cipher type: "Blowfish", "Cast5", "ChainTable", or "Auto".
    /// </summary>
    public string HandshakeCipher { get; set; } = "Auto";
}

/// <summary>
/// Top-level proxy configuration, bound from appsettings.json.
/// </summary>
public sealed class ProxyConfiguration
{
    public const string SectionName = "Proxy";

    /// <summary>All proxy endpoints to listen on.</summary>
    public List<ProxyEndpointConfig> Endpoints { get; set; } = [];

    /// <summary>Directory to save packet log files.</summary>
    public string LogDirectory { get; set; } = "logs";

    /// <summary>Whether to output packet hex to console.</summary>
    public bool LogToConsole { get; set; } = true;

    /// <summary>
    /// Path to the BF_encrypt chain table JSON file used for handshake decryption.
    /// Relative to the application working directory.
    /// Extend the table by running tools/frida/capture-keystream.js against the game process.
    /// </summary>
    public string HandshakeChainTablePath { get; set; } = "resources/handshake-chain-table.json";

    /// <summary>
    /// Console output verbosity: "minimal", "normal", or "verbose".
    /// minimal = session start/end + periodic summary only.
    /// normal  = session start/end + per-packet one-liner (direction, size, no hex).
    /// verbose = everything including hex dumps (for debugging).
    /// </summary>
    public string ConsoleVerbosity { get; set; } = "minimal";
}
