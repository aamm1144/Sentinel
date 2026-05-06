using System.Buffers;
using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Core.Enums;
using Sentinel.Core.Interfaces;
using Sentinel.Core.Models;

namespace Sentinel.Network.Logging;

/// <summary>
/// Logs raw packet data to binary files (one per session) and optionally to console.
///
/// Binary file format per entry:
///   [8 bytes] timestamp (UTC ticks, little-endian Int64)
///   [1 byte]  direction (0 = C→S, 1 = S→C)
///   [4 bytes] data length (little-endian Int32)
///   [N bytes] raw packet data
/// </summary>
public sealed class PacketLogger : IPacketLogger
{
    private readonly ILogger<PacketLogger> _logger;
    private readonly string _consoleVerbosity;
    private readonly string _logDirectory;

    private readonly ConcurrentDictionary<Guid, FileStream> _sessionFiles = new();
    private readonly ConcurrentDictionary<Guid, StreamWriter> _sessionTextFiles = new();

    // Reusable header buffer: 8 (timestamp) + 1 (direction) + 4 (length) = 13 bytes
    private const int HeaderSize = 13;

    public PacketLogger(IOptions<ProxyConfiguration> config, ILogger<PacketLogger> logger)
    {
        _logger = logger;
        _consoleVerbosity = (config.Value.ConsoleVerbosity ?? "minimal").ToLowerInvariant();
        _logDirectory = config.Value.LogDirectory;

        Directory.CreateDirectory(_logDirectory);
    }

    public async ValueTask LogPacketAsync(
        Guid sessionId,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        if (data.Length == 0)
            return;

        // Write to binary file (always)
        var stream = GetOrCreateSessionFile(sessionId);
        await WriteBinaryEntryAsync(stream, direction, data, timestamp);

        // Write to text hex log (always)
        var textWriter = GetOrCreateSessionTextFile(sessionId);
        await WriteTextEntryAsync(textWriter, direction, data, timestamp);

        // Write to console based on verbosity
        if (_consoleVerbosity == "verbose")
            WriteConsoleVerbose(sessionId, direction, data, timestamp);
        else if (_consoleVerbosity == "normal")
            WriteConsoleNormal(sessionId, direction, data, timestamp);
        // "minimal" — no per-packet console output
    }

    public async ValueTask FlushAsync()
    {
        foreach (var stream in _sessionFiles.Values)
        {
            try { await stream.FlushAsync(); } catch { }
        }
        foreach (var writer in _sessionTextFiles.Values)
        {
            try { await writer.FlushAsync(); } catch { }
        }
    }

    private FileStream GetOrCreateSessionFile(Guid sessionId)
    {
        return _sessionFiles.GetOrAdd(sessionId, id =>
        {
            var fileName = $"session_{id:N}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.bin";
            var filePath = Path.Combine(_logDirectory, fileName);
            _logger.LogDebug("Created binary packet log: {Path}", filePath);
            return new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read,
                bufferSize: 65536, useAsync: true);
        });
    }

    private StreamWriter GetOrCreateSessionTextFile(Guid sessionId)
    {
        return _sessionTextFiles.GetOrAdd(sessionId, id =>
        {
            var fileName = $"session_{id:N}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.log";
            var filePath = Path.Combine(_logDirectory, fileName);
            _logger.LogDebug("Created text hex log: {Path}", filePath);
            var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read,
                bufferSize: 65536, useAsync: true);
            return new StreamWriter(stream, Encoding.UTF8, leaveOpen: false);
        });
    }

    private static async ValueTask WriteBinaryEntryAsync(
        FileStream stream,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        // Write header
        var header = ArrayPool<byte>.Shared.Rent(HeaderSize);
        try
        {
            BitConverter.TryWriteBytes(header.AsSpan(0, 8), timestamp.UtcTicks);
            header[8] = (byte)direction;
            BitConverter.TryWriteBytes(header.AsSpan(9, 4), data.Length);

            await stream.WriteAsync(header.AsMemory(0, HeaderSize));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }

        // Write data
        await stream.WriteAsync(data);
    }

    private static async ValueTask WriteTextEntryAsync(
        StreamWriter writer,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        var arrow = direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
        var time = timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

        await writer.WriteAsync($"[{time}] {arrow}  {data.Length,6} bytes   ");

        var span = data.Span;
        for (var i = 0; i < data.Length; i++)
        {
            await writer.WriteAsync(span[i].ToString("X2"));
            if (i < data.Length - 1)
                await writer.WriteAsync(' ');
        }

        await writer.WriteLineAsync();
    }

    /// <summary>"normal" verbosity — one line per packet, no hex.</summary>
    private static void WriteConsoleNormal(
        Guid sessionId,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        var arrow = direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
        var sessionShort = sessionId.ToString()[..8];
        var time = timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

        Console.WriteLine($"[{time}] [{sessionShort}] {arrow}  {data.Length,6} bytes");
    }

    /// <summary>"verbose" verbosity — full hex dump (original behavior).</summary>
    private static void WriteConsoleVerbose(
        Guid sessionId,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        var arrow = direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
        var sessionShort = sessionId.ToString()[..8];
        var time = timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

        var sb = new StringBuilder(128);
        sb.Append($"[{time}] [{sessionShort}] {arrow}  {data.Length,6} bytes");

        // First 64 bytes as hex preview
        var previewLength = Math.Min(data.Length, 64);
        var span = data.Span[..previewLength];

        sb.Append("   ");
        for (var i = 0; i < previewLength; i++)
        {
            sb.Append(span[i].ToString("X2"));
            if (i < previewLength - 1)
                sb.Append(' ');
        }

        if (data.Length > 64)
            sb.Append(" ...");

        Console.WriteLine(sb.ToString());
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var kvp in _sessionFiles)
        {
            try
            {
                await kvp.Value.FlushAsync();
                await kvp.Value.DisposeAsync();
            }
            catch { }
        }
        _sessionFiles.Clear();

        foreach (var kvp in _sessionTextFiles)
        {
            try
            {
                await kvp.Value.FlushAsync();
                await kvp.Value.DisposeAsync();
            }
            catch { }
        }
        _sessionTextFiles.Clear();
    }
}
