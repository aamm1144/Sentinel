using Sentinel.Core.Enums;

namespace Sentinel.Core.Interfaces;

/// <summary>
/// Logs raw packet data for capture and analysis.
/// Implementations may write to console, file, or both.
/// </summary>
public interface IPacketLogger : IAsyncDisposable
{
    /// <summary>
    /// Log a single packet.
    /// </summary>
    /// <param name="sessionId">Which session this packet belongs to.</param>
    /// <param name="direction">Client-to-server or server-to-client.</param>
    /// <param name="data">Raw packet bytes.</param>
    /// <param name="timestamp">When the packet was captured.</param>
    ValueTask LogPacketAsync(
        Guid sessionId,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp);

    /// <summary>
    /// Flush any buffered data to storage.
    /// </summary>
    ValueTask FlushAsync();
}
