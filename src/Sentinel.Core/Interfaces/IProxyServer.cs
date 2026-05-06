namespace Sentinel.Core.Interfaces;

/// <summary>
/// Listens for incoming game client connections and creates proxy sessions.
/// </summary>
public interface IProxyServer : IAsyncDisposable
{
    /// <summary>Whether the server is currently listening.</summary>
    bool IsListening { get; }

    /// <summary>All currently active sessions.</summary>
    IReadOnlyCollection<IProxySession> ActiveSessions { get; }

    /// <summary>
    /// Start listening for client connections.
    /// Returns when cancellation is requested.
    /// </summary>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>Stop listening and disconnect all sessions.</summary>
    Task StopAsync();

    /// <summary>Fired when a new session is established.</summary>
    event Action<IProxySession>? SessionStarted;

    /// <summary>Fired when a session ends.</summary>
    event Action<IProxySession>? SessionEnded;
}
