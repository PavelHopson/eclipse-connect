using System.Runtime.Versioning;

namespace EclipseConnect.Core;

// Cooperative lifetime interlock, not authorization. Preflight still checks external/older clients.
// Use kernel-object existence, not mutex ownership: async continuations may run on another thread.
[SupportedOSPlatform("windows")]
internal sealed class WindowsNetworkModeLease : IDisposable
{
    internal const string Name = @"Global\EclipseConnect.NetworkMode.v1";
    private Mutex? marker;
    private WindowsNetworkModeLease(Mutex marker) => this.marker = marker;

    internal static WindowsNetworkModeLease Acquire(string name = Name)
    {
        var marker = new Mutex(false, name, out var created);
        if (created) return new(marker);
        marker.Dispose();
        throw new InvalidOperationException("FIX или VPN уже запускается либо работает в другом окне Connect. Сначала отключите его там.");
    }

    public void Dispose() => Interlocked.Exchange(ref marker, null)?.Dispose();
}
