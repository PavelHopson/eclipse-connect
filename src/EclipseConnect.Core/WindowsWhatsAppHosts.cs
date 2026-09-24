using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace EclipseConnect.Core;

public sealed record WhatsAppHostsState(bool Managed, bool External);

// Explicit, elevated, reversible action. Never runs on startup or when FIX starts.
[SupportedOSPlatform("windows")]
public static class WindowsWhatsAppHosts
{
    private static readonly string[] CandidateNames =
    [
        "web.whatsapp.com", "static.whatsapp.net",
        "media-fra3-1.cdn.whatsapp.net", "media-fra5-1.cdn.whatsapp.net"
    ];
    public static string HostsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    public static WhatsAppHostsState Inspect()
    {
        var text = ReadHosts(HostsPath);
        return new(WhatsAppHostsPolicy.IsManaged(text), WhatsAppHostsPolicy.HasExternalEntry(text) &&
            !WhatsAppHostsPolicy.IsManaged(text));
    }

    public static async Task Apply(Storage storage, CancellationToken ct)
    {
        RequireAdministrator();
        using var guard = Acquire();
        var original = File.ReadAllBytes(HostsPath);
        var text = Decode(original);
        if (WhatsAppHostsPolicy.IsManaged(text)) throw new InvalidOperationException("Сопоставление уже активно.");
        if (WhatsAppHostsPolicy.HasExternalEntry(text))
            throw new InvalidOperationException("В hosts уже есть записи WhatsApp. Чужие записи не изменены.");
        // Avoid choosing an address observed through a tunnel and later pinning it outside that tunnel.
        if (new WindowsFixRuntime("", storage).HasConfoundingTunnel)
            throw new InvalidOperationException("При активном туннеле сопоставление WhatsApp не применяется.");
        var address = await FindCandidate(
            (name, token) => Dns.GetHostAddressesAsync(name, token),
            ProbeCandidate, ct);
        var updated = WhatsAppHostsPolicy.Apply(text, address);
        ReplaceWithBackup(storage, original, updated);
    }

    public static void Remove(Storage storage)
    {
        RequireAdministrator();
        using var guard = Acquire();
        var original = File.ReadAllBytes(HostsPath);
        var updated = WhatsAppHostsPolicy.Remove(Decode(original));
        ReplaceWithBackup(storage, original, updated);
    }

    internal static async Task<IPAddress> FindCandidate(
        Func<string, CancellationToken, Task<IPAddress[]>> resolve,
        Func<IPAddress, CancellationToken, Task<bool>> probe, CancellationToken ct)
    {
        var candidates = new List<IPAddress>();
        foreach (var name in CandidateNames)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                foreach (var address in await resolve(name, timeout.Token))
                    if (address.AddressFamily == AddressFamily.InterNetwork &&
                        MetaVpnPolicy.RoutesAddress(address) && !candidates.Contains(address))
                        candidates.Add(address);
            }
            catch (Exception error) when (error is SocketException or OperationCanceledException)
            { ct.ThrowIfCancellationRequested(); }
        }
        foreach (var address in candidates.Take(16))
        {
            ct.ThrowIfCancellationRequested();
            if (await probe(address, ct)) return address;
        }
        throw new IOException("Доступный адрес WhatsApp не найден. hosts не изменён.");
    }

    private static async Task<bool> ProbeCandidate(IPAddress address, CancellationToken ct)
    {
        try
        {
            using var handler = new SocketsHttpHandler
            {
                UseProxy = false, UseCookies = false, AllowAutoRedirect = false,
                ConnectTimeout = TimeSpan.FromSeconds(3),
                ConnectCallback = async (context, token) =>
                {
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), token);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch { socket.Dispose(); throw; }
                }
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            using var web = await client.SendAsync(new(HttpMethod.Head, "https://web.whatsapp.com/"),
                HttpCompletionOption.ResponseHeadersRead, ct);
            if (!web.IsSuccessStatusCode) return false;
            using var files = await client.SendAsync(new(HttpMethod.Head, "https://static.whatsapp.net/"),
                HttpCompletionOption.ResponseHeadersRead, ct);
            return (int)files.StatusCode is >= 200 and < 400 or 404;
        }
        catch (Exception error) when (error is HttpRequestException or IOException or OperationCanceledException or SocketException)
        { ct.ThrowIfCancellationRequested(); return false; }
    }

    private static string ReadHosts(string path) => Decode(File.ReadAllBytes(path));
    private static string Decode(byte[] bytes)
    {
        if (bytes.Length > 64 * 1024) throw new InvalidDataException("hosts слишком велик для безопасной правки.");
        var text = Encoding.UTF8.GetString(bytes);
        if (text.Contains('\uFFFD') || text.Contains('\0'))
            throw new InvalidDataException("Кодировка hosts не поддерживается; файл не изменён.");
        return text;
    }

    private static void ReplaceWithBackup(Storage storage, byte[] original, string updated)
    {
        if (!File.ReadAllBytes(HostsPath).SequenceEqual(original))
            throw new IOException("hosts изменился во время проверки; правка отменена.");
        Storage.AssertNoLinks(HostsPath);
        var backup = storage.Resolve("backups/hosts-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") +
            "-" + Guid.NewGuid().ToString("N") + ".bak");
        Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
        File.WriteAllBytes(backup, original);
        if (!SHA256.HashData(File.ReadAllBytes(backup)).SequenceEqual(SHA256.HashData(original)))
            throw new IOException("Резервная копия hosts не подтверждена; правка отменена.");
        var temp = Path.Combine(Path.GetDirectoryName(HostsPath)!,
            ".eclipse-connect-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            { var bytes = Encoding.UTF8.GetBytes(updated); output.Write(bytes); output.Flush(true); }
            if (!File.ReadAllBytes(HostsPath).SequenceEqual(original))
                throw new IOException("hosts изменился перед записью; правка отменена.");
            File.Replace(temp, HostsPath, null);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static void RequireAdministrator()
    {
        if (!WindowsFixRuntime.IsAdministrator())
            throw new UnauthorizedAccessException("Для изменения hosts нужны права администратора.");
    }
    private static IDisposable Acquire()
    {
        var marker = new Mutex(false, @"Local\EclipseConnect.WhatsAppHosts");
        try
        {
            if (!marker.WaitOne(0)) throw new InvalidOperationException("Другая правка hosts уже выполняется.");
        }
        catch (AbandonedMutexException) { /* Verify the current file before every write. */ }
        catch { marker.Dispose(); throw; }
        return new MutexLease(marker);
    }
    private sealed class MutexLease(Mutex marker) : IDisposable
    {
        public void Dispose() { marker.ReleaseMutex(); marker.Dispose(); }
    }
}
