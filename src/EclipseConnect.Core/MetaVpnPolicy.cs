using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EclipseConnect.Core;

// Fixed, reviewed AS32934 snapshot. No route lists, commands, URLs or DNS settings from IPC.
public static class MetaVpnPolicy
{
    public const string Name = "Instagram / Meta";
    public static DateTimeOffset ObservedAt => new(2026, 9, 11, 0, 0, 0, TimeSpan.Zero);
    public static DateTimeOffset ValidUntil => ObservedAt.AddDays(90);
    internal static IReadOnlyList<string> Prefixes { get; } = Array.AsReadOnly(new[]
    {
        "102.132.96.0/20", "103.4.96.0/22", "129.134.0.0/17",
        "157.240.0.0/17", "157.240.192.0/18", "163.70.128.0/17",
        "163.77.132.0/23", "163.77.136.0/23", "173.252.64.0/19",
        "173.252.96.0/19", "179.60.192.0/22", "185.60.216.0/22",
        "185.89.216.0/22", "204.15.20.0/22", "2620:0:1c00::/40",
        "2a03:2880::/32", "31.13.24.0/21", "31.13.64.0/18", "45.64.40.0/22",
        "57.141.0.0/24", "57.141.10.0/24", "57.141.12.0/24",
        "57.141.13.0/24", "57.141.14.0/24", "57.141.16.0/24",
        "57.141.17.0/24", "57.141.18.0/24", "57.141.19.0/24",
        "57.141.2.0/24", "57.141.20.0/24", "57.141.22.0/24",
        "57.141.24.0/24", "57.141.3.0/24", "57.141.4.0/24",
        "57.141.5.0/24", "57.141.6.0/24", "57.141.8.0/24",
        "57.144.0.0/14", "66.220.144.0/20", "69.171.224.0/19",
        "69.63.176.0/20", "74.119.76.0/22"
    });
    // Guard against a future bad snapshot accidentally including local or broad shared networks.
    private static readonly string[] Forbidden =
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "192.0.0.0/24", "192.0.2.0/24",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
        "::/8", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
        "104.16.0.0/13", "104.24.0.0/14", "162.158.0.0/15", "172.64.0.0/13",
        "2606:4700::/32", "2a06:98c0::/29"
    ];
    private static readonly IPNetwork[] Routes = ParseRoutes(Prefixes);
    public static bool IsCurrent(DateTimeOffset now) => now >= ObservedAt && now < ValidUntil;
    public static bool RoutesAddress(IPAddress address) => !address.IsIPv4MappedToIPv6 && Routes.Any(r => r.Contains(address));
    public static void RequireCurrent(DateTimeOffset now)
    {
        if (!IsCurrent(now)) throw new InvalidOperationException("Список сетей Instagram требует обновления Connect или проверки даты Windows. VPN не запущен.");
    }
    internal static IPNetwork[] ParseRoutes(IEnumerable<string> source)
    {
        var values = source.Take(129).ToArray();
        if (values.Length is < 2 or > 128 || values.Distinct(StringComparer.Ordinal).Count() != values.Length)
            throw new InvalidDataException("Некорректный список сетей VPN. Полный туннель вместо него не включается.");
        var routes = new List<IPNetwork>();
        foreach (var value in values)
        {
            if (!IPNetwork.TryParse(value, out var route) || route.ToString() != value ||
                route.BaseAddress.IsIPv4MappedToIPv6 ||
                route.PrefixLength < (route.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 14 : 32))
                throw new InvalidDataException("Недопустимый диапазон выборочного VPN.");
            routes.Add(route);
        }
        if (!routes.Any(r => r.BaseAddress.AddressFamily == AddressFamily.InterNetwork) ||
            !routes.Any(r => r.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6))
            throw new InvalidDataException("Для выборочного VPN нужны IPv4 и IPv6.");
        var denied = Forbidden.Select(IPNetwork.Parse).ToArray();
        foreach (var route in routes)
            if (denied.Any(d => Overlap(d, route)) || routes.Any(other => !other.Equals(route) && Overlap(other, route)))
                throw new InvalidDataException("Пересечение или запрещённый диапазон в списке VPN.");
        return routes.ToArray();
    }
    private static bool Overlap(IPNetwork a, IPNetwork b) =>
        a.BaseAddress.AddressFamily == b.BaseAddress.AddressFamily &&
        (a.Contains(b.BaseAddress) || b.Contains(a.BaseAddress));
    internal static void CheckEndpoint(IEnumerable<IPAddress> addresses)
    {
        var values = addresses.Take(33).ToArray();
        if (values.Length is < 1 or > 32 || values.Any(RoutesAddress))
            throw new InvalidDataException("Адрес VPN-сервера не определён или пересекается с выборочными маршрутами. Подключение отменено.");
    }
    internal static string ServiceConfiguration(AwgProfile profile, DateTimeOffset now)
    {
        RequireCurrent(now);
        _ = ParseRoutes(Prefixes); // Fail closed even after an erroneous developer-edited snapshot.
        var output = new StringBuilder();
        foreach (var line in profile.Configuration.Split('\n'))
        {
            if (line.StartsWith("DNS = ", StringComparison.Ordinal)) continue;
            if (line.StartsWith("AllowedIPs = ", StringComparison.Ordinal))
                output.Append("AllowedIPs = ").AppendJoin(", ", Prefixes).Append('\n');
            else if (line.StartsWith("Address = ", StringComparison.Ordinal))
            {
                var addresses = line[10..].Split(", ").Select(value => IPAddress.Parse(value.Split('/')[0])).ToArray();
                if (addresses.Any(ip => IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) ||
                    ip.IsIPv6Multicast || ip.IsIPv6LinkLocal || RoutesAddress(ip) ||
                    ip.AddressFamily == AddressFamily.InterNetwork && (ip.GetAddressBytes()[0] >= 224 || ip.GetAddressBytes()[0] == 0)))
                    throw new InvalidDataException("Адрес интерфейса несовместим с выборочным VPN.");
                output.Append("Address = ").AppendJoin(", ", addresses.Select(ip => ip + (ip.AddressFamily == AddressFamily.InterNetwork ? "/32" : "/128"))).Append('\n');
            }
            else output.Append(line).Append('\n');
        }
        // The original profile remains unchanged, including its DNS, routes and secrets.
        if (Encoding.UTF8.GetByteCount(output.ToString()) > AwgProfile.MaxBytes)
            throw new InvalidDataException("Служебный профиль слишком большой. Подключение отменено.");
        return output.ToString();
    }
}
