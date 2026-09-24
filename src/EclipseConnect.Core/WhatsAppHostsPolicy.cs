using System.Net;
using System.Net.Sockets;

namespace EclipseConnect.Core;

// Only these exact names may be added to Windows hosts. No wildcard, route, DNS or proxy change.
public static class WhatsAppHostsPolicy
{
    public const string Begin = "# Eclipse Connect WhatsApp mapping begin";
    public const string End = "# Eclipse Connect WhatsApp mapping end";
    public static readonly string[] Names = ["web.whatsapp.com", "static.whatsapp.net"];

    public static bool IsManaged(string content) => ManagedRange(content.Split('\n')) is not null;

    public static string Apply(string content, IPAddress address)
    {
        Validate(content);
        if (address.AddressFamily != AddressFamily.InterNetwork || !MetaVpnPolicy.RoutesAddress(address))
            throw new InvalidDataException("Адрес WhatsApp не входит в проверенные сети Meta.");
        var lines = content.Split('\n');
        if (ManagedRange(lines) != null) throw new InvalidOperationException("Сопоставление WhatsApp уже активно.");
        if (HasExternalEntry(lines)) throw new InvalidOperationException("В hosts уже есть записи WhatsApp. Чужие записи не изменены.");
        var newline = content.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var separator = content.Length == 0 || content.EndsWith('\n') ? "" : newline;
        return content + separator + newline + Begin + newline +
            address + " " + string.Join(' ', Names) + newline + End + newline;
    }

    public static string Remove(string content)
    {
        Validate(content);
        var lines = content.Split('\n').ToList();
        var range = ManagedRange(lines) ?? throw new InvalidOperationException("Сопоставление Connect не найдено; чужие записи не изменены.");
        var first = range.Start;
        if (first > 0 && lines[first - 1].TrimEnd('\r').Length == 0) first--;
        lines.RemoveRange(first, range.End - first + 1);
        return string.Join('\n', lines);
    }

    public static bool HasExternalEntry(string content) => HasExternalEntry(content.Split('\n'));

    private static bool HasExternalEntry(IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            var tokens = line.Split('#', 2)[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length > 1 && tokens.Skip(1).Any(host =>
                Names.Contains(host.TrimEnd('.'), StringComparer.OrdinalIgnoreCase))) return true;
        }
        return false;
    }

    private static (int Start, int End)? ManagedRange(IReadOnlyList<string> lines)
    {
        var starts = Enumerable.Range(0, lines.Count).Where(i => lines[i].TrimEnd('\r') == Begin).ToArray();
        var ends = Enumerable.Range(0, lines.Count).Where(i => lines[i].TrimEnd('\r') == End).ToArray();
        if (starts.Length == 0 && ends.Length == 0) return null;
        if (starts.Length != 1 || ends.Length != 1 || ends[0] != starts[0] + 2)
            throw new InvalidDataException("Блок WhatsApp в hosts повреждён; автоматическая правка запрещена.");
        var values = lines[starts[0] + 1].TrimEnd('\r').Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (values.Length != 3 || !IPAddress.TryParse(values[0], out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !MetaVpnPolicy.RoutesAddress(address) ||
            !values.Skip(1).SequenceEqual(Names, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("Блок WhatsApp в hosts изменён; автоматическая правка запрещена.");
        return (starts[0], ends[0]);
    }

    private static void Validate(string content)
    {
        if (content.Length > 64 * 1024 || content.Contains('\0') || content.Contains('\uFFFD'))
            throw new InvalidDataException("Нестандартный hosts: автоматическая правка запрещена.");
    }
}
