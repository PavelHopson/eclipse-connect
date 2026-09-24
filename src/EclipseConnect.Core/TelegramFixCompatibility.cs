using System.Text;

namespace EclipseConnect.Core;

// Reviewed data, not a remote script or a DNS/IP bypass. Updated with a reviewed Connect release.
public static class TelegramFixCompatibility
{
    public const string ResourcePath = "lists/connect-telegram-exclude.txt";
    public const string Argument = "--hostlist-exclude=" + ResourcePath;
    public const string SnapshotDate = "2026-09-08";
    public const string UpstreamPoolSha256 = "fbc0cb7bad16083fd603b42ded73b775ec3f63a55616adee77bc8e6653b9940f";
    // Flowseal/tg-ws-proxy: .github/cfproxy-domains.txt decoded as specified in proxy/config.py.
    // proxy/bridge.py and proxy/utils.py construct these TLS SNI names for DC1..DC5.
    private static readonly string[] RelayDomains =
    [
        "pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
        "lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk",
        "sorokodin.co.uk", "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk",
        "nebally.co.uk", "havegreatday.co.uk", "pomogite.co.uk", "fixtelega.co.uk",
        "sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk", "nothingthere.co.uk"
    ];
    public static IReadOnlyList<string> ExactHosts { get; } = Array.AsReadOnly(
        Enumerable.Range(1, 5).SelectMany(dc => new[] { $"kws{dc}.web.telegram.org", $"kws{dc}-1.web.telegram.org" }
            .Concat(RelayDomains.Select(domain => $"kws{dc}.{domain}")))
        .Order(StringComparer.Ordinal).ToArray());

    public static Stream OpenResource()
    {
        // '^' is winws' exact-name marker: do not exempt web.telegram.org, a parent domain,
        // arbitrary subdomains, shared Cloudflare IPs, or custom user Workers.
        var text = "# Eclipse Connect / TgWsProxy TLS compatibility / " + SnapshotDate + "\n" +
            string.Join("\n", ExactHosts.Select(host => "^" + host)) + "\n";
        return new MemoryStream(Encoding.ASCII.GetBytes(text), writable: false);
    }

    public static string[] AddExclusions(IReadOnlyList<string> arguments)
    {
        var output = new List<string>();
        var group = new List<string>();
        void Flush()
        {
            // TCP carries the proxy TLS streams; UDP/443 can carry QUIC.
            // Leave Discord/STUN and unknown gaming UDP strategies unchanged.
            if (group.Any(a => a.StartsWith("--filter-tcp=", StringComparison.Ordinal) || a == "--filter-udp=443") &&
                !group.Contains(Argument)) group.Add(Argument);
            output.AddRange(group); group.Clear();
        }
        foreach (var argument in arguments)
        {
            if (argument == "--new") { Flush(); output.Add(argument); }
            else group.Add(argument);
        }
        Flush();
        return output.ToArray();
    }
}
