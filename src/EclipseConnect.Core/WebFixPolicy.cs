using System.Net;
using System.Numerics;

namespace EclipseConnect.Core;

// Reviewed companion allowlists. No broad user-supplied domain/IP collections or gaming rules.
internal static class WebFixPolicy
{
    internal const string Youtube = "youtube.com,youtube-nocookie.com,youtu.be,googlevideo.com,ytimg.com,yt3.ggpht.com,yt4.ggpht.com,yt3.googleusercontent.com,jnn-pa.googleapis.com,wide-youtube.l.google.com,youtube-ui.l.google.com,youtubeembeddedplayer.googleapis.com,youtubekids.com,youtubei.googleapis.com,yt-video-upload.l.google.com,ytimg.l.google.com";
    internal const string Rutracker = "rutracker.org";
    internal static string[] Arguments(int endpointPort)
    {
        var google = "--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=bin/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls=bin/tls_clienthello_www_google_com.bin";
        var web = "--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=bin/tls_clienthello_4pda_to.bin --dpi-desync-fake-tls=bin/tls_clienthello_4pda_to.bin";
        string[] groups =
        [
            "--filter-udp=443 --hostlist-domains=" + Youtube + "," + Rutracker + " --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=bin/quic_initial_www_google_com.bin --new",
            "--filter-tcp=443 --hostlist-domains=" + Youtube + " --ip-id=zero " + google + " --new",
            "--filter-tcp=80 --hostlist-domains=" + Youtube + "," + Rutracker + " --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new",
            "--filter-tcp=443 --hostlist-domains=" + Rutracker + " " + web
        ];
        return groups.SelectMany(g => g.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Prepend("--wf-raw=" + CaptureFilter(endpointPort)).ToArray();
    }
    internal static string CaptureFilter(int endpointPort) =>
        "!impostor and !loopback and ((outbound and (!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength > 0) and " +
        "((tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)) or (udp and udp.DstPort == 443))) or " +
        "(inbound and tcp and (tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin) and (tcp.SrcPort == 80 or tcp.SrcPort == 443))) and (" + ExclusionFilter(endpointPort) + ") and (" + RemotePublicFilter() + ")";
    internal static string ExclusionFilter(int endpointPort)
    {
        if (endpointPort is < 1 or > 65535) throw new InvalidDataException("Некорректный порт VPN.");
        string Family(bool v6)
        {
            var family = v6 ? "ipv6" : "ip";
            var terms = MetaRanges().Where(r => (r.First.GetAddressBytes().Length == 16) == v6)
                .Select(r => "(" + Outside(r, family + ".SrcAddr") + " and " + Outside(r, family + ".DstAddr") + ")").ToArray();
            return "(" + family + " and " + JoinAnd(terms) + ")";
        }
        // Both inner Meta directions and encrypted UDP transport stay outside the packet filter.
        // Port exclusion survives endpoint DNS changes; if endpoint=443, companion QUIC is excluded too.
        // Pinned WinDivert accepts negated fields, not negated parenthesized expressions.
        var filter = "(" + Family(false) + " or " + Family(true) + $") and (!udp or (udp.SrcPort != {endpointPort} and udp.DstPort != {endpointPort}))";
        if (filter.Length > 12000) throw new InvalidDataException("Список исключений FIX слишком большой.");
        return filter;
    }
    private static string Outside(string prefix, string field)
        => Outside(Bounds(prefix), field);
    private static string Outside((IPAddress First, IPAddress Last) range, string field)
        => $"({field} < {range.First} or {field} > {range.Last})";
    private static (IPAddress First, IPAddress Last) Bounds(string prefix)
    {
        var range = IPNetwork.Parse(prefix); var upper = range.BaseAddress.GetAddressBytes();
        for (var bit = range.PrefixLength; bit < upper.Length * 8; bit++) upper[bit / 8] |= (byte)(1 << (7 - bit % 8));
        return (range.BaseAddress, new IPAddress(upper));
    }
    // Merge only touching ranges, never gaps or broader CIDRs. This preserves the exact IP set
    // while staying below the pinned driver's compiled-expression instruction limit.
    internal static (IPAddress First, IPAddress Last)[] MetaRanges()
    {
        static BigInteger Number(IPAddress ip) => new(ip.GetAddressBytes(), isUnsigned: true, isBigEndian: true);
        var merged = new List<(IPAddress First, IPAddress Last)>();
        foreach (var next in MetaVpnPolicy.Prefixes.Select(Bounds).OrderBy(r => r.First.GetAddressBytes().Length).ThenBy(r => Number(r.First)))
        {
            if (merged.Count > 0 && merged[^1].Last.GetAddressBytes().Length == next.First.GetAddressBytes().Length && Number(merged[^1].Last) + 1 == Number(next.First))
                merged[^1] = (merged[^1].First, next.Last);
            else merged.Add(next);
        }
        return merged.ToArray();
    }
    private static string JoinAnd(string[] values) => values.Length == 1 ? values[0] :
        "(" + JoinAnd(values[..(values.Length / 2)]) + " and " + JoinAnd(values[(values.Length / 2)..]) + ")";
    private static string RemotePublicFilter()
    {
        string Remote(string field) => "((ip and " + JoinAnd(new[] { "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3" }.Select(p => Outside(p, "ip." + field)).ToArray()) + ") or (ipv6 and " +
            JoinAnd(new[] { "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8" }.Select(p => Outside(p, "ipv6." + field)).ToArray()) + "))";
        // Only the remote side is checked: a private LAN address on this PC is normal.
        return "((outbound and " + Remote("DstAddr") + ") or (inbound and " + Remote("SrcAddr") + "))";
    }
    internal static string[] Resources =>
    [
        "bin/winws.exe", "bin/WinDivert.dll", "bin/WinDivert64.sys", "bin/cygwin1.dll",
        "bin/quic_initial_www_google_com.bin", "bin/tls_clienthello_www_google_com.bin", "bin/tls_clienthello_4pda_to.bin"
    ];
}
