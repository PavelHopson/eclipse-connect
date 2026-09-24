namespace EclipseConnect.Core;

public sealed record FixProfile(string Id, string Name, string Purpose, string[] Targets);

// Audited translations of local presets. No BAT text, executable names or arbitrary arguments are evaluated.
public static class FixCatalog
{
    public static readonly FixProfile[] All =
    [
        new("ultimate", "UltimateFix v9.2", "Ваш основной профиль. YouTube, Discord и общие списки.", ["youtube", "discord"]),
        new("general", "Общий / multisplit", "Альтернативная стратегия из general.bat.", ["youtube", "discord"]),
        new("youtube", "YouTube", "Только списки YouTube и Google.", ["youtube"]),
        new("discord", "Discord", "Сайт, медиасерверы и голосовые соединения Discord.", ["discord"])
    ];
    public static FixProfile Get(string id) => All.SingleOrDefault(p => p.Id == id)
        ?? throw new InvalidDataException("Этот профиль ещё не прошёл проверку Connect.");
    public static FixProfile[] Candidates(string target) => target switch
    {
        "youtube" => [Get("youtube"), Get("ultimate"), Get("general")],
        "discord" => [Get("discord"), Get("ultimate"), Get("general")],
        "all" => [Get("ultimate"), Get("general")],
        _ => throw new InvalidDataException("Выберите YouTube, Discord или оба сервиса.")
    };
    public static string[] Arguments(string id, bool gaming)
    {
        Get(id);
        if (id == "ultimate") return FixProfiles.Arguments(gaming);
        var google = "--ip-id=zero --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=bin/tls_clienthello_www_google_com.bin";
        var split = "--dpi-desync=multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=bin/tls_clienthello_4pda_to.bin";
        var quic = "--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=bin/quic_initial_www_google_com.bin";
        var voice = "--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=bin/quic_initial_www_google_com.bin --dpi-desync-fake-stun=bin/quic_initial_www_google_com.bin --dpi-desync-repeats=6";
        var ports = "443,2053,2083,2087,2096,8443";
        var range = gaming ? "1024-65535" : "12";
        string[] groups = id switch
        {
            "youtube" => ["--wf-tcp=80,443 --wf-udp=443",
                "--filter-udp=443 --hostlist=lists/list-youtube.txt " + quic + " --new",
                "--filter-udp=443 --hostlist=lists/list-google.txt " + quic + " --new",
                "--filter-tcp=443 --hostlist=lists/list-google.txt " + google + " --new",
                "--filter-tcp=80,443 --hostlist=lists/list-youtube.txt " + google.Replace("--ip-id=zero ", "")],
            "discord" => [$"--wf-tcp={ports} --wf-udp=443,19294-19344,50000-50100",
                "--filter-udp=443 --hostlist=lists/list-discord.txt " + quic + " --new", voice + " --new",
                "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media " + split + " --new",
                "--filter-tcp=443 --hostlist=lists/list-discord.txt " + split + " --new",
                "--filter-udp=443 --ipset=lists/ipset-discord.txt " + quic + " --new",
                "--filter-tcp=443 --ipset=lists/ipset-discord.txt " + split + " --new",
                "--filter-udp=50000-50100 --ipset=lists/ipset-discord.txt --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=bin/quic_initial_www_google_com.bin --dpi-desync-cutoff=n2"],
            _ => [$"--wf-tcp=80,{ports},{range} --wf-udp=443,19294-19344,50000-50100,{range}",
                "--filter-udp=443 --hostlist=lists/list-ultimate.txt --hostlist-exclude=lists/list-exclude.txt " + quic + " --new", voice + " --new",
                "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media " + split + " --new",
                "--filter-tcp=443 --hostlist=lists/list-google.txt " + google + " --new",
                "--filter-tcp=80,443 --hostlist=lists/list-ultimate.txt --hostlist-exclude=lists/list-exclude.txt " + split + " --new",
                "--filter-udp=443 --ipset=lists/ipset-all.txt --hostlist-exclude=lists/list-exclude.txt " + quic + " --new",
                $"--filter-tcp=80,443,{range} --ipset=lists/ipset-all.txt --hostlist-exclude=lists/list-exclude.txt " + split + " --new",
                $"--filter-udp={range} --ipset=lists/ipset-all.txt --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=12 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=bin/quic_initial_www_google_com.bin --dpi-desync-cutoff=n2"]
        };
        return TelegramFixCompatibility.AddExclusions(groups.SelectMany(g => g.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToArray());
    }
    public static string[] Resources(string id, bool gaming) => new[] { "bin/winws.exe", "bin/WinDivert.dll", "bin/WinDivert64.sys", "bin/cygwin1.dll" }
        .Concat(Arguments(id, gaming).Select(a => a.Contains('=') ? a[(a.IndexOf('=') + 1)..] : "")
            .Where(v => v.StartsWith("bin/") || v.StartsWith("lists/"))).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}
