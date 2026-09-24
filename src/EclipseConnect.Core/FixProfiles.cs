using System.Security.Cryptography;

namespace EclipseConnect.Core;

public sealed record ProfileFile(string RelativePath, long Bytes, string Sha256);
public sealed record FixPlan(string Name, DateTimeOffset CreatedAt, string EngineVersion, bool GamingMode,
    IReadOnlyList<ProfileFile> Files, IReadOnlyList<string> Arguments, IReadOnlyList<string> Warnings);

public static class FixProfiles
{
    public const string ProfileName = "UltimateFix v9.2";
    public static readonly string[] RequiredFiles = ["bin/winws.exe", "bin/WinDivert.dll", "bin/WinDivert64.sys",
        "bin/quic_initial_www_google_com.bin", "bin/tls_clienthello_4pda_to.bin", "bin/tls_clienthello_www_google_com.bin",
        "lists/list-ultimate.txt", "lists/list-google.txt", "lists/list-exclude.txt", "lists/ipset-exclude.txt",
        "lists/ipset-discord.txt", "lists/ipset-cloudflare.txt", TelegramFixCompatibility.ResourcePath];
    private static readonly Dictionary<string, string> EngineHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["bin/winws.exe"] = "31d68a175abebab19f7f39bf6d0845ec5c18ab653eeeea6ee830b22d799b7e55",
        ["bin/WinDivert.dll"] = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
        ["bin/WinDivert64.sys"] = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
    };
    // Declarative reconstruction of the user-selected profile, never a BAT parser/executor.
    // Inspection and activation share these fixed arguments; no source collection is modified.
    public static string[] Arguments(bool gaming)
    {
        var range = gaming ? "1024-65535" : "12";
        return TelegramFixCompatibility.AddExclusions(new[]
        {
            $"--wf-tcp=80,443,2053,2083,2087,2096,8443,{range} --wf-udp=443,19294-19344,50000-65535,{range}",
            "--filter-udp=443 --hostlist=lists/list-ultimate.txt --hostlist-exclude=lists/list-exclude.txt --ipset-exclude=lists/ipset-exclude.txt --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=bin/quic_initial_www_google_com.bin --new",
            "--filter-udp=19294-19344,50000-65535 --ipset=lists/ipset-discord.txt --dpi-desync=fake --dpi-desync-fake-discord=bin/quic_initial_www_google_com.bin --dpi-desync-fake-stun=bin/quic_initial_www_google_com.bin --dpi-desync-any-protocol --dpi-desync-cutoff=d3 --dpi-desync-repeats=6 --new",
            "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=bin/tls_clienthello_4pda_to.bin --dpi-desync-fake-tls=bin/tls_clienthello_4pda_to.bin --new",
            "--filter-tcp=443 --hostlist=lists/list-google.txt --ip-id=zero --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=bin/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls=bin/tls_clienthello_www_google_com.bin --new",
            "--filter-tcp=80 --hostlist=lists/list-ultimate.txt --hostlist-exclude=lists/list-exclude.txt --ipset-exclude=lists/ipset-exclude.txt --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new",
            "--filter-tcp=443 --hostlist=lists/list-ultimate.txt --hostlist-exclude=lists/list-exclude.txt --ipset-exclude=lists/ipset-exclude.txt --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=bin/tls_clienthello_4pda_to.bin --dpi-desync-fake-tls=bin/tls_clienthello_4pda_to.bin --new",
            "--filter-udp=443 --ipset=lists/ipset-cloudflare.txt --hostlist-exclude=lists/list-exclude.txt --ipset-exclude=lists/ipset-exclude.txt --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic=bin/quic_initial_www_google_com.bin --new",
            "--filter-tcp=80 --ipset=lists/ipset-cloudflare.txt --hostlist-exclude=lists/list-exclude.txt --ipset-exclude=lists/ipset-exclude.txt --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new",
            $"--filter-tcp=443,{range} --ipset=lists/ipset-cloudflare.txt --hostlist-exclude=lists/list-exclude.txt --ipset-exclude=lists/ipset-exclude.txt --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig,badseq --new",
            $"--filter-udp={range} --ipset=lists/ipset-cloudflare.txt --ipset-exclude=lists/ipset-exclude.txt --dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-repeats=10 --dpi-desync-any-protocol=1 --dpi-desync-fake-unknown-udp=bin/quic_initial_www_google_com.bin --dpi-desync-cutoff=n2"
        }.SelectMany(group => group.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToArray());
    }
    public static async Task<FixPlan> Inspect(string enginePath, CancellationToken ct)
    {
        if (!Path.GetFileName(enginePath).Equals("winws.exe", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Для FIX требуется bin/winws.exe.");
        var root = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(enginePath))) ?? throw new InvalidDataException("Папка FIX не определена.");
        Storage.AssertNoLinks(root);
        var files = new List<ProfileFile>();
        foreach (var relative in RequiredFiles)
        {
            if (relative == TelegramFixCompatibility.ResourcePath)
            {
                await using var generated = TelegramFixCompatibility.OpenResource();
                var generatedHash = Convert.ToHexString(await SHA256.HashDataAsync(generated, ct)).ToLowerInvariant();
                files.Add(new(relative, generated.Length, generatedHash));
                continue;
            }
            var path = Path.Combine(root, relative); Storage.AssertNoLinks(path);
            var info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException("Для профиля не хватает " + relative);
            if (info.Length > 32 * 1024 * 1024) throw new InvalidDataException("Файл профиля слишком большой: " + relative);
            await using var file = File.OpenRead(path);
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(file, ct)).ToLowerInvariant();
            if (EngineHashes.TryGetValue(relative, out var expected) && expected != hash) throw new InvalidDataException("Не подтверждена версия " + relative + ". Автозапуск запрещён.");
            files.Add(new(relative, info.Length, hash));
        }
        var gaming = File.Exists(Path.Combine(root, "bin/gmode.flag"));
        return new(ProfileName, DateTimeOffset.Now, "v72.2", gaming, files, Arguments(gaming),
            ["BAT дополнительно включает глобальный TCP timestamps. Connect эту настройку не меняет.",
             "WinDivert работает с драйвером и требует отдельной проверки перед активацией.",
             "Профиль охватывает не только YouTube. Списки не публикуются и не передаются в отчёт.",
             "Это проверка файлов и экспорт параметров, а не доказательство работоспособности обхода."]);
    }
}
