using System.Text.Json;
using System.Text.RegularExpressions;

namespace EclipseConnect.Core;

public sealed record ComponentSpec(string Id, string Name, string Repository, string AssetName, string Purpose);
public sealed record InstalledComponent(ComponentSpec Spec, string Path, string Hash, string Version, int ProcessCount)
{
    public bool Exists => !string.IsNullOrEmpty(Hash);
    public string State => ProcessCount > 0 ? Spec == Catalog.Fix ? "Обнаружен процесс FIX" : "Работает отдельно" : !Exists ? "Не найден" : "Не запущен";
}
public sealed record ReleaseAsset(string Name, long Size, string Digest, Uri DownloadUrl);
public sealed record ReleaseInfo(string Tag, DateTimeOffset PublishedAt, Uri Page, IReadOnlyList<ReleaseAsset> Assets);
public enum DiagnosticCode { Unknown, HttpsResponse, BrowserChallenge, HttpDenied, HttpAuthentication, HttpRateLimited, HttpServerError, DnsFailure, ConnectionFailure, TlsFailure, ProxyFailure, Timeout, IncompleteResponse }
public sealed record DiagnosticResult(string Target, string State, string Detail, DateTimeOffset CheckedAt,
    DiagnosticCode Code = DiagnosticCode.Unknown, int? HttpStatus = null);
public sealed record JournalEntry(DateTimeOffset Time, string Action, string Result);
public sealed record PreparedArtifact(string ComponentId, string Tag, string Path, string Sha256, DateTimeOffset VerifiedAt);

public static class Catalog
{
    public static readonly ComponentSpec Telegram = new("telegram", "Telegram", "Flowseal/tg-ws-proxy", "TgWsProxy_windows.exe", "Локальный MTProto-прокси для Telegram Desktop");
    public static readonly ComponentSpec Fix = new("fix", "FIX / zapret", "bol-van/zapret", "", "Движок winws и профиль UltimateFix v9.2");
    public static readonly ComponentSpec[] All = [Telegram, Fix];
    // Audited release identities, not a claim that all upstream code is secure.
    public static readonly IReadOnlyDictionary<string, string> KnownHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["7283ce9b0e284877c1028ec7b3aa508a2e16ce3085f8613a20476d5937d1094a"] = "v1.10.1",
        ["17be7f17b2e19920935988822d66f14dd2b727372ff565a28ff64b757ff4d898"] = "v1.10.2",
        ["31d68a175abebab19f7f39bf6d0845ec5c18ab653eeeea6ee830b22d799b7e55"] = "v72.2"
    };
    public static string KnownVersion(ComponentSpec spec, string hash) =>
        KnownHashes.TryGetValue(hash, out var version) &&
        ((spec.Id == Telegram.Id && version.StartsWith("v1.")) || (spec.Id == Fix.Id && version == "v72.2"))
            ? version : "Не подтверждена";
}

public static class ReleasePolicy
{
    private static readonly Regex TagPattern = new(@"^v?\d+(\.\d+){1,3}$", RegexOptions.CultureInvariant);
    public static Version ParseVersion(string tag)
    {
        if (!TagPattern.IsMatch(tag)) throw new InvalidDataException("Некорректная стабильная версия релиза.");
        return Version.Parse(tag.TrimStart('v'));
    }
    public static int Compare(string a, string b)
    {
        var x = ParseVersion(a); var y = ParseVersion(b);
        return new Version(x.Major, x.Minor, Math.Max(x.Build, 0), Math.Max(x.Revision, 0))
            .CompareTo(new Version(y.Major, y.Minor, Math.Max(y.Build, 0), Math.Max(y.Revision, 0)));
    }
    public static string Digest(string value)
    {
        if (!Regex.IsMatch(value, "^sha256:[0-9a-fA-F]{64}$")) throw new InvalidDataException("GitHub не предоставил корректную SHA-256. Автозагрузка запрещена.");
        return value[7..].ToLowerInvariant();
    }
    public static ReleaseInfo Parse(string json, ComponentSpec spec)
    {
        if (!Catalog.All.Any(c => c.Id == spec.Id && c.Repository == spec.Repository)) throw new InvalidDataException("Неизвестный источник обновлений.");
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.GetProperty("prerelease").GetBoolean() || root.GetProperty("draft").GetBoolean()) throw new InvalidDataException("Предварительные релизы отключены.");
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        ParseVersion(tag);
        var page = new Uri($"https://github.com/{spec.Repository}/releases/tag/{tag}");
        var assets = new List<ReleaseAsset>();
        foreach (var item in root.GetProperty("assets").EnumerateArray())
        {
            var name = item.GetProperty("name").GetString() ?? "";
            if (!Regex.IsMatch(name, @"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,150}$") || name.Contains("..")) continue;
            var url = new Uri(item.GetProperty("browser_download_url").GetString() ?? "");
            var expected = new Uri($"https://github.com/{spec.Repository}/releases/download/{tag}/{name}");
            if (url != expected || !string.IsNullOrEmpty(url.UserInfo) || !string.IsNullOrEmpty(url.Query)) continue;
            var size = item.GetProperty("size").GetInt64();
            if (size <= 0 || size > 256 * 1024 * 1024) continue;
            var digest = item.TryGetProperty("digest", out var d) ? d.GetString() ?? "" : "";
            assets.Add(new(name, size, digest, url));
        }
        return new(tag, root.GetProperty("published_at").GetDateTimeOffset(), page, assets);
    }
}

public static class Redactor
{
    public static string Sanitize(string text)
    {
        // VPN import/driver failures must never expose keys or signature packet contents.
        text = Regex.Replace(text, @"(?im)^\s*(PrivateKey|PresharedKey|I[1-5])\s*=[^\r\n]*", "$1 = [скрыто]");
        text = Regex.Replace(text, "(?i)(\"(?:private[_-]?key|preshared[_-]?key|I[1-5])\"\\s*:\\s*)\"[^\"]*\"", "$1\"[скрыто]\"");
        text = Regex.Replace(text, @"(?i)\b(private[_-]?key|preshared[_-]?key)(\s*[=:]\s*)([^\s&;,]+)", "$1$2[скрыто]");
        // Do not preserve signed download URLs or quoted JSON credential values in errors.
        text = Regex.Replace(text, "(?i)(https?://[^\\s?]+)\\?[^\\s]+", "$1?[параметры скрыты]");
        text = Regex.Replace(text, "(?i)(\"(?:secret|token|password|authorization|cookie|api[_-]?key)\"\\s*:\\s*)\"[^\"]*\"", "$1\"[скрыто]\"");
        text = Regex.Replace(text, @"(?i)(secret|token|password|authorization|cookie|api[_-]?key)(\s*[=:]\s*)([^\s&;,]+)", "$1$2[скрыто]");
        text = Regex.Replace(text, @"(?i)tg://[^\s]+", "[ссылка Telegram скрыта]");
        text = Regex.Replace(text, @"(?i)Bearer\s+\S+", "Bearer [скрыто]");
        text = Regex.Replace(text, @"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]");
        return text.Length > 1200 ? text[..1200] : text;
    }
}
