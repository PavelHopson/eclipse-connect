using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EclipseConnect.Core;

public sealed class Updates : IDisposable
{
    private readonly HttpClient client;
    private readonly Storage storage;
    public Updates(Storage storage, HttpMessageHandler? transport = null)
    {
        this.storage = storage;
        client = new(transport ?? new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("EclipseConnect/0.1");
    }
    public async Task<ReleaseInfo> Check(ComponentSpec spec, CancellationToken ct)
    {
        if (!Catalog.All.Contains(spec)) throw new InvalidDataException("Источник не разрешён.");
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{spec.Repository}/releases/latest");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new InvalidDataException("У источника нет доступного latest-релиза. Это не означает, что компонент обновлён.");
        if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            throw new InvalidDataException("GitHub ограничил запросы. Повторите позже; текущая версия не менялась.");
        response.EnsureSuccessStatusCode();
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct); bounded.CancelAfter(TimeSpan.FromSeconds(20));
        await using var stream = await response.Content.ReadAsStreamAsync(bounded.Token);
        using var memory = new MemoryStream();
        await CopyBounded(stream, memory, 2 * 1024 * 1024, null, bounded.Token);
        return ReleasePolicy.Parse(Encoding.UTF8.GetString(memory.ToArray()), spec);
    }
    public static bool AllowedRedirect(Uri uri) => uri.Scheme == "https" && uri.IsDefaultPort &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment) &&
        new[] { "release-assets.githubusercontent.com", "objects.githubusercontent.com" }.Contains(uri.Host);

    public async Task<PreparedArtifact> Prepare(ComponentSpec spec, ReleaseInfo release, ReleaseAsset asset,
        IProgress<double>? progress, CancellationToken ct)
    {
        if (spec != Catalog.Telegram || asset.Name != spec.AssetName || !release.Assets.Contains(asset))
            throw new InvalidDataException("Для этого компонента автоматическая подготовка не поддерживается.");
        ReleasePolicy.ParseVersion(release.Tag);
        if (asset.Size <= 0 || asset.Size > 256 * 1024 * 1024 ||
            asset.DownloadUrl != new Uri($"https://github.com/{spec.Repository}/releases/download/{release.Tag}/{spec.AssetName}"))
            throw new InvalidDataException("Неподтверждённый файл релиза.");
        var expected = ReleasePolicy.Digest(asset.Digest);
        var directory = storage.Resolve($"versions/{spec.Id}/{release.Tag}/{expected[..12]}");
        Directory.CreateDirectory(directory);
        var destination = Path.Combine(directory, spec.AssetName);
        var partial = destination + "." + Guid.NewGuid().ToString("N") + ".partial";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            var uri = asset.DownloadUrl;
            HttpResponseMessage? response = null;
            try
            {
                for (var redirects = 0; redirects <= 3; redirects++)
                {
                    response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                    if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308)) break;
                    var next = response.Headers.Location;
                    response.Dispose(); response = null;
                    if (next == null || !next.IsAbsoluteUri || !AllowedRedirect(next) || redirects == 3)
                        throw new InvalidDataException("Перенаправление загрузки не разрешено.");
                    uri = next;
                }
                if (response == null) throw new InvalidDataException("Ответ загрузки отсутствует.");
                response.EnsureSuccessStatusCode();
                if (response.Content.Headers.ContentLength is long length && length != asset.Size)
                    throw new InvalidDataException("Размер файла не совпадает с релизом.");
                await using (var input = await response.Content.ReadAsStreamAsync(timeout.Token))
                await using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, true))
                {
                    var total = await CopyBounded(input, output, asset.Size, progress, timeout.Token);
                    if (total != asset.Size) throw new InvalidDataException("Файл загружен не полностью.");
                    output.Flush(true);
                }
            }
            finally { response?.Dispose(); }
            await using (var file = File.OpenRead(partial))
            {
                var actual = Convert.ToHexString(await SHA256.HashDataAsync(file, timeout.Token)).ToLowerInvariant();
                if (actual != expected) throw new InvalidDataException("SHA-256 не совпадает. Файл не будет использован.");
            }
            Storage.AssertNoLinks(destination);
            File.Move(partial, destination, true);
            var prepared = new PreparedArtifact(spec.Id, release.Tag, destination, expected, DateTimeOffset.Now);
            storage.AtomicJson($"prepared-{spec.Id}.json", prepared);
            storage.Log("Подготовка обновления", $"{spec.Name} {release.Tag}: размер и SHA-256 совпали. Запуск не выполнялся.");
            return prepared;
        }
        finally { if (File.Exists(partial)) File.Delete(partial); }
    }
    public PreparedArtifact? ReadPrepared(ComponentSpec spec)
    {
        var path = storage.Resolve($"prepared-{spec.Id}.json");
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 16384) throw new InvalidDataException("Манифест слишком большой.");
        var artifact = JsonSerializer.Deserialize<PreparedArtifact>(File.ReadAllText(path));
        if (artifact == null || artifact.ComponentId != spec.Id) throw new InvalidDataException("Повреждённый манифест.");
        ReleasePolicy.ParseVersion(artifact.Tag); ReleasePolicy.Digest("sha256:" + artifact.Sha256);
        var expected = storage.Resolve($"versions/{spec.Id}/{artifact.Tag}/{artifact.Sha256[..12]}/{spec.AssetName}");
        if (!string.Equals(expected, artifact.Path, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Путь манифеста не совпадает.");
        return artifact;
    }
    public static async Task<long> CopyBounded(Stream input, Stream output, long limit, IProgress<double>? progress, CancellationToken ct)
    {
        var buffer = new byte[65536]; long total = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer, ct); if (read == 0) break;
            total += read; if (total > limit) throw new InvalidDataException("Превышен разрешённый размер ответа.");
            await output.WriteAsync(buffer.AsMemory(0, read), ct);
            progress?.Report(total * 100d / limit);
        }
        return total;
    }
    public void Dispose() => client.Dispose();
}
