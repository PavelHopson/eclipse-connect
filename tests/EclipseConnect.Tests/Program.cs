using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EclipseConnect.Core;

// Live mode is opt-in and separate from the default offline regression suite.
if (args.Length == 1 && args[0] == "--access-readonly")
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
    var probes = await Task.WhenAll(new[] { "instagram", "whatsapp", "whatsapp-static", "youtube", "rutracker", "chatgpt" }.Select(async id =>
    {
        var service = ServiceCatalog.Get(id);
        var result = await Diagnostics.Probe(new Uri(service.Url), deadline.Token);
        return new { Service = service.Name, result.State, Code = result.Code.ToString(), result.HttpStatus, result.Detail, result.CheckedAt };
    }));
    Console.WriteLine(JsonSerializer.Serialize(probes, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine("READONLY: direct HTTPS only; no login, VPN start, routing, DNS or proxy changes. HTTP reachability is not application acceptance.");
    return 0;
}
if (args.Length == 2 && args[0] == "--awg-profile-readonly")
{
    try
    {
        var inspected = AwgProfile.ReadLocalFile(args[1]);
        _ = MetaVpnPolicy.ServiceConfiguration(inspected, DateTimeOffset.UtcNow);
        Console.WriteLine($"AWG PROFILE VALID: MTU={inspected.Mtu}; signature packets={inspected.SignaturePackets}; no import or execution");
        return 0;
    }
    catch (InvalidDataException error) { Console.Error.WriteLine(error.Message); return 2; }
    catch { Console.Error.WriteLine("AWG profile could not be read; details withheld to protect credentials."); return 2; }
}
if (args.Length == 3 && args[0] == "--awg-import-local" && args[2] == "--confirm" && OperatingSystem.IsWindows())
{
    try
    {
        var imported = AwgProfile.ReadLocalFile(args[1]);
        _ = MetaVpnPolicy.ServiceConfiguration(imported, DateTimeOffset.UtcNow);
        var local = new Storage(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EclipseConnect"));
        var store = new AwgProfileStore(local);
        store.Save(imported, false); // Never overwrite an existing profile from a command-line import.
        if (store.Load()?.Revision != imported.Revision) throw new InvalidDataException();
        Console.WriteLine("AWG META PROFILE IMPORTED: DPAPI CurrentUser round-trip verified; source unchanged; no VPN execution.");
        return 0;
    }
    catch { Console.Error.WriteLine("AWG import did not complete; an existing profile is never replaced. Details withheld to protect credentials."); return 2; }
}
if (args.Length > 0 && args[0] == "--network-mode-child") return await NetworkModeTests.Child(args);
if (args.Contains("--job-child")) { await Task.Delay(TimeSpan.FromSeconds(45)); return 0; }
if (args.Contains("--job-probe")) return JobProbe.Run();
if (args.Contains("--live-telegram")) return await LiveTelegramTest.Run(args);
if (args.Contains("--live-diagnostics")) return await LiveTelegramTest.ProbeNetwork();
if (args.Contains("--fix-dry-run") && OperatingSystem.IsWindows()) return await FixDryRun.Run();
if (args.Length == 2 && args[0] == "--combined-filter-offline" && OperatingSystem.IsWindows()) return await CombinedFilterOffline.Run(args[1]);
if (args.Length == 2 && args[0] == "--awg-engine-readonly" && OperatingSystem.IsWindows())
{
    var locks = WindowsAwgEngine.VerifyAndLock(Path.GetFullPath(args[1]));
    try { Console.WriteLine("AWG ENGINE VERIFIED: " + WindowsAwgEngine.Version + "; files=" + locks.Count + "; no execution"); }
    finally { foreach (var file in locks) file.Dispose(); }
    return 0;
}

var passed = 0; var failed = 0;
void Test(string name, Action test)
{ try { test(); passed++; Console.WriteLine("PASS " + name); } catch (Exception e) { failed++; Console.WriteLine("FAIL " + name + ": " + e.Message); } }
async Task AsyncTest(string name, Func<Task> test)
{ try { await test(); passed++; Console.WriteLine("PASS " + name); } catch (Exception e) { failed++; Console.WriteLine("FAIL " + name + ": " + e.Message); } }
void Assert(bool valid) { if (!valid) throw new Exception("Assertion failed"); }
void Reject(Action action) { var rejected = false; try { action(); } catch (Exception) { rejected = true; } Assert(rejected); }
async Task RejectAsync(Func<Task> action) { var rejected = false; try { await action(); } catch (Exception) { rejected = true; } Assert(rejected); }
var body = Encoding.UTF8.GetBytes("local-test-payload-never-executed");
var digest = "sha256:" + Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
var root = Path.Combine(Path.GetTempPath(), "eclipse-connect-tests-" + Guid.NewGuid().ToString("N"));
var storage = new Storage(root);
string ReleaseJson(string tag = "v1.10.1", bool preview = false, string? assetName = null, string? url = null, string? hash = null, long? size = null) => JsonSerializer.Serialize(new
{
    tag_name = tag, prerelease = preview, draft = false, published_at = "2026-09-04T12:00:00Z",
    assets = new[] { new { name = assetName ?? "TgWsProxy_windows.exe", size = size ?? body.Length, digest = hash ?? digest,
        browser_download_url = url ?? "https://github.com/Flowseal/tg-ws-proxy/releases/download/v1.10.1/TgWsProxy_windows.exe" } }
});
var release = ReleasePolicy.Parse(ReleaseJson(), Catalog.Telegram);
var asset = release.Assets.Single();
Test("numeric semver", () => Assert(ReleasePolicy.Compare("v1.10.1", "v1.9.9") > 0));
Test("normalized semver", () => Assert(ReleasePolicy.Compare("v1.10", "1.10.0") == 0));
Test("reject traversal tag", () => Reject(() => ReleasePolicy.ParseVersion("../1.2")));
Test("reject prerelease tag", () => Reject(() => ReleasePolicy.ParseVersion("v1.2-beta")));
Test("reject prerelease payload", () => Reject(() => ReleasePolicy.Parse(ReleaseJson(preview: true), Catalog.Telegram)));
Test("reject malformed JSON", () => Reject(() => ReleasePolicy.Parse("{", Catalog.Telegram)));
Test("reject untrusted repository", () => Reject(() => ReleasePolicy.Parse(ReleaseJson(), Catalog.Telegram with { Repository = "evil/repo" })));
Test("reject cross-repository asset", () => Assert(ReleasePolicy.Parse(ReleaseJson(url: "https://github.com/evil/repo/file.exe"), Catalog.Telegram).Assets.Count == 0));
Test("reject asset traversal", () => Assert(ReleasePolicy.Parse(ReleaseJson(assetName: "../evil.exe"), Catalog.Telegram).Assets.Count == 0));
Test("reject asset oversize", () => Assert(ReleasePolicy.Parse(ReleaseJson(size: 300 * 1024 * 1024), Catalog.Telegram).Assets.Count == 0));
Test("reject empty digest", () => Reject(() => ReleasePolicy.Digest("")));
Test("reject short digest", () => Reject(() => ReleasePolicy.Digest("sha256:abcd")));
Test("verified manifest accepted", () => Assert(release.Tag == "v1.10.1" && asset.Size == body.Length));
Test("identity is per component", () => Assert(Catalog.KnownVersion(Catalog.Fix, Catalog.KnownHashes.First().Key) == "Не подтверждена"));
Test("known Telegram bytes", () => Assert(Catalog.KnownVersion(Catalog.Telegram, Catalog.KnownHashes.First().Key) == "v1.10.1"));
Test("reject storage traversal", () => Reject(() => storage.Resolve("../other/settings.json")));
Test("reject absolute storage path", () => Reject(() => storage.Resolve(Path.GetTempPath())));
Test("settings round trip", () => { storage.SaveSettings(new() { Theme = "Dark" }); Assert(storage.LoadSettings().Theme == "Dark"); });
Test("redact token", () => Assert(!Redactor.Sanitize("token=abcdef").Contains("abcdef")));
Test("redact proxy link", () => Assert(!Redactor.Sanitize("tg://proxy?server=test&secret=abcdef").Contains("abcdef")));
Test("redact bearer", () => Assert(!Redactor.Sanitize("Bearer abcdef").Contains("abcdef")));
Test("redact quoted JSON token", () => Assert(!Redactor.Sanitize("{\"token\": \"super secret value\"}").Contains("super secret")));
Test("redact signed URL query", () => Assert(!Redactor.Sanitize("https://release-assets.githubusercontent.com/file?sig=abcdef").Contains("abcdef")));
Test("redact IP", () => Assert(!Redactor.Sanitize("source 192.168.12.50").Contains("192.168")));
Test("bounded journal", () => { for (var i=0;i<215;i++) storage.Log("test", "ok"); Assert(storage.ReadJournal().Count == 200); });
Test("HTTP 403 challenge is not failure of DNS", () => Assert(Diagnostics.Classify("test", 403, "challenge", "").State == "Проверка браузера"));
Test("site rejection classified", () => Assert(Diagnostics.Classify("test", 403, null, "Unable to load site").State == "Отказ сайта"));
Test("HTTP 200 is not full app validation", () => Assert(Diagnostics.Classify("test", 200, null, "").Detail.Contains("не проверялись")));
Test("HTTP 500 server category", () => Assert(Diagnostics.Classify("test", 500, null, "").Code == DiagnosticCode.HttpServerError));
Test("launcher needs confirmation", () => Assert(Launcher.BlockReason(false, false, false, true) != null));
Test("launcher refuses external", () => Assert(Launcher.BlockReason(true, true, false, true) != null));
Test("launcher refuses busy port", () => Assert(Launcher.BlockReason(true, false, true, true) != null));
Test("launcher refuses unknown hash", () => Assert(Launcher.BlockReason(true, false, false, false) != null));
Test("launcher preflight pass", () => Assert(Launcher.BlockReason(true, false, false, true) == null));
Test("allow official CDN", () => Assert(Updates.AllowedRedirect(new("https://release-assets.githubusercontent.com/github-production-release-asset/1/a"))));
Test("reject CDN lookalike", () => Assert(!Updates.AllowedRedirect(new("https://release-assets.githubusercontent.com.attacker.test/file"))));
Test("reject HTTP CDN", () => Assert(!Updates.AllowedRedirect(new("http://objects.githubusercontent.com/file"))));
Test("reject CDN custom port", () => Assert(!Updates.AllowedRedirect(new("https://objects.githubusercontent.com:444/file"))));
Test("reject CDN credentials", () => Assert(!Updates.AllowedRedirect(new("https://user@objects.githubusercontent.com/file"))));
await AsyncTest("bounded copy overrun", () => RejectAsync(() => Updates.CopyBounded(new MemoryStream(body), new MemoryStream(), 3, null, default)));
await AsyncTest("HTTPS target allowlist", () => RejectAsync(() => Diagnostics.Probe(new Uri("https://127.0.0.1/"), default)));
await AsyncTest("prepare verified artifact without execution", async () =>
{
    using var updater = new Updates(storage, new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }));
    var result = await updater.Prepare(Catalog.Telegram, release, asset, null, default);
    Assert(File.Exists(result.Path) && File.ReadAllBytes(result.Path).SequenceEqual(body)); Assert(updater.ReadPrepared(Catalog.Telegram)?.Sha256 == result.Sha256);
});
await AsyncTest("wrong hash leaves no manifest", async () =>
{
    var local = new Storage(Path.Combine(root, "bad-hash"));
    var bad = ReleasePolicy.Parse(ReleaseJson(hash: "sha256:" + new string('0',64)), Catalog.Telegram);
    using var updater = new Updates(local, new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }));
    await RejectAsync(() => updater.Prepare(Catalog.Telegram, bad, bad.Assets.Single(), null, default));
    Assert(updater.ReadPrepared(Catalog.Telegram) == null && !Directory.EnumerateFiles(local.Root, "*.partial", SearchOption.AllDirectories).Any());
});
await AsyncTest("short download rejected", async () =>
{
    using var updater = new Updates(new Storage(Path.Combine(root,"short")), new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent([1,2]) }));
    await RejectAsync(() => updater.Prepare(Catalog.Telegram, release, asset, null, default));
});
await AsyncTest("malicious redirect rejected", async () =>
{
    using var updater = new Updates(storage, new FakeHandler(_ => { var response = new HttpResponseMessage(HttpStatusCode.Redirect); response.Headers.Location = new("https://attacker.test/file"); return response; }));
    await RejectAsync(() => updater.Prepare(Catalog.Telegram, release, asset, null, default));
});
await AsyncTest("download cancellation leaves no partial", async () =>
{
    using var updater = new Updates(storage, new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }));
    using var token = new CancellationTokenSource(); token.Cancel();
    await RejectAsync(() => updater.Prepare(Catalog.Telegram, release, asset, null, token.Token));
    Assert(!Directory.EnumerateFiles(storage.Root, "*.partial", SearchOption.AllDirectories).Any());
});
await AsyncTest("404 is not up-to-date", async () =>
{
    using var updater = new Updates(storage, new FakeHandler(_ => new(HttpStatusCode.NotFound)));
    await RejectAsync(() => updater.Check(Catalog.Fix, default));
});
await AsyncTest("429 not silently successful", async () =>
{
    using var updater = new Updates(storage, new FakeHandler(_ => new(HttpStatusCode.TooManyRequests)));
    await RejectAsync(() => updater.Check(Catalog.Telegram, default));
});
await AsyncTest("release API parse", async () =>
{
    using var updater = new Updates(storage, new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new StringContent(ReleaseJson()) }));
    Assert((await updater.Check(Catalog.Telegram, default)).Tag == "v1.10.1");
});
Test("FIX profile has no shell commands", () => Assert(FixProfiles.Arguments(false).All(a => a.StartsWith("--") && !a.Contains('%') && !a.Contains('&') && !a.Contains("netsh"))));
Test("FIX preserves non-gaming ports", () => Assert(FixProfiles.Arguments(false).Contains("--wf-tcp=80,443,2053,2083,2087,2096,8443,12")));
Test("FIX gaming mode is explicit", () => Assert(FixProfiles.Arguments(true).Contains("--filter-udp=1024-65535")));
Test("FIX all required resources are relative", () => Assert(FixProfiles.RequiredFiles.All(f => !Path.IsPathRooted(f) && !f.Contains(".."))));
await AsyncTest("FIX missing engine rejected", () => RejectAsync(() => FixProfiles.Inspect(Path.Combine(root,"missing","bin","winws.exe"), default)));
await AsyncTest("HTTPS custom port rejected", () => RejectAsync(() => Diagnostics.Probe(new Uri("https://chatgpt.com:444/"), default)));
await AsyncTest("HTTPS query rejected", () => RejectAsync(() => Diagnostics.Probe(new Uri("https://chatgpt.com/?token=test"), default)));
Test("prepared manifest cannot escape storage", () =>
{
    storage.AtomicJson("prepared-telegram.json", new PreparedArtifact("telegram", "v1.10.1", Path.Combine(Path.GetTempPath(),"other.exe"), digest[7..], DateTimeOffset.Now));
    using var updater = new Updates(storage, new FakeHandler(_ => new(HttpStatusCode.OK)));
    Reject(() => updater.ReadPrepared(Catalog.Telegram));
});
Test("corrupt settings do not disappear", () =>
{
    var path = storage.Resolve("settings.json"); File.WriteAllText(path, "invalid-settings");
    Reject(() => storage.LoadSettings()); Assert(File.ReadAllText(path) == "invalid-settings");
});
Test("corrupt settings recovery copy", () =>
{
    storage.PreserveInvalidSettings(); Assert(Directory.EnumerateFiles(storage.Resolve("recovery")).Any(p => File.ReadAllText(p) == "invalid-settings"));
});
Test("reject alternate data stream", () => Reject(() => storage.Resolve("file.json:payload")));
await LifecycleTests.Run(Test, AsyncTest);
await AwgTests.Run(Test, AsyncTest);
MetaVpnTests.Run(Test);
await CombinedModeTests.Run(Test, AsyncTest);
await ResilienceTests.Run(Test, AsyncTest);
if (OperatingSystem.IsWindows()) await NetworkModeTests.Run(Test, AsyncTest);
await FixTests.Run(Test, AsyncTest);
await WhatsAppHostsTests.Run(Test, AsyncTest);
UiStateTests.Run(Test, root);
await FixControlTests.Run(Test, AsyncTest);
if (args.Contains("--local-readonly"))
{
    var preferences = new AppSettings(); Inventory.Discover(preferences);
    foreach (var spec in Catalog.All)
    {
        var value = await Inventory.Inspect(spec, spec == Catalog.Telegram ? preferences.TelegramPath : preferences.FixPath);
        Console.WriteLine($"LOCAL {spec.Id}: exists={value.Exists}; version={value.Version}; processCount={value.ProcessCount}");
    }
    await AsyncTest("REAL FIX profile resources verified", async () =>
    {
        var plan = await FixProfiles.Inspect(preferences.FixPath, default);
        storage.AtomicJson("local-profile-plan.json", plan);
        Assert(plan.Files.Count == 13); Console.WriteLine($"LOCAL FIX engine={plan.EngineVersion}; gaming={plan.GamingMode}; files={plan.Files.Count}; not launched");
    });
    if (OperatingSystem.IsWindows())
    foreach (var profile in FixCatalog.All)
        await AsyncTest("REAL FIX resources " + profile.Id, async () =>
        { var count = await WindowsFixRuntime.InspectResources(preferences.FixPath, profile.Id, default); Assert(count >= 4); Console.WriteLine($"LOCAL profile={profile.Id}; verifiedResources={count}; not launched"); });
}
if (args.Contains("--network-readonly"))
{
    using var updater = new Updates(storage);
    foreach (var spec in Catalog.All)
    {
        try { var current = await updater.Check(spec, default); Console.WriteLine($"UPSTREAM {spec.Id}: {current.Tag}; assets={current.Assets.Count}"); }
        catch (Exception error) { Console.WriteLine($"UPSTREAM {spec.Id}: unavailable ({error.GetType().Name})"); }
    }
    var check = await Diagnostics.Probe(new Uri("https://chatgpt.com/"), default);
    Console.WriteLine($"NETWORK {check.Target}: {check.State}. {check.Detail}");
}
Console.WriteLine($"RESULT passed={passed} failed={failed}. No component was launched and no network settings were changed.");
Console.WriteLine("Test artifacts: " + root);
return failed == 0 ? 0 : 1;

sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> handle) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    { ct.ThrowIfCancellationRequested(); return Task.FromResult(handle(request)); }
}
