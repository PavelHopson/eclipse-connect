using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EclipseConnect.Core;

internal static class AwgTests
{
    // Generated test-only credentials. Never copy an actual user profile into fixtures or snapshots.
    private static readonly string Private = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static readonly string Public = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    internal static string Fixture => $"[Interface]\nPrivateKey = {Private}\nMTU = 1280\nAddress = 172.16.0.2, 2001:db8::2\nDNS = 1.1.1.1, 2606:4700:4700::1111\nS1 = 0\nS2 = 0\nJc = 4\nJmin = 40\nJmax = 70\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nI1 = <b 0xc200000001{new string('a', 2390)}>\n\n[Peer]\nPublicKey = {Public}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.net:4500\n";
    private static void Check(bool value) { if (!value) throw new Exception("AWG assertion failed"); }
    private static void Reject(Action action)
    {
        try { action(); } catch (Exception error) { Check(!error.ToString().Contains(Private)); return; }
        throw new Exception("Expected rejection");
    }
    private static async Task RejectAsync(Func<Task> action)
    {
        try { await action(); } catch (Exception error) { Check(!error.ToString().Contains(Private)); return; }
        throw new Exception("Expected rejection");
    }
    private static AwgRequest Request(string operation, long sequence = 1, string? revision = null, bool? confirmed = null) =>
        new(1, Guid.NewGuid().ToString("N"), operation, revision, confirmed ?? operation is "start" or "stop", sequence);
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        var profile = AwgProfile.Parse(Fixture);
        test("AWG preserves long I1 and normalizes unmasked addresses", () =>
        { Check(profile.Mtu == 1280 && profile.SignaturePackets == 1 && profile.Configuration.Contains("172.16.0.2/32, 2001:db8::2/128")); Check(profile.Configuration.Contains(Fixture.Split('\n').Single(l => l.StartsWith("I1")))); });
        test("AWG round-trip stable revision", () => Check(AwgProfile.Parse(profile.Configuration).Revision == profile.Revision));
        test("AWG no secrets in ToString or JSON", () => Check(!profile.ToString().Contains(Private) && !JsonSerializer.Serialize(profile).Contains(Private) && !JsonSerializer.Serialize(profile).Contains(new string('a', 30))));
        test("AWG BOM, CRLF and comments", () => Check(AwgProfile.Parse("\uFEFF# profile\r\n" + Fixture.Replace("\n", "\r\n")).Revision == profile.Revision));
        test("AWG optional PSK, keepalive and IPv6 endpoint", () => Check(AwgProfile.Parse(Fixture.Replace("vpn.example.net:4500", "[2001:db8::1]:4500") + $"PresharedKey = {Public}\nPersistentKeepalive = 25\n").EndpointHost == "2001:db8::1"));
        test("AWG header ranges and multiple CPS tags", () => Check(AwgProfile.Parse(Fixture.Replace("H1 = 1", "H1 = 10-20").Replace("S1 = 0", "S1 = 0\nI2 = <r 2><b 0x1234><t>")).SignaturePackets == 2));
        var invalid = new Dictionary<string, string>
        {
            ["redacted key"] = Fixture.Replace(Private, "intentionally-hidden="),
            ["empty key"] = Fixture.Replace(Private, ""),
            ["zero key"] = Fixture.Replace(Private, Convert.ToBase64String(new byte[32])),
            ["duplicate key"] = Fixture.Replace("MTU = 1280", "MTU = 1280\nMTU = 1400"),
            ["unknown field"] = Fixture + "Command = powershell\n",
            ["hook"] = Fixture.Replace("S1 = 0", "S1 = 0\nPostUp = cmd /c anything"),
            ["unknown section"] = Fixture + "[Other]\n",
            ["second peer"] = Fixture + "[Peer]\nPublicKey = " + Public,
            ["interface reordered"] = Fixture + "[Interface]\n",
            ["missing peer"] = Fixture.Split("[Peer]")[0],
            ["IPv6 missing"] = Fixture.Replace(", 2001:db8::2", ""),
            ["IPv4-only routes"] = Fixture.Replace(", ::/0", ""),
            ["split routing unsupported"] = Fixture.Replace("0.0.0.0/0", "192.0.2.0/24"),
            ["DNS injection"] = Fixture.Replace("DNS = 1.1.1.1", "DNS = https://evil.invalid"),
            ["empty address"] = Fixture.Replace("Address = ", "Address = ,"),
            ["numeric IPv4 shorthand"] = Fixture.Replace("172.16.0.2", "0xAC100002"),
            ["invalid prefix"] = Fixture.Replace("172.16.0.2", "172.16.0.2/33"),
            ["IPv6 scoped"] = Fixture.Replace("2001:db8::2", "2001:db8::2%9"),
            ["mapped address"] = Fixture.Replace("2001:db8::2", "::ffff:172.16.0.2"),
            ["URL endpoint"] = Fixture.Replace("vpn.example.net:4500", "https://vpn.example.net:4500"),
            ["invalid endpoint port"] = Fixture.Replace(":4500", ":65536"),
            ["zero endpoint port"] = Fixture.Replace(":4500", ":0"),
            ["escaped CPS"] = Fixture.Replace("I1 = <", "I1 = \\<"),
            ["unclosed CPS"] = Fixture.Replace(">\n", "\n"),
            ["odd hex CPS"] = Fixture.Replace("0xc200", "0xc20"),
            ["unsupported CPS tag"] = Fixture.Replace("S1 = 0", "S1 = 0\nI2 = <exec command>"),
            ["huge CPS"] = Fixture.Replace("S1 = 0", "S1 = 0\nI2 = <r 1000><r 1000><r 1000>"),
            ["CPS trailing content"] = Fixture.Replace(">\n", "> garbage\n"),
            ["duplicate CPS timestamp"] = Fixture.Replace("S1 = 0", "S1 = 0\nI2 = <t><t>"),
            ["Jmin over Jmax"] = Fixture.Replace("Jmin = 40", "Jmin = 80"),
            ["negative Jc"] = Fixture.Replace("Jc = 4", "Jc = -1"),
            ["unbounded Jc"] = Fixture.Replace("Jc = 4", "Jc = 129"),
            ["small IPv6 MTU"] = Fixture.Replace("MTU = 1280", "MTU = 1279"),
            ["H overlap"] = Fixture.Replace("H1 = 1", "H1 = 1-2"),
            ["H overflow"] = Fixture.Replace("H1 = 1", "H1 = 4294967296"),
            ["NUL"] = Fixture.Replace("MTU = 1280", "MTU = 1280\0"),
            ["oversize"] = Fixture + new string(' ', AwgProfile.MaxBytes)
        };
        foreach (var pair in invalid) test("AWG rejects " + pair.Key, () => Reject(() => AwgProfile.Parse(pair.Value)));
        test("AWG redacts INI, inline and JSON keys", () =>
        {
            foreach (var value in new[] { Fixture, "error PrivateKey = " + Private, JsonSerializer.Serialize(new { PrivateKey = Private, PresharedKey = Private, I1 = "sensitive-payload" }) })
            { var sanitized = Redactor.Sanitize(value); Check(!sanitized.Contains(Private) && !sanitized.Contains("sensitive-payload") && !sanitized.Contains(new string('a', 30))); }
        });
        foreach (var bad in new[] { Request("shell"), Request("start", revision: profile.Revision, confirmed: false), Request("start"), Request("stop", revision: profile.Revision), Request("status", confirmed: true), Request("status", 0), Request("start", revision: "../profile") })
            await asyncTest("AWG refuses invalid control " + bad.Operation + "/" + bad.Sequence, async () =>
            { var runtime = new Fake(); await using var session = new AwgControlSession(runtime, () => profile); await RejectAsync(() => session.Execute(bad, default)); Check(runtime.Starts == 0 && runtime.Stops == 0); });
        await asyncTest("AWG status never starts a tunnel", async () =>
        { var fake = new Fake(); await using var session = new AwgControlSession(fake, () => profile); Check(!(await session.Execute(Request("status"), default)).Running && fake.Starts == 0); });
        await asyncTest("AWG revision mismatch preserves current runtime", async () =>
        { var fake = new Fake(); await using var session = new AwgControlSession(fake, () => profile); await RejectAsync(() => session.Execute(Request("start", revision: new string('A', 64)), default)); Check(fake.Starts == 0 && fake.Stops == 0); });
        await asyncTest("AWG confirmed start stop and replay guard", async () =>
        {
            var fake = new Fake(); await using var session = new AwgControlSession(fake, () => profile);
            var start = Request("start", revision: profile.Revision); Check((await session.Execute(start, default)).Authenticated);
            await RejectAsync(() => session.Execute(start, default)); Check(fake.Starts == 1 && fake.Stops == 0);
            Check(!(await session.Execute(Request("stop", 2), default)).Running && fake.Stops == 1);
        });
        await asyncTest("AWG cancellation before send does not launch", async () =>
        { var fake = new Fake(); await using var session = new AwgControlSession(fake, () => profile); using var ct = new CancellationTokenSource(); ct.Cancel(); await RejectAsync(() => session.Execute(Request("start", revision: profile.Revision), ct.Token)); Check(fake.Starts == 0); });
        await asyncTest("AWG failed stop keeps ownership visible", async () =>
        {
            var fake = new Fake { StopFails = true }; await using var session = new AwgControlSession(fake, () => profile);
            await session.Execute(Request("start", revision: profile.Revision), default);
            await RejectAsync(() => session.Execute(Request("stop", 2), default)); Check(session.State.Running);
        });
        await asyncTest("AWG unknown IPC property rejected", async () =>
        {
            var json = JsonSerializer.Serialize(Request("status")).TrimEnd('}') + ",\"PrivateKey\":\"fixture\"}";
            using var frame = new MemoryStream(); var bytes = Encoding.UTF8.GetBytes(json); var length = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
            frame.Write(length); frame.Write(bytes); frame.Position = 0;
            await RejectAsync(() => FixWire.Read<AwgRequest>(frame, default));
        });
        if (OperatingSystem.IsWindows())
        {
            ProtectedStoreTests(test, profile);
            await ConcurrentInitialImport(asyncTest, profile);
            await PipeTests(asyncTest, profile);
        }
    }
    [SupportedOSPlatform("windows")]
    private static async Task ConcurrentInitialImport(Func<string, Func<Task>, Task> asyncTest, AwgProfile profile)
    {
        await asyncTest("AWG concurrent initial imports have one winner and never replace", async () =>
        {
            var storage = new Storage(Path.Combine(Path.GetTempPath(), "connect-awg-race-" + Guid.NewGuid().ToString("N")));
            var store = new AwgProfileStore(storage);
            var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
            {
                try { store.Save(profile, false); return true; }
                catch (IOException) { return false; }
                catch (InvalidOperationException) { return false; }
            })));
            Check(outcomes.Count(value => value) == 1 && store.Load()?.Revision == profile.Revision);
        });
    }
    [SupportedOSPlatform("windows")]
    private static void ProtectedStoreTests(Action<string, Action> test, AwgProfile profile)
    {
        var storage = new Storage(Path.Combine(Path.GetTempPath(), "connect-awg-fixture-" + Guid.NewGuid().ToString("N")));
        var store = new AwgProfileStore(storage);
        test("AWG selective profile is isolated from legacy full-tunnel storage", () =>
        {
            var legacyPath = storage.Resolve("profiles/awg-current.dpapi");
            Directory.CreateDirectory(Path.GetDirectoryName(legacyPath)!);
            File.WriteAllBytes(legacyPath, WindowsDataProtection.Protect(Encoding.UTF8.GetBytes("synthetic legacy"), "EclipseConnect.AmneziaWG.Profile.v1"));
            var before = File.ReadAllBytes(legacyPath);
            Check(store.Load() == null);
            var isolated = WindowsDataProtection.Protect(Encoding.UTF8.GetBytes("synthetic"), "EclipseConnect.AmneziaWG.MetaProfile.v1");
            Reject(() => WindowsDataProtection.Unprotect(isolated, "EclipseConnect.AmneziaWG.Profile.v1"));
            Check(before.SequenceEqual(File.ReadAllBytes(legacyPath)));
        });
        test("AWG encrypted local store round trip", () =>
        { Check(store.Load() == null); store.Save(profile, false); Check(store.Load()?.Revision == profile.Revision); Check(!Encoding.UTF8.GetString(File.ReadAllBytes(storage.Resolve("profiles/awg-meta-current.dpapi"))).Contains(Private)); });
        test("AWG replacement requires consent and preserves encrypted previous", () =>
        {
            var previous = File.ReadAllBytes(storage.Resolve("profiles/awg-meta-current.dpapi"));
            Reject(() => store.Save(profile, false)); Check(previous.SequenceEqual(File.ReadAllBytes(storage.Resolve("profiles/awg-meta-current.dpapi"))));
            store.Save(profile, true); Check(previous.SequenceEqual(File.ReadAllBytes(storage.Resolve("profiles/awg-meta-previous.dpapi"))));
        });
        test("AWG DPAPI rejects corruption and wrong purpose", () =>
        {
            var clear = Encoding.UTF8.GetBytes("synthetic-fixture"); var encrypted = WindowsDataProtection.Protect(clear, "fixture");
            Reject(() => WindowsDataProtection.Unprotect(encrypted, "different")); encrypted[^1] ^= 1;
            Reject(() => WindowsDataProtection.Unprotect(encrypted, "fixture"));
        });
        test("AWG machine DPAPI preserves official tunnel description", () =>
        {
            var bytes = Encoding.UTF8.GetBytes("fixture-only"); var encrypted = WindowsDataProtection.Protect(bytes, WindowsAwgEngine.TunnelName, true);
            Check(WindowsDataProtection.Unprotect(encrypted, WindowsAwgEngine.TunnelName).SequenceEqual(bytes));
        });
        test("AWG rejects UNC, ADS and unexpected extension", () =>
        { foreach (var path in new[] { @"\\localhost\share\vpn.conf", @"C:\file.conf:stream", @"C:\file.exe" }) Reject(() => AwgProfile.ReadLocalFile(path)); });
        test("AWG local UTF8 import does not alter source", () =>
        {
            var path = storage.Resolve("input.conf"); File.WriteAllText(path, Fixture, new UTF8Encoding(true));
            var original = File.ReadAllBytes(path); Check(AwgProfile.ReadLocalFile(path).Revision == profile.Revision); Check(original.SequenceEqual(File.ReadAllBytes(path)));
        });
        test("AWG IPC has separate bounded namespace", () =>
        { var nonce = Guid.NewGuid().ToString("N"); Check(FixPipeSecurity.Name(nonce) != FixPipeSecurity.Name(nonce, "Vpn")); Reject(() => FixPipeSecurity.Name(nonce, "../other")); });
    }
    [SupportedOSPlatform("windows")]
    private static async Task PipeTests(Func<string, Func<Task>, Task> asyncTest, AwgProfile profile)
    {
        foreach (var scenario in new[] { "status", "start-stop", "cancel", "eof", "invalid", "replay", "reserve-start-stop", "reserve-cancel" })
            await asyncTest("AWG real local pipe " + scenario, async () =>
            {
                var nonce = Guid.NewGuid().ToString("N");
                using var server = FixPipeSecurity.Create(nonce, "Vpn");
                using var client = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce, "Vpn"), PipeDirection.InOut, PipeOptions.Asynchronous);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                var wait = server.WaitForConnectionAsync(timeout.Token); await client.ConnectAsync(timeout.Token); await wait;
                FixPipeSecurity.VerifyClient(server, Environment.ProcessId); FixPipeSecurity.VerifyServer(client, Environment.ProcessId);
                var fake = new Fake { HoldStart = scenario is "cancel" or "eof" or "reserve-cancel" }; var session = new AwgControlSession(fake, _ => profile);
                var serving = WindowsAwgAgent.Serve(client, session);
                try
                {
                    var request = scenario == "status" ? Request("status") : Request("start", revision: profile.Revision, confirmed: scenario != "invalid");
                    if (scenario.StartsWith("reserve-")) request = request with { ProfileSlot = AwgProfileSlot.Reserve };
                    await FixWire.Write(server, request, timeout.Token);
                    if (scenario is "cancel" or "eof" or "reserve-cancel")
                    {
                        await fake.Entered.Task.WaitAsync(timeout.Token);
                        if (scenario == "eof") { server.Dispose(); await serving.WaitAsync(timeout.Token); Check(!fake.Alive); return; }
                        await FixWire.Write(server, request with { Operation = "cancel", Revision = null, Confirmed = false, ProfileSlot = AwgProfileSlot.Primary }, timeout.Token);
                    }
                    if (scenario == "invalid") { await serving.WaitAsync(timeout.Token); Check(fake.Starts == 0); return; }
                    var reply = await FixWire.Read<AwgReply>(server, timeout.Token);
                    Check(reply.Id == request.Id);
                    if (scenario is "cancel" or "reserve-cancel") Check(reply.Error != null && !fake.Alive);
                    else Check(reply.Error == null);
                    if (scenario is "start-stop" or "reserve-start-stop")
                    {
                        await FixWire.Write(server, Request("stop", 2), timeout.Token); var stopped = await FixWire.Read<AwgReply>(server, timeout.Token); Check(!stopped.State.Running && fake.Stops == 1);
                    }
                    if (scenario == "replay")
                    { await FixWire.Write(server, request, timeout.Token); Check((await FixWire.Read<AwgReply>(server, timeout.Token)).Error != null && fake.Starts == 1); }
                }
                finally { server.Dispose(); await serving.WaitAsync(timeout.Token); Check(!fake.Alive && fake.Disposals == 1); }
            });
    }
    private sealed class Fake : IAwgRuntime
    {
        public int Starts, Stops, Disposals; public bool Alive, HoldStart, StopFails;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<AwgState> Status(CancellationToken ct) => Task.FromResult(new AwgState(Alive, Alive, "fixture"));
        public async Task<AwgState> Start(AwgProfile profile, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Starts++; Alive = true; Entered.TrySetResult();
            try { if (HoldStart) await Task.Delay(Timeout.Infinite, ct); return await Status(ct); }
            catch { Alive = false; throw; }
        }
        public Task<AwgState> Stop(CancellationToken ct)
        { if (StopFails) throw new IOException("fixture stop failure"); Stops++; Alive = false; return Status(ct); }
        public ValueTask DisposeAsync() { Disposals++; Alive = false; return ValueTask.CompletedTask; }
    }
}
