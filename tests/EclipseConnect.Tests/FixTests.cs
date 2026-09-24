using EclipseConnect.Core;

internal static class FixTests
{
    private static void Check(bool pass) { if (!pass) throw new Exception("Assertion failed"); }
    private static async Task Reject(Func<Task> action)
    { try { await action(); } catch (Exception e) when (e is InvalidOperationException or IOException or InvalidDataException or OperationCanceledException) { return; } throw new Exception("Expected refusal"); }
    private static SessionSafety Allowed() { var s = new SessionSafety(); s.AllowForSession(true); return s; }
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        test("Telegram real configurable port", () => Check(TelegramEndpoint.Parse("""{"port":1080,"host":"127.0.0.1","secret":"ignored"}""").Port == 1080));
        test("Telegram endpoint never exports secret", () => Check(!TelegramEndpoint.Parse("""{"port":1080,"secret":"never-log"}""").ToString().Contains("never-log")));
        foreach (var value in new[] { "0", "65536", "-1", "\"1080\"", "true" })
            await asyncTest("reject invalid Telegram port " + value, () => Reject(() => { TelegramEndpoint.Parse("{\"port\":" + value + "}"); return Task.CompletedTask; }));
        await asyncTest("reject remote Telegram binding", () => Reject(() => { TelegramEndpoint.Parse("""{"port":1080,"host":"203.0.113.42"}"""); return Task.CompletedTask; }));
        test("known updated Telegram release", () => Check(Catalog.KnownVersion(Catalog.Telegram, "17be7f17b2e19920935988822d66f14dd2b727372ff565a28ff64b757ff4d898") == "v1.10.2"));
        test("FIX profiles have fixed IDs", () => Check(FixCatalog.All.Length == 4 && FixCatalog.All.Select(p => p.Id).Distinct().Count() == 4));
        await asyncTest("FIX arbitrary profile rejected", () => Reject(() => { FixCatalog.Arguments("../evil.bat", false); return Task.CompletedTask; }));
        await asyncTest("FIX arbitrary target rejected", () => Reject(() => { FixCatalog.Candidates("http://127.0.0.1"); return Task.CompletedTask; }));
        test("FIX all targets use only broad profiles", () => Check(FixCatalog.Candidates("all").All(p => p.Targets.Length == 2)));
        test("Telegram exclusions contain only 110 exact TLS names", () =>
        {
            using var stream = TelegramFixCompatibility.OpenResource(); using var reader = new StreamReader(stream);
            var lines = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith('#')).ToArray();
            Check(lines.Length == 110 && lines.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 110);
            Check(lines.All(s => System.Text.RegularExpressions.Regex.IsMatch(s, @"^\^kws[1-5](-1)?\.[a-z.]+$")));
            Check(lines.Contains("^kws2.web.telegram.org") && lines.Contains("^kws4-1.web.telegram.org") && lines.Contains("^kws2.pclead.co.uk"));
            Check(!lines.Any(s => s is "^web.telegram.org" or "^telegram.org" or "^co.uk" || s.Contains("cloudflare") || s.Contains('/') || s.Contains('*')));
        });
        test("Telegram resource is deterministic read-only data", () =>
        {
            using var a = TelegramFixCompatibility.OpenResource(); using var b = TelegramFixCompatibility.OpenResource();
            Check(!a.CanWrite && a.Length is > 0 and < 32768);
            Check(System.Security.Cryptography.SHA256.HashData(a).SequenceEqual(System.Security.Cryptography.SHA256.HashData(b)));
        });
        foreach (var p in FixCatalog.All)
        foreach (var gaming in new[] { false, true })
        {
            test($"Telegram exclusion covers every TLS/QUIC rule {p.Id}/{gaming}", () =>
            {
                var args = FixCatalog.Arguments(p.Id, gaming);
                foreach (var group in string.Join("\n", args).Split("\n--new\n"))
                {
                    var parts = group.Split('\n');
                    var affected = parts.Any(a => a.StartsWith("--filter-tcp=") || a == "--filter-udp=443");
                    Check(parts.Count(a => a == TelegramFixCompatibility.Argument) == (affected ? 1 : 0));
                }
                Check(args.SequenceEqual(TelegramFixCompatibility.AddExclusions(args)));
                Check(FixCatalog.Resources(p.Id, gaming).Count(r => r == TelegramFixCompatibility.ResourcePath) == 1);
            });
        }
        test("Telegram exclusions preserve original arguments and UDP voice", () =>
        {
            string[] original = ["--wf-tcp=443", "--filter-tcp=443", "--hostlist-exclude=lists/list-exclude.txt", "--dpi-desync=fake", "--new",
                "--filter-udp=50000-50100", "--dpi-desync-any-protocol=1", "--new", "--filter-tcp=80,443", "--dpi-desync=multisplit"];
            var result = TelegramFixCompatibility.AddExclusions(original);
            Check(result.Where(a => a != TelegramFixCompatibility.Argument).SequenceEqual(original));
            Check(result.Count(a => a == TelegramFixCompatibility.Argument) == 2);
        });
        test("Telegram exclusions retain Cloudflare and IP exclusions", () =>
        {
            var args = FixCatalog.Arguments("ultimate", false);
            Check(args.Count(a => a == "--ipset=lists/ipset-cloudflare.txt") == 4);
            Check(args.Count(a => a == "--ipset-exclude=lists/ipset-exclude.txt") == 7);
            Check(args.Count(a => a == "--hostlist-exclude=lists/list-exclude.txt") == 6);
        });
        foreach (var p in FixCatalog.All)
        {
            test("FIX argv no shell " + p.Id, () => Check(FixCatalog.Arguments(p.Id, false).All(a => a.StartsWith("--") && a.IndexOfAny(['&','|',';','^','%','\"','\r','\n']) < 0)));
            test("FIX resources constrained " + p.Id, () => Check(FixCatalog.Resources(p.Id, false).All(f => !Path.IsPathRooted(f) && !f.Contains("..") && (f.StartsWith("bin/") || f.StartsWith("lists/")))));
            test("FIX dependency cygwin verified " + p.Id, () => Check(FixCatalog.Resources(p.Id, false).Contains("bin/cygwin1.dll")));
            test("FIX never enables gaming implicitly " + p.Id, () => Check(!FixCatalog.Arguments(p.Id, false).Any(a => a.Contains("1024-65535"))));
        }
        await asyncTest("FIX protected selection has zero effects", async () =>
        { var r = new Fake(); await Reject(() => new FixSelector(new(), r).Select("all", true, null, default)); Check(r.Starts == 0 && r.Probes == 0); });
        await asyncTest("FIX unconfirmed selection has zero effects", async () =>
        { var r = new Fake(); await Reject(() => new FixSelector(Allowed(), r).Select("all", false, null, default)); Check(r.Starts == 0 && r.Probes == 0); });
        foreach (var external in new[] { true, false })
            await asyncTest("FIX refuse " + (external ? "external engine" : "tunnel"), async () =>
            { var r = new Fake { External = external, Tunnel = !external }; await Reject(() => new FixSelector(Allowed(), r).Select("all", true, null, default)); Check(r.Starts == 0 && r.Probes == 0); });
        await asyncTest("FIX bad baseline control never starts", async () =>
        { var r = new Fake { Results = new([Probe(false, false)]) }; var result = await new FixSelector(Allowed(), r).Select("all", true, null, default); Check(result.SelectedId == null && r.Starts == 0); });
        await asyncTest("FIX already available does not attribute success to profile", async () =>
        { var r = new Fake { Results = new([Probe(true, true)]) }; var result = await new FixSelector(Allowed(), r).Select("all", true, null, default); Check(result.SelectedId == null && r.Starts == 0); });
        await asyncTest("FIX success needs two passes and stops trial", async () =>
        { var r = new Fake(); var result = await new FixSelector(Allowed(), r).Select("all", true, null, default); Check(result.SelectedId == "ultimate" && r.Probes == 3 && r.Stops == 1 && r.Alive == 0); });
        await asyncTest("FIX failed candidate is stopped before next", async () =>
        {
            var r = new Fake { Results = new([Probe(true, false), Probe(true, true), Probe(true, false), Probe(true, true), Probe(true, true)]) };
            var result = await new FixSelector(Allowed(), r).Select("all", true, null, default);
            Check(result.SelectedId == "general" && r.Starts == 2 && r.Stops == 2 && r.MaxAlive == 1);
        });
        await asyncTest("FIX all candidates fail no selection", async () =>
        { var r = new Fake { Results = new(Enumerable.Repeat(Probe(true, false), 5)) }; var result = await new FixSelector(Allowed(), r).Select("all", true, null, default); Check(result.SelectedId == null && r.Stops == 2 && r.Alive == 0); });
        await asyncTest("FIX cancellation stops trial", async () =>
        { using var c = new CancellationTokenSource(); var r = new Fake { OnTrialProbe = () => c.Cancel() }; await Reject(() => new FixSelector(Allowed(), r).Select("all", true, null, c.Token)); Check(r.Stops == 1 && r.Alive == 0); });
        await asyncTest("FIX protection revocation stops trial", async () =>
        { var s = Allowed(); var r = new Fake { OnTrialProbe = s.Protect }; await Reject(() => new FixSelector(s, r).Select("all", true, null, default)); Check(r.Stops == 1 && r.Alive == 0); });
        await asyncTest("FIX tunnel appears during trial invalidates result", async () =>
        { var r = new Fake(); r.OnTrialProbe = () => r.Tunnel = true; await Reject(() => new FixSelector(Allowed(), r).Select("all", true, null, default)); Check(r.Stops == 1 && r.Alive == 0); });
        await asyncTest("FIX stop failure aborts selection", async () =>
        { var r = new Fake { StopFails = true }; await Reject(() => new FixSelector(Allowed(), r).Select("all", true, null, default)); Check(r.Starts == 1 && r.Disposals == 1); });
        await asyncTest("FIX probe failure stops own trial", async () =>
        { var r = new Fake { OnTrialProbe = () => throw new IOException("test") }; await Reject(() => new FixSelector(Allowed(), r).Select("all", true, null, default)); Check(r.Stops == 1 && r.Alive == 0); });
        await asyncTest("FIX cancellation before baseline never starts", async () =>
        { var r = new Fake(); await Reject(() => new FixSelector(Allowed(), r).Select("all", true, null, new CancellationToken(true))); Check(r.Starts == 0 && r.Probes == 0); });
        await asyncTest("FIX double-click refused", async () =>
        {
            var gate = new TaskCompletionSource<FixProbe>(TaskCreationOptions.RunContinuationsAsynchronously);
            var r = new Fake { FirstProbe = gate.Task }; var selector = new FixSelector(Allowed(), r);
            var first = selector.Select("all", true, null, default);
            await Reject(() => selector.Select("all", true, null, default));
            gate.SetResult(Probe(true, true)); await first; Check(r.Starts == 0);
        });
        await asyncTest("FIX detailed result records both probes", async () =>
        {
            var r = new Fake(); var states = new List<FixProgress>();
            var result = await new FixSelector(Allowed(), r).Select("all", true, null, default, new ImmediateProgress(states.Add));
            Check(result.Trials[0].Checks.Count == 2 && result.Trials[0].Checks.All(c => c.ControlReady && c.ProcessRunning));
            Check(states.First().Stage == "Исходная сеть" && states.Last().Stage == "Кандидат остановлен" && states.Last().Trials.Count == 1);
        });
    }
    private static FixProbe Probe(bool control, bool sites) => new(control, new Dictionary<string, bool> { ["youtube"] = sites, ["discord"] = sites });
    private sealed class ImmediateProgress(Action<FixProgress> report) : IProgress<FixProgress>
    { public void Report(FixProgress value) => report(value); }
    private sealed class Fake : IFixRuntime
    {
        public bool External, Tunnel, StopFails;
        public int Starts, Probes, Stops, Alive, MaxAlive, Disposals;
        public Queue<FixProbe> Results = new([FixTests.Probe(true, false), FixTests.Probe(true, true), FixTests.Probe(true, true)]);
        public Action? OnTrialProbe;
        public Task<FixProbe>? FirstProbe;
        public bool HasExternalEngine => External;
        public bool HasConfoundingTunnel => Tunnel;
        public Task<IManagedProcess> Start(string profileId, bool gaming, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); Check(Alive == 0 && !gaming); Starts++; Alive++; MaxAlive = Math.Max(MaxAlive, Alive); return Task.FromResult<IManagedProcess>(new Owned(this)); }
        public Task<FixProbe> Probe(CancellationToken ct)
        {
            Probes++;
            if (Probes == 1 && FirstProbe != null) return FirstProbe;
            if (Probes > 1) OnTrialProbe?.Invoke();
            ct.ThrowIfCancellationRequested(); return Task.FromResult(Results.Dequeue());
        }
        private sealed class Owned(Fake runtime) : IManagedProcess
        {
            private bool alive = true;
            public bool IsRunning => alive;
            public void Stop() { runtime.Stops++; if (runtime.StopFails) throw new IOException("test stop failure"); alive = false; runtime.Alive--; }
            public void Dispose() { runtime.Disposals++; }
        }
    }
}
