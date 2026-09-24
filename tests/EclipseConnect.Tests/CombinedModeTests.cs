using EclipseConnect.Core;

internal static class CombinedModeTests
{
    private static void Check(bool value) { if (!value) throw new Exception("Combined mode assertion failed"); }
    private static async Task Refuse(Func<Task> action)
    { try { await action(); } catch (Exception e) when (e is IOException or InvalidOperationException or OperationCanceledException) { return; } throw new Exception("Expected rejection"); }
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        var profile = AwgProfile.Parse(AwgTests.Fixture);
        test("HY policy contains four bounded hostname strategies", () =>
        {
            var groups = string.Join(" ", WebFixPolicy.Arguments(4500)).Split(" --new ");
            Check(groups.Length == 4 && groups.All(g => g.Contains("--hostlist-domains=") && g.Contains("--filter-")));
            Check(groups.All(g => !g.Contains("--ipset") && !g.Contains("--dpi-desync-any-protocol") && !g.Contains("--hostlist-auto")));
        });
        test("HY policy excludes shared service hostnames from FIX strategies", () =>
        {
            var hosts = (WebFixPolicy.Youtube + "," + WebFixPolicy.Rutracker).Split(',');
            foreach (var hostname in new[] { "chatgpt.com", "api.openai.com", "auth.openai.com", "instagram.com", "web.telegram.org", "cloudflare.com", "example.com", "google.com", "googleapis.com" })
                Check(!hosts.Any(h => hostname == h || hostname.EndsWith("." + h, StringComparison.Ordinal)));
            Check(hosts.Contains("rutracker.org") && hosts.Contains("googlevideo.com") && hosts.Contains("youtubei.googleapis.com"));
        });
        test("HY policy is immutable across calls and uses only fixed resources", () =>
        {
            var first = WebFixPolicy.Arguments(4500); first[0] = "unsafe";
            Check(WebFixPolicy.Arguments(4500)[0].StartsWith("--wf-raw=", StringComparison.Ordinal));
            var referenced = WebFixPolicy.Arguments(4500).Where(a => a.Contains('=')).Select(a => a[(a.IndexOf('=') + 1)..]).Where(a => a.StartsWith("bin/", StringComparison.Ordinal));
            Check(referenced.All(WebFixPolicy.Resources.Contains) && WebFixPolicy.Resources.Length == 7);
        });
        test("HY filter bounds and both directions of every Meta prefix", () =>
        {
            var text = WebFixPolicy.ExclusionFilter(4500);
            Check(text.Length < 12000 && text.Contains("udp.SrcPort != 4500") && text.Contains("udp.DstPort != 4500"));
            foreach (var prefix in MetaVpnPolicy.Prefixes)
            {
                var address = System.Net.IPNetwork.Parse(prefix).BaseAddress;
                var number = new System.Numerics.BigInteger(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true);
                Check(WebFixPolicy.MetaRanges().Any(r => r.First.GetAddressBytes().Length == address.GetAddressBytes().Length &&
                    new System.Numerics.BigInteger(r.First.GetAddressBytes(), isUnsigned: true, isBigEndian: true) <= number &&
                    new System.Numerics.BigInteger(r.Last.GetAddressBytes(), isUnsigned: true, isBigEndian: true) >= number));
            }
            Check(text.Contains("ipv6.SrcAddr") && text.Contains("ipv6.DstAddr") && text.Contains("ip.SrcAddr") && text.Contains("ip.DstAddr"));
        });
        foreach (var port in new[] { 0, -1, 65536 })
            test("HY rejects invalid endpoint port " + port, () =>
            { try { WebFixPolicy.Arguments(port); } catch (InvalidDataException) { return; } throw new Exception("Invalid port accepted"); });
        test("HY merged Meta ranges preserve exact cardinality without overlap or extra addresses", () =>
        {
            static System.Numerics.BigInteger Number(System.Net.IPAddress ip) => new(ip.GetAddressBytes(), isUnsigned: true, isBigEndian: true);
            foreach (var size in new[] { 4, 16 })
            {
                var original = MetaVpnPolicy.Prefixes.Select(System.Net.IPNetwork.Parse).Where(r => r.BaseAddress.GetAddressBytes().Length == size)
                    .Aggregate(System.Numerics.BigInteger.Zero, (sum, r) => sum + (System.Numerics.BigInteger.One << (size * 8 - r.PrefixLength)));
                var merged = WebFixPolicy.MetaRanges().Where(r => r.First.GetAddressBytes().Length == size).ToArray();
                Check(original == merged.Aggregate(System.Numerics.BigInteger.Zero, (sum, r) => sum + Number(r.Last) - Number(r.First) + 1));
                for (var i = 1; i < merged.Length; i++) Check(Number(merged[i - 1].Last) < Number(merged[i].First));
            }
        });
        if (OperatingSystem.IsWindows())
            test("HY companion cannot authorize an unowned VPN by name", () =>
            { if (!OperatingSystem.IsWindows()) return; try { new WindowsAwgRuntime().AssertCompanionAllowed(); } catch (InvalidOperationException) { return; } throw new Exception("Unowned VPN accepted"); });
        await asyncTest("HY start order and successful combined status", async () =>
        {
            var f = new Scenario(); await using var run = f.Create();
            var state = await run.Start(profile, default);
            Check(state.Authenticated && f.Events.Take(3).SequenceEqual(new[] { "preflight", "vpn-start", "fix-start" }));
            await Refuse(() => run.Start(profile, default));
        });
        await asyncTest("HY preflight failure never starts VPN", async () =>
        {
            var f = new Scenario { FailPreflight = true }; await using var run = f.Create();
            await Refuse(() => run.Start(profile, default)); Check(f.Events.SequenceEqual(new[] { "preflight" }));
        });
        await asyncTest("HY VPN start failure rolls back without FIX", async () =>
        {
            var f = new Scenario(); f.Vpn.FailStart = true; await using var run = f.Create();
            await Refuse(() => run.Start(profile, default)); Check(!f.Events.Contains("fix-start") && f.Events.Contains("vpn-stop"));
        });
        await asyncTest("HY unverified handshake prevents FIX start", async () =>
        {
            var f = new Scenario(); f.Vpn.Authenticated = false; await using var run = f.Create();
            await Refuse(() => run.Start(profile, default)); Check(!f.Events.Contains("fix-start") && !f.Vpn.Running);
        });
        await asyncTest("HY FIX start failure rolls back own VPN", async () =>
        {
            var f = new Scenario { FailFixStart = true }; await using var run = f.Create();
            await Refuse(() => run.Start(profile, default)); Check(!f.Vpn.Running && f.Events.Last() == "vpn-stop");
        });
        await asyncTest("HY cancelled FIX preparation rolls back", async () =>
        {
            var f = new Scenario(); using var ct = new CancellationTokenSource(); f.CancelDuringFix = ct; await using var run = f.Create();
            await Refuse(() => run.Start(profile, ct.Token)); Check(!f.Vpn.Running && !f.Fix.Running);
        });
        await asyncTest("HY failed FIX stop retains VPN for safe retry", async () =>
        {
            var f = new Scenario(); await using var run = f.Create(); await run.Start(profile, default);
            f.Fix.FailStop = true; await Refuse(() => run.Stop(default));
            Check(f.Vpn.Running && !f.Events.Contains("vpn-stop")); await Refuse(() => run.Start(profile, default));
            f.Fix.FailStop = false; await run.Stop(default); Check(!f.Vpn.Running && !f.Fix.Running);
            Check(f.Events.IndexOf("fix-dispose") < f.Events.IndexOf("vpn-stop"));
        });
        await asyncTest("HY failed VPN stop retains retry and rejects restart", async () =>
        {
            var f = new Scenario(); await using var run = f.Create(); await run.Start(profile, default);
            f.Vpn.FailStop = true; await Refuse(() => run.Stop(default));
            Check(!f.Fix.Running && f.Vpn.Running && !(await run.Status(default)).Authenticated);
            await Refuse(() => run.Start(profile, default)); f.Vpn.FailStop = false; await run.Stop(default);
            Check(!(await run.Status(default)).Running);
        });
        await asyncTest("HY crashed FIX is never reported as connected", async () =>
        {
            var f = new Scenario(); await using var run = f.Create(); await run.Start(profile, default);
            f.Fix.Running = false; var state = await run.Status(default); Check(state.Running && !state.Authenticated);
        });
        await asyncTest("HY crashed VPN retains FIX stop action without false success", async () =>
        {
            var f = new Scenario(); await using var run = f.Create(); await run.Start(profile, default);
            f.Vpn.Running = false; var state = await run.Status(default); Check(state.Running && !state.Authenticated);
        });
        await asyncTest("HY disposal contains FIX before disposing VPN on stop error", async () =>
        {
            var f = new Scenario(); var run = f.Create(); await run.Start(profile, default); f.Fix.FailStop = true;
            await Refuse(() => run.DisposeAsync().AsTask());
            Check(!f.Fix.Running && !f.Vpn.Running && f.Events.IndexOf("fix-dispose") < f.Events.IndexOf("vpn-dispose"));
        });
        await asyncTest("HY stop is repeatable and successful stop allows reconnect", async () =>
        {
            var f = new Scenario(); await using var run = f.Create(); await run.Start(profile, default); await run.Stop(default); await run.Stop(default);
            Check((await run.Start(profile, default)).Authenticated);
        });
    }
    private sealed class Scenario
    {
        public readonly List<string> Events = [];
        public FakeVpn Vpn { get; }
        public FakeFix Fix { get; }
        public bool FailPreflight, FailFixStart;
        public CancellationTokenSource? CancelDuringFix;
        public Scenario() { Vpn = new(Events); Fix = new(Events); }
        public CombinedAwgRuntime Create() => new(Vpn, (_, ct) =>
        {
            Events.Add("fix-start"); if (FailFixStart) throw new IOException("simulated");
            Fix.Running = true; CancelDuringFix?.Cancel(); return Task.FromResult<IManagedProcess>(Fix);
        }, ct => { ct.ThrowIfCancellationRequested(); Events.Add("preflight"); if (FailPreflight) throw new IOException("simulated"); return Task.CompletedTask; });
    }
    private sealed class FakeVpn(List<string> events) : IAwgRuntime
    {
        public bool Running, FailStart, FailStop;
        public bool Authenticated = true;
        public Task<AwgState> Status(CancellationToken ct) { ct.ThrowIfCancellationRequested(); return Task.FromResult(new AwgState(Running, Running && Authenticated, "simulated")); }
        public Task<AwgState> Start(AwgProfile profile, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); events.Add("vpn-start"); Running = true; if (FailStart) throw new IOException("simulated"); return Status(ct); }
        public Task<AwgState> Stop(CancellationToken ct)
        { events.Add("vpn-stop"); if (FailStop) throw new IOException("simulated"); Running = false; return Status(ct); }
        public ValueTask DisposeAsync() { events.Add("vpn-dispose"); Running = false; return ValueTask.CompletedTask; }
    }
    private sealed class FakeFix(List<string> events) : IManagedProcess
    {
        public bool Running, FailStop;
        public bool IsRunning => Running;
        public void Stop() { events.Add("fix-stop"); if (FailStop) throw new IOException("simulated"); Running = false; }
        public void Dispose() { events.Add("fix-dispose"); Running = false; }
    }
}
