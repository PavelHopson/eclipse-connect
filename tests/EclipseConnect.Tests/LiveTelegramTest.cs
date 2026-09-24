using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using EclipseConnect.Core;

internal static class LiveTelegramTest
{
    public static async Task<int> ProbeNetwork()
    {
        using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var results = new List<DiagnosticResult> { await Diagnostics.DnsProbe(ct.Token) };
        var targets = new[] { "https://chatgpt.com/", "https://web.telegram.org/", "https://www.youtube.com/", "https://discord.com/", "https://api.github.com/" };
        results.AddRange(await Task.WhenAll(targets.Select(t => Diagnostics.Probe(new Uri(t), ct.Token))));
        foreach (var result in results) Console.WriteLine(result.Target + ": " + result.State + ". " + result.Detail);
        var output = new Storage(Path.Combine(Path.GetTempPath(), "connect-network-test-" + Guid.NewGuid().ToString("N")));
        Console.WriteLine("NETWORK_REPORT=" + output.ExportReport(results));
        return 0; // Individual service outcomes are data, not a test-runner crash or proof of login.
    }
    public static async Task<int> Run(string[] args)
    {
        if (!args.Contains("--confirm-live")) throw new InvalidOperationException("Live test requires explicit --confirm-live authorization.");
        var index = Array.IndexOf(args, "--telegram-path");
        if (index < 0 || index + 1 >= args.Length) throw new InvalidOperationException("Explicit --telegram-path required.");
        var path = Path.GetFullPath(args[index + 1]);
        var portIndex = Array.IndexOf(args, "--expected-port");
        var port = portIndex >= 0 && portIndex + 1 < args.Length ? int.Parse(args[portIndex + 1]) : 1443;
        if (port is < 1024 or > 65535) throw new InvalidOperationException("Expected an unprivileged local port.");
        var artifacts = new Storage(Path.Combine(Path.GetTempPath(), "connect-live-test-" + Guid.NewGuid().ToString("N")));
        var evidence = new List<object>(); var failures = 0;
        void Record(string test, bool pass, string detail)
        {
            if (!pass) failures++;
            evidence.Add(new { Test = test, Pass = pass, Detail = detail, At = DateTimeOffset.Now });
            Console.WriteLine($"{(pass ? "PASS" : "FAIL")} {test}: {detail}");
        }
        var safety = new SessionSafety(); using var launcher = new Launcher(safety);
        try
        {
            using var overall = new CancellationTokenSource(TimeSpan.FromSeconds(85));
            var item = await Inventory.Inspect(Catalog.Telegram, path, overall.Token);
            if (!item.Exists || !item.Version.StartsWith('v') || item.ProcessCount != 0 || PortBusy(port))
                throw new InvalidOperationException("Preflight refused: file identity, external instance or occupied port.");
            Record("verified existing executable", true, "Known SHA-256 matches " + item.Version + "; no external instance or listener on " + port + ".");
            var denied = false;
            try { await launcher.StartTelegram(path, item.Hash, true, overall.Token); }
            catch (InvalidOperationException) { denied = true; }
            Record("default protection blocks real launch", denied && Inventory.CountProcesses(path) == 0, "No process should have been created.");
            if (!denied) throw new InvalidOperationException("Protection failed; stop test.");
            safety.AllowForSession(true);
            await launcher.StartTelegram(path, item.Hash, true, overall.Token);
            Record("real Process.Start", launcher.OwnsRunningProcess, "Connect owns the process handle.");
            var ready = await Until(async () => launcher.OwnsRunningProcess && await CanConnect(port), TimeSpan.FromSeconds(30));
            Record("local listener readiness", ready, ready ? $"TCP 127.0.0.1:{port} accepts connections; MTProto authentication not tested." : "No accepting listener within 30 seconds. A running GUI alone is not readiness.");
            if (ready) await Task.Delay(12000, overall.Token); // Allow independent read-only PID/port observation.

            denied = false;
            try { await launcher.StartTelegram(path, item.Hash, true, overall.Token); }
            catch (InvalidOperationException) { denied = true; }
            Record("duplicate request blocked", denied, "Second launch through same controller refused.");
            if (launcher.OwnsRunningProcess)
            {
                var otherSafety = new SessionSafety(); otherSafety.AllowForSession(true);
                using var other = new Launcher(otherSafety);
                denied = false;
                try { await other.StartTelegram(path, item.Hash, true, overall.Token); }
                catch (InvalidOperationException) { denied = true; }
                finally { if (other.OwnsRunningProcess) other.StopOwned(true); }
                Record("external controller cannot adopt or duplicate", denied && !other.OwnsRunningProcess, "Another controller does not own the test process.");
            }
            safety.Protect(); denied = false;
            try { launcher.StopOwned(true); }
            catch (InvalidOperationException) { denied = true; }
            Record("protection blocks stop", denied && launcher.OwnsRunningProcess, "Owned process stays alive when protection is on.");
        }
        catch (Exception error)
        {
            Record("live test exception", false, error.GetType().Name + ": " + Redactor.Sanitize(error.Message));
        }
        finally
        {
            // Only the handle created by this test can be stopped. Never search-and-kill.
            if (launcher.OwnsRunningProcess)
            {
                safety.AllowForSession(true);
                try
                {
                    launcher.StopOwned(true);
                    var stopped = await Until(() => Task.FromResult(Inventory.CountProcesses(path) == 0), TimeSpan.FromSeconds(10));
                    Record("stop owned process tree", stopped, stopped ? "Test process and same-executable children exited." : "A same-executable process remains; not terminated by name.");
                    Record("listener released", !PortBusy(port), "Expected " + port + " to be free again.");
                }
                catch (Exception error) { Record("owned cleanup", false, Redactor.Sanitize(error.Message)); }
            }
            artifacts.AtomicJson("live-result.json", new { Cases = evidence, Failures = failures, Scope = "Real Core Launcher only; no UI clicks, DNS/proxy/route edits or Telegram messages" });
            Console.WriteLine("LIVE_REPORT=" + artifacts.Resolve("live-result.json"));
        }
        Console.WriteLine("LIVE_FAILURES=" + failures);
        return failures == 0 ? 0 : 1;
    }
    private static bool PortBusy(int port) => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e => e.Port == port);
    private static async Task<bool> CanConnect(int port)
    {
        using var socket = new TcpClient(); using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        try { await socket.ConnectAsync("127.0.0.1", port, ct.Token); return true; }
        catch (Exception e) when (e is SocketException or OperationCanceledException) { return false; }
    }
    private static async Task<bool> Until(Func<Task<bool>> probe, TimeSpan timeout)
    {
        var timer = Stopwatch.StartNew();
        while (timer.Elapsed < timeout) { if (await probe()) return true; await Task.Delay(500); }
        return false;
    }
}
