using System.Diagnostics;
using System.Runtime.Versioning;
using EclipseConnect.Core;

internal static class NetworkModeTests
{
    private const string Prefix = @"Global\EclipseConnect.Tests.NetworkMode.";
    [SupportedOSPlatform("windows")]
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        if (!OperatingSystem.IsWindows()) return;
        test("network mode rejects second lease and permits restart", () =>
        {
            var name = NewName(); var first = WindowsNetworkModeLease.Acquire(name);
            try { Reject(name); Reject(name); } finally { first.Dispose(); first.Dispose(); }
            using var next = WindowsNetworkModeLease.Acquire(name);
        });
        await asyncTest("network mode releases on another async thread", async () =>
        {
            var name = NewName(); using var lease = WindowsNetworkModeLease.Acquire(name);
            await Task.Run(lease.Dispose);
            using var next = WindowsNetworkModeLease.Acquire(name);
        });
        test("network mode eight concurrent contenders have one winner", () =>
        {
            var name = NewName(); var winners = 0; var errors = 0;
            using var ready = new CountdownEvent(8); using var attempted = new CountdownEvent(8);
            using var go = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
            var threads = Enumerable.Range(0, 8).Select(_ => new Thread(() =>
            {
                WindowsNetworkModeLease? lease = null;
                ready.Signal();
                try
                {
                    if (!go.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException();
                    lease = WindowsNetworkModeLease.Acquire(name); Interlocked.Increment(ref winners);
                }
                catch (InvalidOperationException) { }
                catch { Interlocked.Increment(ref errors); }
                finally { attempted.Signal(); }
                try { release.Wait(TimeSpan.FromSeconds(10)); } finally { lease?.Dispose(); }
            }) { IsBackground = true }).ToArray();
            foreach (var thread in threads) thread.Start();
            try
            {
                Check(ready.Wait(TimeSpan.FromSeconds(10))); go.Set();
                Check(attempted.Wait(TimeSpan.FromSeconds(10))); Check(winners == 1 && errors == 0);
            }
            finally { go.Set(); release.Set(); foreach (var thread in threads) Check(thread.Join(5000)); }
            using var next = WindowsNetworkModeLease.Acquire(name);
        });
        await asyncTest("network mode blocks a separate process", async () =>
        {
            var name = NewName(); using var lease = WindowsNetworkModeLease.Acquire(name);
            using var child = StartChild(name, "try");
            try
            {
                Check(await Line(child) == "BUSY"); await Exit(child); Check(child.ExitCode == 23);
                Reject(name);
            }
            finally { StopChild(child); }
        });
        await asyncTest("network mode survives owner crash without a stale lock", async () =>
        {
            var name = NewName(); using var child = StartChild(name, "hold");
            try
            {
                Check(await Line(child) == "ACQUIRED"); Reject(name);
                child.Kill(true); await Exit(child);
                using var next = WindowsNetworkModeLease.Acquire(name);
            }
            finally { StopChild(child); }
        });
        await asyncTest("network mode simultaneous separate processes cannot both start", async () =>
        {
            var name = NewName(); using var first = StartChild(name, "race"); using var second = StartChild(name, "race");
            try
            {
                Check(await Line(first) == "READY" && await Line(second) == "READY");
                await Task.WhenAll(Send(first, "GO"), Send(second, "GO"));
                var results = await Task.WhenAll(Line(first), Line(second));
                Check(results.Count(r => r == "ACQUIRED") == 1 && results.Count(r => r == "BUSY") == 1);
                Reject(name);
                await Send(results[0] == "ACQUIRED" ? first : second, "RELEASE");
                await Task.WhenAll(Exit(first), Exit(second));
                Check(new[] { first.ExitCode, second.ExitCode }.Order().SequenceEqual(new[] { 0, 23 }));
                using var next = WindowsNetworkModeLease.Acquire(name);
            }
            finally { StopChild(first); StopChild(second); }
        });
    }

    // Only the test runner exposes this harmless child mode; it cannot launch network components.
    public static async Task<int> Child(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 3 || args[0] != "--network-mode-child" ||
            !args[1].StartsWith(Prefix, StringComparison.Ordinal) || !Guid.TryParseExact(args[1][Prefix.Length..], "N", out _) ||
            args[2] is not ("try" or "hold" or "race")) return 2;
        if (args[2] == "race")
        {
            Console.WriteLine("READY");
            if (await Console.In.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15)) != "GO") return 2;
        }
        try
        {
            using var lease = WindowsNetworkModeLease.Acquire(args[1]); Console.WriteLine("ACQUIRED");
            if (args[2] != "try") await Console.In.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
            return 0;
        }
        catch (InvalidOperationException) { Console.WriteLine("BUSY"); return 23; }
    }
    private static string NewName() => Prefix + Guid.NewGuid().ToString("N");
    [SupportedOSPlatform("windows")]
    private static void Reject(string name)
    {
        try { using var unexpected = WindowsNetworkModeLease.Acquire(name); }
        catch (InvalidOperationException) { return; }
        throw new Exception("Second network-mode owner was admitted");
    }
    private static void Check(bool ok) { if (!ok) throw new Exception("Network-mode assertion failed"); }
    private static Process StartChild(string name, string mode)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!)
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true };
        if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(NetworkModeTests).Assembly.Location);
        start.ArgumentList.Add("--network-mode-child"); start.ArgumentList.Add(name); start.ArgumentList.Add(mode);
        return Process.Start(start) ?? throw new Exception("No test child");
    }
    private static Task<string?> Line(Process child) => child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
    private static Task Exit(Process child) => child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
    private static async Task Send(Process child, string value)
    { await child.StandardInput.WriteLineAsync(value); await child.StandardInput.FlushAsync(); }
    private static void StopChild(Process child)
    { if (!child.HasExited) { child.Kill(true); child.WaitForExit(5000); } }
}
