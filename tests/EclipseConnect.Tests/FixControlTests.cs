using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using EclipseConnect.Core;

internal static class FixControlTests
{
    private static void Check(bool value) { if (!value) throw new Exception("Assertion failed"); }
    private static async Task Reject(Func<Task> action)
    { var rejected = false; try { await action(); } catch (Exception) { rejected = true; } Check(rejected); }
    private static FixControlRequest Command(string op, FixRun? run = null, bool confirmed = true, long sequence = 1)
        => new(1, Guid.NewGuid().ToString("N"), op, run, confirmed, sequence);
    private static Storage Store() => new(Path.Combine(Path.GetTempPath(), "connect-control-test-" + Guid.NewGuid().ToString("N")));
    private static FixRun First => new("ultimate", false, "youtube");
    private static FixRun Second => new("general", false, "youtube");
    private static FixControlSession Session(Fake fake, Storage? store = null, Func<string, CancellationToken, Task>? preflight = null)
        => new(fake, store ?? Store(), preflight ?? ((_, ct) => { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; }));
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        foreach (var invalid in new[]
        {
            Command("shell"), Command("start", First, false), Command("start", null),
            Command("status", First), Command("start", First with { ProfileId = "../bad.exe" }),
            Command("start", First with { Target = "https://127.0.0.1" }), Command("select", First with { Gaming = true }),
            Command("status") with { Version = 99 }, Command("status") with { Id = "bad" }, Command("status", sequence: 0)
        })
            await asyncTest("FIX control rejects invalid " + invalid.Operation + "/" + invalid.Version + "/" + invalid.Sequence, async () =>
            { var fake = new Fake(); using var s = Session(fake); await Reject(() => s.Execute(invalid, default, default)); Check(fake.Starts == 0); });
        await asyncTest("FIX status never launches", async () =>
        { var f = new Fake(); using var s = Session(f); var state = await s.Execute(Command("status"), default, default); Check(!state.Running && f.Starts == 0); });
        await asyncTest("FIX manual start refuses active VPN", async () =>
        { var f = new Fake { Tunnel = true }; using var s = Session(f); await Reject(() => s.Execute(Command("start", First), default, default)); Check(f.Starts == 0 && f.Stops == 0); });
        await asyncTest("FIX manual start rechecks VPN after preparation", async () =>
        { var f = new Fake(); using var s = Session(f, preflight: (_, _) => { f.Tunnel = true; return Task.CompletedTask; }); await Reject(() => s.Execute(Command("start", First), default, default)); Check(f.Starts == 0 && f.Stops == 0); });
        await asyncTest("FIX rejects external engine without stopping it", async () =>
        { var f = new Fake { External = true }; using var s = Session(f); await Reject(() => s.Execute(Command("start", First), default, default)); Check(f.Starts == 0 && f.Stops == 0); });
        await asyncTest("FIX owned start stop", async () =>
        { var f = new Fake(); using var s = Session(f); Check((await s.Execute(Command("start", First), default, default)).Running); await s.Execute(Command("stop"), default, default); Check(f.Alive == 0 && f.Stops == 1); });
        await asyncTest("FIX preflight failure preserves active process", async () =>
        {
            var f = new Fake(); using var s = Session(f, preflight: (id, _) => id == "general" ? Task.FromException(new IOException("fixture")) : Task.CompletedTask);
            await s.Execute(Command("start", First), default, default);
            await Reject(() => s.Execute(Command("switch", Second), default, default));
            Check(s.State.Active == First && f.Stops == 0);
        });
        await asyncTest("FIX recovery write failure preserves active process", async () =>
        {
            var store = Store(); File.WriteAllText(store.Resolve("recovery"), "fixture");
            var f = new Fake(); using var s = Session(f, store);
            await s.Execute(Command("start", First), default, default);
            await Reject(() => s.Execute(Command("switch", Second), default, default));
            Check(s.State.Active == First && f.Stops == 0);
        });
        await asyncTest("FIX successful switch and explicit restore", async () =>
        {
            var f = new Fake(); using var s = Session(f);
            await s.Execute(Command("start", First), default, default);
            var state = await s.Execute(Command("switch", Second), default, default);
            Check(state.Active == Second && state.Previous == First && f.Probes == 2 && f.MaxAlive == 1);
            state = await s.Execute(Command("restore"), default, default); Check(state.Active == First && f.MaxAlive == 1);
        });
        await asyncTest("FIX failed probe restores previous actual run", async () =>
        {
            var f = new Fake { Pass = false }; using var s = Session(f);
            await s.Execute(Command("start", First), default, default);
            var state = await s.Execute(Command("switch", Second), default, default);
            Check(state.Active == First && f.Starts == 3 && f.MaxAlive == 1 && state.Message.Contains("Предыдущий"));
        });
        await asyncTest("FIX failed start restores previous actual run", async () =>
        {
            var f = new Fake { FailStarts = [2] }; using var s = Session(f);
            await s.Execute(Command("start", First), default, default);
            var state = await s.Execute(Command("switch", Second), default, default); Check(state.Active == First && f.Starts == 3);
        });
        await asyncTest("FIX rollback failure reported without hidden success", async () =>
        {
            var f = new Fake { FailStarts = [2,3] }; using var s = Session(f);
            await s.Execute(Command("start", First), default, default);
            await Reject(() => s.Execute(Command("switch", Second), default, default)); Check(!s.State.Running && f.Alive == 0);
        });
        await asyncTest("FIX cancel during switch restores while owner alive", async () =>
        {
            using var cancel = new CancellationTokenSource(); var f = new Fake { OnProbe = cancel.Cancel }; using var s = Session(f);
            await s.Execute(Command("start", First), default, default);
            var state = await s.Execute(Command("switch", Second), cancel.Token, default); Check(state.Active == First && f.Starts == 3);
        });
        await asyncTest("FIX lost owner does not secretly restart", async () =>
        {
            using var life = new CancellationTokenSource(); var f = new Fake { OnProbe = life.Cancel }; using var s = Session(f);
            await s.Execute(Command("start", First), default, life.Token);
            await Reject(() => s.Execute(Command("switch", Second), default, life.Token)); Check(f.Alive == 0 && f.Starts == 2);
        });
        await asyncTest("FIX stop failure blocks next start", async () =>
        {
            var f = new Fake { StopFails = true }; using var s = Session(f);
            await s.Execute(Command("start", First), default, default);
            await Reject(() => s.Execute(Command("switch", Second), default, default)); Check(f.Starts == 1 && s.State.Active == First);
        });
        await asyncTest("FIX tunnel prevents tested switch without interruption", async () =>
        {
            var f = new Fake(); using var s = Session(f); await s.Execute(Command("start", First), default, default);
            f.Tunnel = true; await Reject(() => s.Execute(Command("switch", Second), default, default)); Check(f.Stops == 0);
        });
        await asyncTest("FIX late cancelled start cleans its exact handle", async () =>
        {
            using var cancel = new CancellationTokenSource(); var f = new Fake { OnStart = cancel.Cancel }; using var s = Session(f);
            await Reject(() => s.Execute(Command("start", First), cancel.Token, default)); Check(f.Alive == 0);
        });
        await asyncTest("FIX owner loss at rollback start cleans restored handle", async () =>
        {
            using var life = new CancellationTokenSource();
            var f = new Fake { FailStarts = [2] }; using var s = Session(f);
            await s.Execute(Command("start", First), default, life.Token);
            f.OnStart = life.Cancel;
            await Reject(() => s.Execute(Command("switch", Second), default, life.Token));
            Check(f.Alive == 0 && f.Starts == 3);
        });
        await asyncTest("FIX simultaneous operation is rejected", async () =>
        {
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var f = new Fake(); using var s = Session(f, preflight: (_, _) => gate.Task);
            var first = s.Execute(Command("start", First), default, default);
            await Reject(() => s.Execute(Command("start", Second), default, default));
            gate.SetResult(); await first; Check(f.Starts == 1);
        });
        await asyncTest("FIX frame round trip", async () =>
        { using var m = new MemoryStream(); var request = Command("status"); await FixWire.Write(m, request, default); m.Position = 0; Check(await FixWire.Read<FixControlRequest>(m, default) == request); });
        foreach (var length in new[] { -1, 0, FixWire.MaxFrame + 1 })
            await asyncTest("FIX rejects frame length " + length, async () =>
            { using var m = new MemoryStream(); var header = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(header, length); m.Write(header); m.Position = 0; await Reject(() => FixWire.Read<FixControlRequest>(m, default)); });
        await asyncTest("FIX rejects unknown JSON command fields", async () =>
        {
            using var m = new MemoryStream(); var payload = JsonSerializer.SerializeToUtf8Bytes(new { Version = 1, Id = Guid.NewGuid().ToString("N"), Operation = "start", Path = "bad.exe" });
            var header = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length); m.Write(header); m.Write(payload); m.Position = 0;
            await Reject(() => FixWire.Read<FixControlRequest>(m, default));
        });
        await asyncTest("diagnostic arbitrary path rejected", () => Reject(() => Diagnostics.Probe(new("https://www.instagram.com/private"), default)));
        if (OperatingSystem.IsWindows()) await RunWindows(asyncTest);
    }
    [SupportedOSPlatform("windows")]
    private static async Task RunWindows(Func<string, Func<Task>, Task> asyncTest)
    {
            foreach (var disconnect in new[] { false, true })
            await asyncTest(disconnect ? "FIX pipe lost owner during probe never restarts" : "FIX pipe cancellation restores previous run", async () =>
            {
                var nonce = Guid.NewGuid().ToString("N"); using var server = FixPipeSecurity.Create(nonce);
                using var client = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce), PipeDirection.InOut, PipeOptions.Asynchronous);
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await Task.WhenAll(server.WaitForConnectionAsync(limit.Token), client.ConnectAsync(limit.Token));
                var probeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var f = new Fake { WaitProbe = true, OnProbe = () => probeStarted.TrySetResult() };
                using var s = Session(f); var serve = WindowsFixAgent.Serve(client, s);
                await FixWire.Write(server, Command("start", First), limit.Token);
                _ = await FixWire.Read<FixControlReply>(server, limit.Token);
                var change = Command("switch", Second, sequence: 2);
                await FixWire.Write(server, change, limit.Token); await probeStarted.Task.WaitAsync(limit.Token);
                if (!disconnect)
                {
                    await FixWire.Write(server, change with { Operation = "cancel", Run = null, Confirmed = false }, limit.Token);
                    var reply = await FixWire.Read<FixControlReply>(server, limit.Token);
                    Check(reply.State?.Active == First && f.Starts == 3 && f.MaxAlive == 1);
                }
                server.Dispose(); await serve.WaitAsync(limit.Token);
                Check(f.Alive == 0 && (!disconnect || f.Starts == 2));
            });
            await asyncTest("FIX pipe rejects unconfirmed command without effects", async () =>
            {
                var nonce = Guid.NewGuid().ToString("N"); using var server = FixPipeSecurity.Create(nonce);
                using var client = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce), PipeDirection.InOut, PipeOptions.Asynchronous);
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await Task.WhenAll(server.WaitForConnectionAsync(limit.Token), client.ConnectAsync(limit.Token));
                var f = new Fake(); using var s = Session(f); var serve = WindowsFixAgent.Serve(client, s);
                await FixWire.Write(server, Command("start", First, false), limit.Token);
                await serve.WaitAsync(limit.Token); Check(f.Starts == 0 && f.Stops == 0);
            });
            await asyncTest("FIX real local pipe peer IDs and ACL", async () =>
            {
                var nonce = Guid.NewGuid().ToString("N"); using var server = FixPipeSecurity.Create(nonce);
                using var client = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce), PipeDirection.InOut, PipeOptions.Asynchronous);
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await Task.WhenAll(server.WaitForConnectionAsync(limit.Token), client.ConnectAsync(limit.Token));
                FixPipeSecurity.VerifyClient(server, Environment.ProcessId); FixPipeSecurity.VerifyServer(client, Environment.ProcessId);
                await Reject(() => { FixPipeSecurity.VerifyClient(server, -1); return Task.CompletedTask; });
                var rules = server.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToArray();
                Check(rules.Any(r => r.AccessControlType == AccessControlType.Deny && ((SecurityIdentifier)r.IdentityReference).IsWellKnown(WellKnownSidType.NetworkSid)));
                using var identity = WindowsIdentity.GetCurrent();
                Check(rules.Any(r => r.AccessControlType == AccessControlType.Allow && r.IdentityReference == identity.User));
            });
            await asyncTest("FIX real pipe EOF releases only fake owned job", async () =>
            {
                var nonce = Guid.NewGuid().ToString("N"); using var server = FixPipeSecurity.Create(nonce);
                using var client = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce), PipeDirection.InOut, PipeOptions.Asynchronous);
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await Task.WhenAll(server.WaitForConnectionAsync(limit.Token), client.ConnectAsync(limit.Token));
                var f = new Fake(); using var s = Session(f); var serve = WindowsFixAgent.Serve(client, s);
                await FixWire.Write(server, Command("start", First), limit.Token);
                var reply = await FixWire.Read<FixControlReply>(server, limit.Token); Check(reply.State?.Running == true);
                server.Dispose(); await serve.WaitAsync(limit.Token); Check(f.Alive == 0 && f.Disposals == 1);
            });
            await asyncTest("FIX pipe rejects replay before another mutation", async () =>
            {
                var nonce = Guid.NewGuid().ToString("N"); using var server = FixPipeSecurity.Create(nonce);
                using var client = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce), PipeDirection.InOut, PipeOptions.Asynchronous);
                using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await Task.WhenAll(server.WaitForConnectionAsync(limit.Token), client.ConnectAsync(limit.Token));
                var f = new Fake(); using var s = Session(f); var serve = WindowsFixAgent.Serve(client, s);
                var request = Command("start", First); await FixWire.Write(server, request, limit.Token);
                _ = await FixWire.Read<FixControlReply>(server, limit.Token);
                await FixWire.Write(server, request, limit.Token); await serve.WaitAsync(limit.Token); Check(f.Starts == 1 && f.Alive == 0);
            });
    }
    private sealed class Fake : IFixRuntime
    {
        public bool External, Tunnel, StopFails, WaitProbe, Pass = true;
        public int Starts, Stops, Alive, MaxAlive, Probes, Disposals;
        public HashSet<int> FailStarts = [];
        public Action? OnProbe, OnStart;
        public bool HasExternalEngine => External;
        public bool HasConfoundingTunnel => Tunnel;
        public Task<IManagedProcess> Start(string id, bool gaming, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Starts++;
            if (FailStarts.Contains(Starts)) throw new IOException("fixture start failure");
            Check(Alive == 0); Alive++; MaxAlive = Math.Max(MaxAlive, Alive); OnStart?.Invoke();
            return Task.FromResult<IManagedProcess>(new Owned(this));
        }
        public async Task<FixProbe> Probe(CancellationToken ct)
        {
            Probes++; OnProbe?.Invoke();
            if (WaitProbe) await Task.Delay(Timeout.Infinite, ct);
            ct.ThrowIfCancellationRequested();
            return new FixProbe(true, new Dictionary<string,bool> { ["youtube"] = Pass, ["discord"] = Pass });
        }
        private sealed class Owned(Fake f) : IManagedProcess
        {
            private bool alive = true, disposed;
            public bool IsRunning => alive;
            public void Stop() { f.Stops++; if (f.StopFails) throw new IOException("fixture stop failure"); if (alive) { alive = false; f.Alive--; } }
            public void Dispose() { if (disposed) return; disposed = true; f.Disposals++; if (alive) { alive = false; f.Alive--; } }
        }
    }
}
