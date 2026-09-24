using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using EclipseConnect.Core;

internal static class ResilienceTests
{
    private static void Check(bool value) { if (!value) throw new Exception("Resilience assertion failed"); }
    private static async Task Reject(Func<Task> action)
    { try { await action(); } catch { return; } throw new Exception("Expected refusal"); }
    private static void Reject(Action action)
    { try { action(); } catch { return; } throw new Exception("Expected refusal"); }
    private static readonly Uri Target = new("https://chatgpt.com/");
    private static AwgRequest Start(AwgProfile profile, AwgProfileSlot slot, long sequence = 1) =>
        new(1, Guid.NewGuid().ToString("N"), "start", profile.Revision, true, sequence, slot);
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        foreach (var pair in new[] { (403, DiagnosticCode.HttpDenied), (401, DiagnosticCode.HttpAuthentication),
            (429, DiagnosticCode.HttpRateLimited), (503, DiagnosticCode.HttpServerError), (200, DiagnosticCode.HttpsResponse), (302, DiagnosticCode.HttpsResponse) })
            test("Diagnostics HTTP category " + pair.Item1, () =>
            { var r = Diagnostics.Classify("chatgpt.com", pair.Item1, null, "secret-response-body"); Check(r.Code == pair.Item2 && r.HttpStatus == pair.Item1 && !r.Detail.Contains("secret-response")); });
        test("Diagnostics 403 is not DNS and does not assert censorship", () =>
        { var r = Diagnostics.Classify("chatgpt.com", 403, null, ""); Check(r.Detail.Contains("не доказательство") && r.Detail.Contains("Причина не установлена")); });
        test("Diagnostics challenge takes precedence over 403", () => Check(Diagnostics.Classify("chatgpt.com", 403, "challenge", "").Code == DiagnosticCode.BrowserChallenge));
        foreach (var pair in new[] { (HttpRequestError.NameResolutionError, DiagnosticCode.DnsFailure),
            (HttpRequestError.ConnectionError, DiagnosticCode.ConnectionFailure), (HttpRequestError.SecureConnectionError, DiagnosticCode.TlsFailure),
            (HttpRequestError.ProxyTunnelError, DiagnosticCode.ProxyFailure), (HttpRequestError.HttpProtocolError, DiagnosticCode.Unknown) })
            await asyncTest("Diagnostics transport category " + pair.Item1, async () =>
            {
                var r = await Diagnostics.ProbeCore(Target, new Handler((_, _) => throw new HttpRequestException(pair.Item1, "secret-token-not-for-ui")), default);
                Check(r.Code == pair.Item2 && r.HttpStatus == null && !r.Detail.Contains("secret-token"));
            });
        test("Diagnostics socket refusal is not HTTP denial", () => Check(Diagnostics.ClassifyTransport("test", HttpRequestError.ConnectionError, SocketError.ConnectionRefused).Code == DiagnosticCode.ConnectionFailure));
        test("Diagnostics socket timeout distinguished", () => Check(Diagnostics.ClassifyTransport("test", HttpRequestError.ConnectionError, SocketError.TimedOut).Code == DiagnosticCode.Timeout));
        await asyncTest("Diagnostics header timeout bounded", async () =>
        {
            var r = await Diagnostics.ProbeCore(Target, new Handler(async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new Exception(); }), default, TimeSpan.FromMilliseconds(40));
            Check(r.Code == DiagnosticCode.Timeout && r.HttpStatus == null);
        });
        foreach (var status in new[] { HttpStatusCode.Forbidden, HttpStatusCode.OK })
            await asyncTest("Diagnostics slow body retains HTTP " + (int)status, async () =>
            {
                var r = await Diagnostics.ProbeCore(Target, new Handler((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StreamContent(new WaitingStream()) })), default,
                    bodyDeadline: TimeSpan.FromMilliseconds(40));
                Check(r.HttpStatus == (int)status && r.Code == (status == HttpStatusCode.Forbidden ? DiagnosticCode.HttpDenied : DiagnosticCode.IncompleteResponse));
            });
        await asyncTest("Diagnostics body cancellation propagates rather than false failure", async () =>
        {
            using var ct = new CancellationTokenSource();
            var waiting = new WaitingStream();
            var task = Diagnostics.ProbeCore(Target, new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {Content = new StreamContent(waiting)})), ct.Token);
            await waiting.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); ct.Cancel();
            try { await task; throw new Exception("Cancellation swallowed"); } catch (OperationCanceledException) { }
        });
        await asyncTest("Diagnostics bounded body and no credential headers", async () =>
        {
            // CountingStream keeps its count even after disposal.
            var counter = new CountingStream();
            await Diagnostics.ProbeCore(Target, new Handler((request, _) =>
            { Check(request.Headers.Authorization == null && !request.Headers.Contains("Cookie") && request.RequestUri == Target); return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {Content = new StreamContent(counter)}); }), default);
            Check(counter.Count == 32768);
        });
        foreach (var id in new[] { "whatsapp", "whatsapp-static" })
            await asyncTest("WhatsApp public root probe " + id, async () =>
            {
                var target = new Uri(ServiceCatalog.Get(id).Url); var calls = 0;
                var result = await Diagnostics.ProbeCore(target, new Handler((request, _) =>
                {
                    calls++;
                    Check(request.RequestUri == target && request.Headers.Authorization == null && !request.Headers.Contains("Cookie"));
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {Content = new StringContent("public test")});
                }), default);
                Check(calls == 1 && result.Target == target.Host && result.Code == DiagnosticCode.HttpsResponse);
                Check(ServiceCatalog.Get(id).Scope.Contains("приложения Windows"));
                await Reject(() => Diagnostics.ProbeCore(new Uri(target, "/private"), new Handler((_, _) =>
                { calls++; throw new Exception(); }), default));
                Check(calls == 1);
            });
        foreach (var uri in new[] { "https://chatgpt.com/backend-api/codex/responses", "https://chatgpt.com/?token=secret", "https://user@chatgpt.com/", "http://chatgpt.com/", "https://127.0.0.1/", "https://chatgpt.com:444/", "https://chatgpt.com.evil.invalid/", "https://chatgpt.com/#fragment" })
            await asyncTest("Diagnostics refuses non-catalog target " + new Uri(uri).Host + new Uri(uri).AbsolutePath, async () =>
            { var calls = 0; await Reject(() => Diagnostics.ProbeCore(new Uri(uri), new Handler((_, _) => {calls++; throw new Exception();}), default)); Check(calls == 0); });
        await asyncTest("Diagnostics cancellation before send never calls transport", async () =>
        { var calls = 0; using var ct = new CancellationTokenSource(); ct.Cancel(); await Reject(() => Diagnostics.ProbeCore(Target, new Handler((_, _) => {calls++; throw new Exception();}), ct.Token)); Check(calls == 0); });
        test("Diagnostics stale HTTP refusal cannot look fresh", () =>
        { var now=DateTimeOffset.Now; var r=Diagnostics.Classify("chatgpt.com",403,null,"") with {CheckedAt=now.AddMinutes(-6)}; Check(ServiceCatalog.Describe(ServiceCatalog.Get("chatgpt"),r,now).Label == "Нужна новая проверка"); });

        var primary = AwgProfile.Parse(AwgTests.Fixture);
        var reserve = AwgProfile.Parse(AwgTests.Fixture.Replace("vpn.example.net", "reserve.example.net"));
        test("Reserve cannot claim infrastructure independence", () =>
        { Check(AwgProfileSelection.ReserveHint(primary,null).Contains("не настроен")); Check(AwgProfileSelection.ReserveHint(primary,primary).Contains("копия")); Check(AwgProfileSelection.ReserveHint(primary,reserve).Contains("не доказывает")); Check(AwgProfileSelection.ReserveHint(primary,AwgProfile.Parse(AwgTests.Fixture.Replace(":4500",":4501"))).Contains("одинаковый адрес")); });
        test("Profile selection requires stopped and known state", () =>
        { Check(AwgProfileSelection.CanChange(AwgState.Off,false)); Check(!AwgProfileSelection.CanChange(new(true,false,"partial"),false)); Check(!AwgProfileSelection.CanChange(new(true,true,"running"),false)); Check(!AwgProfileSelection.CanChange(AwgState.Off,true)); });
        foreach(var slot in new[] { AwgProfileSlot.Primary, AwgProfileSlot.Reserve })
            test("Both slots retain selective routing " + slot, () =>
            { var config=MetaVpnPolicy.ServiceConfiguration(slot == AwgProfileSlot.Primary ? primary : reserve,DateTimeOffset.UtcNow); Check(!config.Contains("DNS =") && !config.Contains("0.0.0.0/0") && !config.Contains("::/0") && !config.Contains("chatgpt.com")); });
        await asyncTest("Reserve selection reaches only requested slot", async () =>
        {
            var runtime=new Fake(); var loads=new List<AwgProfileSlot>();
            await using var session=new AwgControlSession(runtime, slot => {loads.Add(slot);return slot == AwgProfileSlot.Primary ? primary : reserve;});
            await session.Execute(Start(reserve,AwgProfileSlot.Reserve),default);
            Check(loads.SequenceEqual(new[]{AwgProfileSlot.Reserve}) && runtime.Revision == reserve.Revision && runtime.Starts == 1);
        });
        await asyncTest("Missing reserve never falls back to primary", async () =>
        { var runtime=new Fake(); await using var session=new AwgControlSession(runtime, slot => slot == AwgProfileSlot.Primary ? primary : null); await Reject(() => session.Execute(Start(reserve,AwgProfileSlot.Reserve),default)); Check(runtime.Starts == 0); });
        await asyncTest("Changed reserve requires fresh confirmation", async () =>
        { var runtime=new Fake(); await using var session=new AwgControlSession(runtime, _ => reserve); await Reject(() => session.Execute(Start(primary,AwgProfileSlot.Reserve),default)); Check(runtime.Starts == 0); });
        await asyncTest("Active session refuses profile switching without touching runtime", async () =>
        { var runtime=new Fake(); await using var session=new AwgControlSession(runtime, slot => slot == AwgProfileSlot.Primary ? primary : reserve); await session.Execute(Start(primary,AwgProfileSlot.Primary),default); await Reject(() => session.Execute(Start(reserve,AwgProfileSlot.Reserve,2),default)); Check(runtime.Starts == 1 && runtime.Stops == 0 && runtime.Revision == primary.Revision); });
        await asyncTest("Stopped session can explicitly start reserve", async () =>
        {
            var runtime=new Fake(); await using var session=new AwgControlSession(runtime,slot=>slot == AwgProfileSlot.Primary ? primary : reserve);
            await session.Execute(Start(primary,AwgProfileSlot.Primary),default);
            await session.Execute(new(1,Guid.NewGuid().ToString("N"),"stop",null,true,2),default);
            await session.Execute(Start(reserve,AwgProfileSlot.Reserve,3),default);
            Check(runtime.Starts == 2 && runtime.Stops == 1 && runtime.Revision == reserve.Revision);
        });
        await asyncTest("Corrupt reserve never loads fallback", async () =>
        {
            var runtime=new Fake();var loads=new List<AwgProfileSlot>();
            await using var session=new AwgControlSession(runtime,slot=>{loads.Add(slot);throw new System.Security.Cryptography.CryptographicException("synthetic corruption");});
            await Reject(()=>session.Execute(Start(reserve,AwgProfileSlot.Reserve),default));
            Check(runtime.Starts == 0 && loads.SequenceEqual(new[]{AwgProfileSlot.Reserve}));
        });
        await asyncTest("Failed stop cannot be followed by reserve start", async () =>
        {
            var runtime=new Fake {StopFails=true};await using var session=new AwgControlSession(runtime,slot=>slot == AwgProfileSlot.Primary ? primary : reserve);
            await session.Execute(Start(primary,AwgProfileSlot.Primary),default);
            await Reject(()=>session.Execute(new(1,Guid.NewGuid().ToString("N"),"stop",null,true,2),default));
            await Reject(()=>session.Execute(Start(reserve,AwgProfileSlot.Reserve,3),default));
            Check(runtime.Starts == 1 && runtime.Revision == primary.Revision && session.State.Running);
        });
        foreach(var request in new[] {Start(primary,(AwgProfileSlot)99),new AwgRequest(1,Guid.NewGuid().ToString("N"),"stop",null,true,1,AwgProfileSlot.Reserve),new AwgRequest(1,Guid.NewGuid().ToString("N"),"status",null,false,1,AwgProfileSlot.Reserve)})
            test("IPC refuses invalid profile scope " + request.Operation, () => Reject(() => AwgControlPolicy.Validate(request)));
        test("IPC profile slot survives JSON without keys", () =>
        { var json=JsonSerializer.Serialize(Start(reserve,AwgProfileSlot.Reserve)); Check(JsonSerializer.Deserialize<AwgRequest>(json)?.ProfileSlot == AwgProfileSlot.Reserve && !json.Contains("PrivateKey")); });
        if(OperatingSystem.IsWindows()) StoreTests(test,primary,reserve);
    }
    [SupportedOSPlatform("windows")]
    private static void StoreTests(Action<string,Action> test,AwgProfile primary,AwgProfile reserve)
    {
        var storage=new Storage(Path.Combine(Path.GetTempPath(),"connect-reserve-tests-"+Guid.NewGuid().ToString("N")));
        var p=new AwgProfileStore(storage); var r=new AwgProfileStore(storage,AwgProfileSlot.Reserve);
        test("Reserve store does not create or replace primary", () => {r.Save(reserve,false);Check(!p.Exists && r.Load()?.Revision == reserve.Revision);p.Save(primary,false);Check(p.Load()?.Revision == primary.Revision);});
        test("Reserve replacement requires consent and isolated backup", () =>
        {var before=File.ReadAllBytes(storage.Resolve("profiles/awg-meta-current.dpapi"));var reserveBefore=File.ReadAllBytes(storage.Resolve("profiles/awg-meta-reserve.dpapi"));Reject(()=>r.Save(primary,false));r.Save(primary,true);Check(before.SequenceEqual(File.ReadAllBytes(storage.Resolve("profiles/awg-meta-current.dpapi"))) && reserveBefore.SequenceEqual(File.ReadAllBytes(storage.Resolve("profiles/awg-meta-reserve-previous.dpapi"))));});
        test("Reserve ciphertext cannot be substituted into primary", () =>
        {var primaryPath=storage.Resolve("profiles/awg-meta-current.dpapi");var before=File.ReadAllBytes(primaryPath);try{File.Copy(storage.Resolve("profiles/awg-meta-reserve.dpapi"),primaryPath,true);Reject(()=>p.Load());}finally{File.WriteAllBytes(primaryPath,before);}});
        test("Corrupt reserve leaves primary usable", () =>
        {File.WriteAllBytes(storage.Resolve("profiles/awg-meta-reserve.dpapi"),new byte[]{1,2,3});Reject(()=>r.Load());Check(p.Load()?.Revision == primary.Revision);});
        test("Unknown profile slot refuses storage access", () => Reject(()=>new AwgProfileStore(storage,(AwgProfileSlot)99).Load()));
    }
    private sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> action) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)=>action(request,ct); }
    private sealed class WaitingStream : MemoryStream
    {
        public TaskCompletionSource Entered {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {Entered.TrySetResult();await Task.Delay(Timeout.Infinite,cancellationToken);return 0;}
    }
    private sealed class CountingStream : MemoryStream
    {
        public int Count {get;private set;}
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {cancellationToken.ThrowIfCancellationRequested();buffer.Span.Fill((byte)'a');Count+=buffer.Length;return ValueTask.FromResult(buffer.Length);}
    }
    private sealed class Fake : IAwgRuntime
    {
        public int Starts,Stops; public bool Alive,StopFails; public string? Revision;
        public Task<AwgState> Status(CancellationToken ct)=>Task.FromResult(new AwgState(Alive,Alive,"fixture"));
        public Task<AwgState> Start(AwgProfile profile,CancellationToken ct){ct.ThrowIfCancellationRequested();Starts++;Alive=true;Revision=profile.Revision;return Status(ct);}
        public Task<AwgState> Stop(CancellationToken ct){if(StopFails)throw new IOException("fixture stop failed");Stops++;Alive=false;return Status(ct);}
        public ValueTask DisposeAsync(){Alive=false;return ValueTask.CompletedTask;}
    }
}
