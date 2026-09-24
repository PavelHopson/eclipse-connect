using EclipseConnect.Core;

internal static class LifecycleTests
{
    private static void Check(bool value) { if (!value) throw new Exception("Assertion failed"); }
    private static async Task Refused(Func<Task> action)
    {
        try { await action(); }
        catch (Exception e) when (e is InvalidOperationException or OperationCanceledException or IOException or InvalidDataException) { return; }
        throw new Exception("Expected a refusal");
    }
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        test("safety starts protected every session", () =>
        {
            var safety = new SessionSafety(); Check(safety.IsProtected); safety.AllowForSession(true);
            Check(!safety.IsProtected && new SessionSafety().IsProtected);
        });
        await asyncTest("unlock requires confirmation", () => Refused(() => { new SessionSafety().AllowForSession(false); return Task.CompletedTask; }));
        await asyncTest("protected launcher never reaches runtime", async () =>
        {
            var runtime = new FakeRuntime(); using var launcher = new Launcher(new SessionSafety(), runtime);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, default));
            Check(runtime.Prepares == 0 && runtime.Starts == 0);
        });
        await asyncTest("unconfirmed launch never inspects file", async () =>
        {
            var safety = Allowed(); var runtime = new FakeRuntime(); using var launcher = new Launcher(safety, runtime);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", false, default)); Check(runtime.Prepares == 0);
        });
        foreach (var blocked in new[] { "external", "port", "hash" })
        {
            await asyncTest("runtime refuses " + blocked, async () =>
            {
                var runtime = new FakeRuntime { External = blocked == "external", Port = blocked == "port", Hash = blocked != "hash" };
                using var launcher = new Launcher(Allowed(), runtime);
                await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, default));
                Check(runtime.Starts == 0 && runtime.DisposedPreparations == 1);
            });
        }
        await asyncTest("cancel before preflight has no side effects", async () =>
        {
            var runtime = new FakeRuntime(); using var launcher = new Launcher(Allowed(), runtime);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, new CancellationToken(true)));
            Check(runtime.Prepares == 0);
        });
        await asyncTest("relock during preflight revokes pending launch", async () =>
        {
            var safety = Allowed(); var runtime = new FakeRuntime { BeforeReturn = () => { safety.Protect(); return Task.CompletedTask; } };
            using var launcher = new Launcher(safety, runtime);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, default));
            Check(runtime.Starts == 0 && runtime.DisposedPreparations == 1);
        });
        await asyncTest("reunlock does not revive stale permit", async () =>
        {
            var safety = Allowed(); var runtime = new FakeRuntime { BeforeReturn = () => { safety.Protect(); safety.AllowForSession(true); return Task.CompletedTask; } };
            using var launcher = new Launcher(safety, runtime);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, default)); Check(runtime.Starts == 0);
        });
        await asyncTest("cancel after preflight prevents execution", async () =>
        {
            using var ct = new CancellationTokenSource();
            var runtime = new FakeRuntime { BeforeReturn = () => { ct.Cancel(); return Task.CompletedTask; } };
            using var launcher = new Launcher(Allowed(), runtime);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, ct.Token)); Check(runtime.Starts == 0);
        });
        await asyncTest("double launch is rejected not queued", async () =>
        {
            var wait = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var runtime = new FakeRuntime { BeforeReturn = () => wait.Task };
            using var launcher = new Launcher(Allowed(), runtime);
            var pending = launcher.StartTelegram("fixture.exe", "hash", true, default);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, default));
            wait.SetResult(); await pending;
            Check(runtime.Prepares == 1 && runtime.Starts == 1);
        });
        await asyncTest("dispose during preflight prevents launch", async () =>
        {
            var wait = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var runtime = new FakeRuntime { BeforeReturn = () => wait.Task };
            using var launcher = new Launcher(Allowed(), runtime);
            var pending = launcher.StartTelegram("fixture.exe", "hash", true, default);
            launcher.Dispose(); wait.SetResult(); await Refused(() => pending); Check(runtime.Starts == 0);
        });
        await asyncTest("failed start releases gate for retry", async () =>
        {
            var runtime = new FakeRuntime { FailStart = true }; using var launcher = new Launcher(Allowed(), runtime);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, default)); Check(!launcher.OwnsRunningProcess);
            runtime.FailStart = false; await launcher.StartTelegram("fixture.exe", "hash", true, default);
            Check(launcher.OwnsRunningProcess && runtime.DisposedPreparations == 2);
        });
        await asyncTest("existing owned instance cannot launch twice", async () =>
        {
            var runtime = new FakeRuntime(); using var launcher = new Launcher(Allowed(), runtime);
            await launcher.StartTelegram("fixture.exe", "hash", true, default);
            await Refused(() => launcher.StartTelegram("fixture.exe", "hash", true, default)); Check(runtime.Starts == 1);
        });
        await asyncTest("protected stop preserves own connection", async () =>
        {
            var safety = Allowed(); var runtime = new FakeRuntime(); using var launcher = new Launcher(safety, runtime);
            await launcher.StartTelegram("fixture.exe", "hash", true, default); safety.Protect();
            await Refused(() => { launcher.StopOwned(true); return Task.CompletedTask; }); Check(runtime.Process.Stops == 0);
        });
        await asyncTest("unconfirmed stop preserves own connection", async () =>
        {
            var runtime = new FakeRuntime(); using var launcher = new Launcher(Allowed(), runtime);
            await launcher.StartTelegram("fixture.exe", "hash", true, default);
            await Refused(() => { launcher.StopOwned(false); return Task.CompletedTask; }); Check(runtime.Process.Stops == 0);
        });
        await asyncTest("failed stop retains ownership for explicit retry", async () =>
        {
            var runtime = new FakeRuntime(); using var launcher = new Launcher(Allowed(), runtime);
            await launcher.StartTelegram("fixture.exe", "hash", true, default); runtime.Process.FailStop = true;
            await Refused(() => { launcher.StopOwned(true); return Task.CompletedTask; }); Check(launcher.OwnsRunningProcess);
            runtime.Process.FailStop = false; launcher.StopOwned(true);
            Check(!launcher.OwnsRunningProcess && runtime.Process.Disposals == 1);
        });
        await asyncTest("close releases handle without stopping process", async () =>
        {
            var runtime = new FakeRuntime(); var launcher = new Launcher(Allowed(), runtime);
            await launcher.StartTelegram("fixture.exe", "hash", true, default); launcher.Dispose(); launcher.Dispose();
            Check(runtime.Process.IsRunning && runtime.Process.Stops == 0 && runtime.Process.Disposals == 1);
        });
        await asyncTest("cannot stop external process without ownership", async () =>
        {
            var runtime = new FakeRuntime { External = true }; using var launcher = new Launcher(Allowed(), runtime);
            await Refused(() => { launcher.StopOwned(true); return Task.CompletedTask; }); Check(runtime.Process.Stops == 0);
        });
        test("close exits by default", () => Check(!WindowClosePolicy.HideInTray(false, true, false, false, false)));
        test("close to tray requires available tray", () => Check(!WindowClosePolicy.HideInTray(true, false, false, false, false)));
        test("explicit exit never hides", () => Check(!WindowClosePolicy.HideInTray(true, true, true, false, false)));
        test("Windows shutdown never hides", () => Check(!WindowClosePolicy.HideInTray(true, true, false, true, false)));
        test("QA never hides", () => Check(!WindowClosePolicy.HideInTray(true, true, false, false, true)));
        test("opted in close hides", () => Check(WindowClosePolicy.HideInTray(true, true, false, false, false)));

        var root = Path.Combine(Path.GetTempPath(), "connect-rollback-tests-" + Guid.NewGuid().ToString("N"));
        var storage = new Storage(root); var old = Path.Combine(root, "old.exe"); var next = Path.Combine(root, "next.exe");
        File.WriteAllText(old, "fixture-not-an-executable"); File.WriteAllText(next, "fixture-not-an-executable");
        var original = new AppSettings { TelegramPath = old, Theme = "Dark", CloseToTray = true };
        test("version selection commits rollback atomically", () =>
        {
            var selected = new VersionSelection(storage).Select(original, next);
            Check(selected.TelegramPath == next && selected.PreviousTelegramPath == old && original.TelegramPath == old);
            Check(storage.LoadSettings().PreviousTelegramPath == old);
        });
        test("repeat selection preserves rollback reference", () =>
        {
            var selected = storage.LoadSettings(); var repeated = new VersionSelection(storage).Select(selected, next);
            Check(repeated.PreviousTelegramPath == old);
        });
        await asyncTest("failed selection does not change memory or disk", async () =>
        {
            storage.SaveSettings(original);
            await Refused(() => { new VersionSelection(storage, _ => throw new IOException("disk unavailable")).Select(original, next); return Task.CompletedTask; });
            Check(original.TelegramPath == old && storage.LoadSettings().TelegramPath == old);
        });
        test("rollback restores only component choice", () =>
        {
            var select = new VersionSelection(storage); var selected = select.Select(original, next);
            var restored = select.Restore(selected);
            Check(restored.TelegramPath == old && restored.Theme == "Dark" && restored.CloseToTray && restored.PreviousTelegramPath == "");
            Check(selected.TelegramPath == next);
        });
        await asyncTest("failed rollback does not change current selection", async () =>
        {
            var selected = new VersionSelection(storage).Select(original, next);
            await Refused(() => { new VersionSelection(storage, _ => throw new IOException("disk unavailable")).Restore(selected); return Task.CompletedTask; });
            Check(selected.TelegramPath == next && storage.LoadSettings().TelegramPath == next);
        });
        await asyncTest("missing old executable leaves selection intact", async () =>
        {
            var selected = new AppSettings { TelegramPath = next, PreviousTelegramPath = Path.Combine(root, "missing.exe") };
            await Refused(() => { new VersionSelection(storage).Restore(selected); return Task.CompletedTask; });
            Check(selected.TelegramPath == next);
        });
        await asyncTest("script cannot be selected as executable", async () =>
        {
            await Refused(() => { new VersionSelection(storage).Select(original, Path.Combine(root, "script.bat")); return Task.CompletedTask; });
        });
        test("legacy rollback migrates without losing current preferences", () =>
        {
            storage.AtomicJson("settings-before-update.json", original);
            var restored = new VersionSelection(storage).Restore(new AppSettings { TelegramPath = next, Theme = "Light" });
            Check(restored.TelegramPath == old && restored.Theme == "Light");
        });
    }
    private static SessionSafety Allowed() { var safety = new SessionSafety(); safety.AllowForSession(true); return safety; }
    private sealed class FakeRuntime : IProcessRuntime
    {
        public bool External, Port, FailStart;
        public bool Hash = true;
        public int Prepares, Starts, DisposedPreparations;
        public Func<Task>? BeforeReturn;
        public FakeProcess Process = new();
        public async Task<ILaunchPreparation> Prepare(string path, string expectedHash, CancellationToken ct)
        { Prepares++; if (BeforeReturn != null) await BeforeReturn(); return new Preparation(this); }
        private sealed class Preparation(FakeRuntime owner) : ILaunchPreparation
        {
            public bool ExternalRunning => owner.External;
            public bool PortBusy => owner.Port;
            public bool HashKnown => owner.Hash;
            public IManagedProcess Start()
            {
                owner.Starts++; if (owner.FailStart) throw new IOException("simulated start failure");
                owner.Process = new(); return owner.Process;
            }
            public void Dispose() => owner.DisposedPreparations++;
        }
    }
    private sealed class FakeProcess : IManagedProcess
    {
        public bool IsRunning { get; private set; } = true;
        public bool FailStop;
        public int Stops, Disposals;
        public void Stop() { Stops++; if (FailStop) throw new IOException("simulated stop failure"); IsRunning = false; }
        public void Dispose() => Disposals++;
    }
}
