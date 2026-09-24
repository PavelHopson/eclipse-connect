using EclipseConnect.Core;

internal static class UiStateTests
{
    public static void Run(Action<string, Action> test, string tempRoot)
    {
        static void Check(bool value) { if (!value) throw new Exception("Assertion failed"); }
        static void Refused(Action action)
        {
            try { action(); }
            catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException) { return; }
            throw new Exception("Expected data refusal");
        }
        var now = DateTimeOffset.Parse("2026-09-08T09:00:00Z");
        var youtube = ServiceCatalog.Get("youtube");
        DiagnosticResult Result(string state, DateTimeOffset? at = null) => new("www.youtube.com", state, "test", at ?? now);
        test("health service catalog fixed and unique", () => Check(ServiceCatalog.All.Length == 9 &&
            ServiceCatalog.All.Select(s => s.Id).Distinct().Count() == 9 &&
            ServiceCatalog.Get("instagram").Url == "https://www.instagram.com/" &&
            ServiceCatalog.Get("rutracker").Url == "https://rutracker.org/" &&
            ServiceCatalog.Get("whatsapp").Url == "https://web.whatsapp.com/" &&
            ServiceCatalog.Get("whatsapp-static").Url == "https://static.whatsapp.net/"));
        test("running external component visible even when selected file missing", () => Check(new InstalledComponent(Catalog.Telegram, "", "", "", 2).State == "Работает отдельно"));
        test("FIX process observation does not claim ownership", () => Check(new InstalledComponent(Catalog.Fix, "", "", "", 1).State == "Обнаружен процесс FIX"));
        test("health rejects arbitrary target", () => Refused(() => ServiceCatalog.Get("https://127.0.0.1")));
        test("health unknown not green", () => Check(ServiceCatalog.Describe(youtube, null, now).Tone == "Muted"));
        test("health checking overrides old success", () => Check(ServiceCatalog.Describe(youtube, Result("HTTPS доступен"), now, true).Label == "Проверяется"));
        test("health HTTPS label never full app success", () => Check(ServiceCatalog.Describe(youtube, Result("HTTPS доступен"), now).Label == "HTTPS доступен"));
        test("health challenge is warning", () => Check(ServiceCatalog.Describe(youtube, Result("Проверка браузера"), now).Tone == "Warning"));
        test("health timeout is error", () => Check(ServiceCatalog.Describe(youtube, Result("Тайм-аут"), now).Tone == "Error"));
        test("health timestamp fresh at 299 seconds", () => Check(ServiceCatalog.Describe(youtube, Result("HTTPS доступен", now.AddSeconds(-299)), now).Tone == "Success"));
        test("health stale at five minutes", () => Check(ServiceCatalog.Describe(youtube, Result("HTTPS доступен", now.AddMinutes(-5)), now).Label == "Нужна новая проверка"));
        test("health future timestamp not trusted", () => Check(ServiceCatalog.Describe(youtube, Result("HTTPS доступен", now.AddSeconds(1)), now).Tone == "Muted"));
        test("health wrong service cannot turn green", () => Check(ServiceCatalog.Describe(youtube, new("discord.com", "HTTPS доступен", "", now), now).Label == "Не проверен"));
        test("window offscreen clamped", () =>
        { var b = WindowPlacement.Fit(9000, -9000, 1100, 700, new(0, 0, 1920, 1080)); Check(b.Left == 820 && b.Top == 0); });
        test("window handles bad numbers", () =>
        { var b = WindowPlacement.Fit(double.NaN, double.PositiveInfinity, double.NaN, double.NegativeInfinity, new(0, 0, 1920, 1080)); Check(double.IsFinite(b.Left + b.Top + b.Width + b.Height)); });
        test("window small display stays visible", () =>
        { var b = WindowPlacement.Fit(null, null, 1060, 760, new(0, 0, 740, 480)); Check(b.Width == 740 && b.Height == 480 && b.Left == 0 && b.Top == 0); });
        test("window negative monitor coordinates", () =>
        { var b = WindowPlacement.Fit(-1600, 10, 900, 600, new(-1920, 0, 1920, 1080)); Check(b.Left == -1600 && b.Top == 10); });
        test("settings preserve window and mode", () =>
        { var s = new Storage(Path.Combine(tempRoot, "ui-settings")); s.SaveSettings(new() { AdvancedMode = true, Left = 41, Top = 23, Width = 930 }); var v = s.LoadSettings(); Check(v.AdvancedMode && v.Left == 41 && v.Top == 23 && v.Width == 930); });

        FixSelectionResult Selection(string id, bool passes = true) => new(id, "result",
            [new FixTrial(id, passes, "two checks") { Checks = [
                new(true, new Dictionary<string, bool> { ["youtube"] = passes, ["discord"] = passes }, true),
                new(true, new Dictionary<string, bool> { ["youtube"] = passes, ["discord"] = passes }, true)] }]);
        var store = new Storage(Path.Combine(tempRoot, "fix-choice"));
        var choices = new FixChoiceStore(store);
        test("FIX choice empty has no fabricated good profile", () => Check(choices.Read().Selected == null));
        test("FIX choice accepts verified selection", () =>
        { var s = choices.Accept(Selection("ultimate"), "all", now); Check(s.Selected?.ProfileId == "ultimate" && s.Selected.CheckedAt == now && s.Previous == null); });
        test("FIX failed selection preserves file", () =>
        { var before = File.ReadAllText(store.Resolve("profiles/fix-state.json")); choices.Accept(new(null, "failed", []), "all", now); Check(before == File.ReadAllText(store.Resolve("profiles/fix-state.json"))); });
        test("FIX unverifiable success rejected", () => Refused(() => choices.Accept(new("general", "", [new("general", true, "fake")]), "all", now)));
        test("FIX false check rejected", () => Refused(() => choices.Accept(Selection("general", false), "all", now)));
        test("FIX target mismatch rejected", () => Refused(() => choices.Accept(Selection("youtube"), "all", now)));
        test("FIX previous choice retained", () =>
        { var s = choices.Accept(Selection("general"), "all", now); Check(s.Previous?.ProfileId == "ultimate"); });
        test("FIX duplicate selection preserves rollback", () =>
        { var s = choices.Accept(Selection("general"), "all", now.AddMinutes(1)); Check(s.Previous?.ProfileId == "ultimate"); });
        test("FIX write failure leaves selection unchanged", () =>
        { var before = File.ReadAllText(store.Resolve("profiles/fix-state.json")); Refused(() => new FixChoiceStore(store, _ => throw new IOException("disk")).Accept(Selection("ultimate"), "all", now)); Check(before == File.ReadAllText(store.Resolve("profiles/fix-state.json"))); });
        test("FIX restore changes data only", () =>
        { var s = choices.Restore(); Check(s.Selected?.ProfileId == "ultimate" && s.Previous == null); });
        test("FIX second restore refused", () => Refused(() => choices.Restore()));
        test("FIX corrupt choice never overwritten", () =>
        { store.AtomicJson("profiles/fix-state.json", new { Schema = 88 }); var before = File.ReadAllText(store.Resolve("profiles/fix-state.json")); Refused(() => choices.Accept(Selection("general"), "all", now)); Check(before == File.ReadAllText(store.Resolve("profiles/fix-state.json"))); });
        test("FIX malicious profile rejected on read", () =>
        { store.AtomicJson("profiles/fix-state.json", new FixChoiceState(1, new("../evil.bat", "all", now), null)); Refused(() => choices.Read()); });
        test("FIX unknown target rejected on read", () =>
        { store.AtomicJson("profiles/fix-state.json", new FixChoiceState(1, new("ultimate", "unknown", now), null)); Refused(() => choices.Read()); });
        test("FIX bounded state parsing", () =>
        { File.WriteAllText(store.Resolve("profiles/fix-state.json"), new string(' ', 65537)); Refused(() => choices.Read()); });
        test("FIX legacy migration does not invent verification date", () =>
        { var legacy = new Storage(Path.Combine(tempRoot, "fix-legacy")); legacy.AtomicJson("fix-selection.json", Selection("ultimate")); var old = new FixChoiceStore(legacy).Read(); Check(old.Selected?.CheckedAt == null && old.Selected?.Target == "legacy" && !File.Exists(legacy.Resolve("profiles/fix-state.json"))); });
    }
}
