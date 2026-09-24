using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using EclipseConnect.Core;

namespace EclipseConnect.App;

public partial class MainWindow
{
    // In-process WPF layout tests of our own views, not desktop input automation.
    public async Task<int> RunRenderTests()
    {
        if (!qa) throw new InvalidOperationException("Render tests require an isolated QA session.");
        var evidence = new List<object>(); var errors = new List<string>();
        try
        {
            foreach (var theme in new[] { "Light", "Dark" })
            foreach (var size in new[] { (1180d, 800d), (820d, 570d) })
            foreach (var scenario in new[] { "overview", "components", "diagnostics", "updates", "settings", "journal", "fix",
                "components-protected", "components-allowed", "components-external", "diagnostics-results", "overview-loading", "overview-error",
                "recovery", "service", "service-whatsapp", "overview-ready", "overview-stale", "overview-partial", "overview-advanced",
                "fix-ready", "fix-running", "fix-external", "fix-restored", "fix-error", "service-instagram",
                "vpn", "vpn-ready", "vpn-protected", "vpn-running", "vpn-error", "vpn-loading", "vpn-unknown", "vpn-corrupt", "vpn-routes-expired", "vpn-missingfix", "vpn-partial",
                "vpn-reserve", "vpn-reserve-empty", "vpn-http-denied", "vpn-dns-error", "vpn-tls-error", "vpn-stale", "vpn-whatsapp-timeout" })
            {
                var view = scenario.Split('-')[0];
                safety.Protect(); installed.Clear(); results.Clear(); checkingServices.Clear(); settings.AdvancedMode = false; selectedService = "youtube";
                StatusText.Text = "Готово. Ничего не запускается автоматически.";
                qaFixState = null; fixTrials = [];
                qaVpnState = null; qaVpnProfile = false; qaVpnError = null; vpnCheckedAt = null; qaVpnRoutesExpired = scenario == "vpn-routes-expired";
                qaVpnFixMissing = scenario == "vpn-missingfix";
                qaVpnReserve = scenario == "vpn-reserve";
                selectedVpnSlot = scenario.StartsWith("vpn-reserve") ? AwgProfileSlot.Reserve : AwgProfileSlot.Primary;
                if (scenario.StartsWith("vpn-"))
                {
                    qaVpnProfile = scenario is not ("vpn-corrupt" or "vpn-reserve-empty");
                    if (scenario != "vpn-protected") safety.AllowForSession(true);
                    qaVpnState = new(scenario is "vpn-running" or "vpn-unknown" or "vpn-partial", scenario == "vpn-running", scenario switch
                    {
                        "vpn-error" => "Сервер не подтвердил соединение. Пробное подключение остановлено.",
                        "vpn-unknown" => "Служба запущена, но свежего подтверждения VPN-сервера нет.",
                        "vpn-running" => "VPN подтверждён, FIX работает (имитация).",
                        "vpn-partial" => "VPN или FIX не подтверждён. Отключите подключение перед повторным запуском.",
                        _ => "Тестовый профиль. Сеть не переключается."
                    });
                    if (scenario == "vpn-corrupt") qaVpnError = "Не удалось прочитать VPN-профиль. Исходный файл не изменён.";
                    if (scenario == "vpn-http-denied") results.Add(Diagnostics.Classify("chatgpt.com", 403, null, ""));
                    if (scenario == "vpn-dns-error") results.Add(Diagnostics.ClassifyTransport("chatgpt.com", System.Net.Http.HttpRequestError.NameResolutionError));
                    if (scenario == "vpn-tls-error") results.Add(Diagnostics.ClassifyTransport("chatgpt.com", System.Net.Http.HttpRequestError.SecureConnectionError));
                    if (scenario == "vpn-stale") results.Add(Diagnostics.Classify("chatgpt.com", 200, null, "") with { CheckedAt = DateTimeOffset.Now.AddMinutes(-6) });
                    if (scenario == "vpn-whatsapp-timeout")
                    {
                        results.Add(new("web.whatsapp.com", "Тайм-аут", "Нет ответа от веб-узла WhatsApp.", DateTimeOffset.Now, DiagnosticCode.Timeout));
                        results.Add(new("static.whatsapp.net", "Тайм-аут", "Нет ответа от узла файлов WhatsApp.", DateTimeOffset.Now, DiagnosticCode.Timeout));
                    }
                }
                if (scenario.StartsWith("fix-"))
                {
                    var run = new FixRun("ultimate", false, "youtube");
                    var active = scenario is "fix-running" or "fix-restored";
                    qaFixState = new(active, active ? run : null, active ? new("general", false, "youtube") : null,
                        scenario == "fix-external", scenario switch
                        {
                            "fix-restored" => "Переключение не завершено. Предыдущий FIX снова запущен; доступ требует проверки.",
                            "fix-error" => "Не удалось вернуть предыдущий FIX. Проверьте подключение вручную.",
                            _ => "Тестовые данные. Реальный FIX не запускается."
                        }, []);
                }
                if (scenario == "service-instagram") selectedService = "instagram";
                if (scenario == "service-whatsapp") selectedService = "whatsapp";
                WorkProgress.Visibility = Visibility.Collapsed; CancelButton.Visibility = Visibility.Collapsed;
                if (scenario.StartsWith("components-"))
                    installed[Catalog.Telegram.Id] = new InstalledComponent(Catalog.Telegram, @"C:\QA\TgWsProxy_windows.exe", new string('a', 64), "v1.10.1", scenario.EndsWith("external") ? 2 : 0);
                if (scenario == "components-allowed") safety.AllowForSession(true);
                if (scenario == "diagnostics-results")
                {
                    results.Add(Diagnostics.Classify("chatgpt.com (тестовые данные)", 403, "challenge", ""));
                    results.Add(Diagnostics.Classify("youtube.com (тестовые данные)", 200, null, ""));
                }
                if (scenario is "overview-ready" or "overview-stale" or "overview-partial" or "service")
                {
                    var stamp = scenario == "overview-stale" ? DateTimeOffset.Now.AddMinutes(-6) : DateTimeOffset.Now;
                    foreach (var service in ServiceCatalog.All)
                        results.Add(new(new Uri(service.Url).Host, service.Id == "chatgpt" ? "Проверка браузера" : "HTTPS доступен", "Тестовые данные QA. Полная работа приложения не проверена.", stamp));
                    installed["telegram"] = new(Catalog.Telegram, @"C:\QA\TgWsProxy_windows.exe", new string('a', 64), "v1.10.2", 2);
                    installed["fix"] = new(Catalog.Fix, @"C:\QA\winws.exe", new string('b', 64), "v72.2", 1);
                }
                if (scenario == "overview-advanced") settings.AdvancedMode = true;
                if (scenario == "overview-partial") checkingServices.Add("youtube");
                settings.Theme = theme; ApplyTheme(); Width = size.Item1; Height = size.Item2;
                Navigate(view); UpdateLayout();
                if (scenario is "overview-loading" or "vpn-loading")
                {
                    PageContent.IsEnabled = PageTools.IsEnabled = false; WorkProgress.Visibility = Visibility.Visible; WorkProgress.IsIndeterminate = true;
                    CancelButton.Visibility = Visibility.Visible; StatusText.Text = "Проверка интерфейса (имитация)...";
                }
                if (scenario == "overview-error") StatusText.Text = "Не выполнено: тестовая ошибка сохранения. Выбранная версия не изменена.";
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                var issues = new List<string>();
                if (VersionLabel.Text != "Версия " + typeof(MainWindow).Assembly.GetName().Version?.ToString(3))
                    issues.Add("UI version differs from assembly");
                // ComboBox templates contain internal glyph buttons named by the parent control.
                var buttons = Descendants(PageContent).Concat(Descendants(PageTools)).OfType<Button>().Where(b => b.Content is string).ToList();
                foreach (var button in buttons)
                {
                    if (button.ActualWidth > PageContent.ActualWidth + 2) issues.Add("Button exceeds content width: " + button.Content);
                    if (string.IsNullOrWhiteSpace(AutomationProperties.GetName(button))) issues.Add("Button lacks accessible name");
                    if (!button.Focusable) issues.Add("Button not keyboard focusable");
                }
                if (scenario.StartsWith("components-") && buttons.Any(b => (b.Content.ToString()!.StartsWith("Запустить Telegram") || b.Content.ToString()!.StartsWith("Остановить запущенный")) && b.IsEnabled))
                    issues.Add("QA exposes real lifecycle controls");
                if (view == "fix" && buttons.Any(b => new[] { "Подключить управление", "Обновить состояние", "Запустить FIX",
                    "Остановить FIX", "Подобрать профиль", "Применить с возвратом", "Вернуть прошлый запуск" }.Contains(b.Content.ToString()) && b.IsEnabled))
                    issues.Add("QA exposes real FIX control");
                if (view == "fix")
                {
                    var primary = qaFixState == null ? "Подключить управление" : qaFixState.Running ? "Применить с возвратом" : "Запустить FIX";
                    if (!PageTools.Children.OfType<Button>().Any(b => b.Content.ToString() == primary))
                        issues.Add("FIX primary action is not pinned");
                }
                if (view == "vpn")
                {
                    if (buttons.Any(b => new[] { "Подключить VPN + FIX", "Отключить VPN + FIX", "Выбрать FIX", "Импортировать .conf", "Заменить профиль", "Разрешить управление", "Обновить состояние", "Проверить доступ", "Добавить резервный .conf" }.Contains(b.Content.ToString()) && b.IsEnabled))
                        issues.Add("QA exposes real VPN operations");
                    var main = qaVpnState?.Running == true ? "Отключить VPN + FIX" : qaVpnProfile ? "Подключить VPN + FIX" : qaVpnError == null ? "Импортировать .conf" : "Заменить профиль";
                    if (!PageTools.Children.OfType<Button>().Any(b => b.Content.ToString() == main)) issues.Add("VPN primary action not pinned");
                    var descriptions = string.Join("\n", Descendants(PageContent).OfType<TextBlock>().Select(t => t.Text));
                    if (!descriptions.Contains("Остальной трафик, включая Codex") || !descriptions.Contains("Facebook и WhatsApp") || !descriptions.Contains("YouTube и RuTracker"))
                        issues.Add("Selective VPN scope is not visible");
                    if (scenario == "vpn-routes-expired" && !descriptions.Contains("Список сетей устарел"))
                        issues.Add("Expired route list is not explained");
                    if (scenario == "vpn-missingfix" && !descriptions.Contains("Не найден FIX")) issues.Add("Missing FIX is not explained");
                    if (scenario == "vpn-partial" && !descriptions.Contains("Соединение не подтверждено")) issues.Add("Partial connection shows false success");
                    var selector = Descendants(PageContent).OfType<ComboBox>().Single();
                    if (!PageTools.Children.OfType<Button>().Any(b => b.Content.ToString() == "Проверить доступ")) issues.Add("Access check is not pinned");
                    if (selector.IsEnabled || string.IsNullOrWhiteSpace(AutomationProperties.GetName(selector))) issues.Add("Profile selector lacks QA/accessibility guard");
                    if (scenario.StartsWith("vpn-reserve") && !descriptions.Contains("Профиль: Резервный")) issues.Add("Reserve selection is not visible");
                    if (scenario == "vpn-http-denied" && !descriptions.Contains("Доступ отклонён (403)")) issues.Add("403 classification missing");
                    if (scenario == "vpn-dns-error" && !descriptions.Contains("Ошибка DNS")) issues.Add("DNS classification missing");
                    if (scenario == "vpn-tls-error" && !descriptions.Contains("Ошибка TLS")) issues.Add("TLS classification missing");
                    if (scenario == "vpn-stale" && !descriptions.Contains("Нужна новая проверка")) issues.Add("Stale VPN check displayed as fresh");
                    if (scenario == "vpn-whatsapp-timeout" && (!descriptions.Contains("WhatsApp: Тайм-аут") ||
                        !descriptions.Contains("WhatsApp файлы: Тайм-аут") || !descriptions.Contains("Подключите VPN + FIX кнопкой сверху")))
                        issues.Add("WhatsApp failure or next action missing");
                }
                if (string.IsNullOrWhiteSpace(AutomationProperties.GetName(SafetyButton))) issues.Add("Safety switch lacks accessible name");
                if (PageTitle.ActualHeight > 80) issues.Add("Header exceeds two lines");
                if (view == "overview")
                {
                    if (serviceLabels.Count != ServiceCatalog.All.Length) issues.Add("Missing service rows");
                    if (!PageTools.Children.OfType<Button>().Any(b => b.Content.ToString() == "Проверить сервисы")) issues.Add("Missing primary check action");
                    if (scenario == "overview-stale" && serviceLabels.Values.Any(v => v.State.Text != "Нужна новая проверка")) issues.Add("Stale result shown as fresh");
                    if (scenario == "overview-partial" && serviceLabels["youtube"].State.Text != "Проверяется") issues.Add("Missing per-service loading state");
                    if (!settings.AdvancedMode && navButtons["journal"].Visibility != Visibility.Collapsed) issues.Add("Advanced navigation leaks into normal mode");
                }
                if (view == "service" && !buttons.Any(b => b.Content.ToString() == "Назад")) issues.Add("Missing back action");
                if (scenario == "service-whatsapp" && !buttons.Any(b => b.Content.ToString() == "Найти адрес и временно применить")) issues.Add("WhatsApp detail lacks manual hosts action");
                var path = storage.Resolve($"renders/{theme}-{(int)size.Item1}-{scenario}.png");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var bitmap = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32);
                bitmap.Render(this);
                var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                using (var file = File.Create(path)) encoder.Save(file);
                if (scenario is "vpn-http-denied" or "vpn-reserve-empty")
                {
                    PageScroll.ScrollToBottom(); UpdateLayout();
                    var bottom = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32); bottom.Render(this);
                    var bottomEncoder = new PngBitmapEncoder(); bottomEncoder.Frames.Add(BitmapFrame.Create(bottom));
                    using var bottomFile = File.Create(storage.Resolve($"renders/{theme}-{(int)size.Item1}-{scenario}-bottom.png")); bottomEncoder.Save(bottomFile);
                }
                var key = $"{theme}-{size.Item1}-{scenario}";
                errors.AddRange(issues.Select(issue => key + ": " + issue));
                evidence.Add(new { View = view, Scenario = scenario, Theme = theme, Width = ActualWidth, Height = ActualHeight, Buttons = buttons.Count, Issues = issues });
            }
            foreach (var theme in new[] { "Light", "Dark" })
            foreach (var size in new[] { (820d, 710d), (640d, 520d) })
            foreach (var populated in new[] { false, true })
            {
                settings.Theme = theme; ApplyTheme();
                var fix = new FixWindow(storage, "", true, theme == "Dark") { Width = size.Item1, Height = size.Item2 };
                if (populated)
                {
                    FixCheck Check(bool value) => new(true, new Dictionary<string, bool> { ["youtube"] = value, ["discord"] = value }, true);
                    fix.SetQaTrials([new FixTrial("ultimate", false, "") { Checks = [Check(false), Check(true)] },
                        new FixTrial("general", true, "") { Checks = [Check(true), Check(true)] }]);
                }
                fix.Show(); fix.UpdateLayout();
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                var issues = new List<string>();
                var buttons = Descendants(fix).OfType<Button>().Where(b => b.Content is string).ToList();
                foreach (var button in buttons)
                {
                    if (string.IsNullOrWhiteSpace(AutomationProperties.GetName(button))) issues.Add("FIX button lacks name");
                    if (button.Content.ToString() != "Выйти" && button.IsEnabled) issues.Add("FIX QA exposes process control");
                    if (button.ActualWidth > size.Item1 - 40) issues.Add("FIX button exceeds viewport");
                }
                var image = new RenderTargetBitmap((int)fix.ActualWidth, (int)fix.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                image.Render(fix); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
                using (var file = File.Create(storage.Resolve($"renders/{theme}-{(int)size.Item1}-fix-controller{(populated ? "-results" : "")}.png"))) encoder.Save(file);
                errors.AddRange(issues.Select(i => theme + " FIX: " + i));
                evidence.Add(new { View = "fix-controller", Scenario = populated ? "fix-controller-results" : "fix-controller-qa", Theme = theme, Width = size.Item1, Height = size.Item2, Buttons = buttons.Count, Issues = issues });
                fix.Close();
            }
            // Exercise our own routed handlers. QA denies network/process backends.
            settings.AdvancedMode = false; Navigate("overview");
            ModeButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (!settings.AdvancedMode || navButtons["components"].Visibility != Visibility.Visible) errors.Add("Mode toggle does not expose advanced navigation");
            ModeButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (settings.AdvancedMode || navButtons["components"].Visibility != Visibility.Collapsed) errors.Add("Mode toggle does not restore normal navigation");
            await CheckServices("youtube");
            if (!StatusText.Text.StartsWith("QA:")) errors.Add("QA network action not refused");
            selectedService = "youtube"; await OpenService();
            var back = PageTools.Children.OfType<Button>().Single(b => b.Content.ToString() == "Назад");
            back.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            if (page != "overview") errors.Add("Service back action failed");
            evidence.Add(new { View = "interaction", Scenario = "mode-toggle-service-back-qa-network-denial" });
            results.Clear(); results.Add(Diagnostics.Classify("chatgpt.com", 200, null, ""));
            selectedVpnSlot = AwgProfileSlot.Primary; Navigate("vpn");
            results[0] = results[0] with { CheckedAt = DateTimeOffset.Now.AddMinutes(-6) };
            RefreshServiceLabels();
            if (!vpnServiceLabels["chatgpt"].State.Text.Contains("Нужна новая проверка")) errors.Add("VPN freshness timer path does not invalidate stale success");
            evidence.Add(new { View = "interaction", Scenario = "vpn-freshness-without-navigation-or-network" });
            foreach (var theme in new[] { "Light", "Dark" })
            {
                settings.Theme = theme; ApplyTheme(); Width = 1060; Height = 760; Navigate("overview"); UpdateLayout();
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                var image = new RenderTargetBitmap((int)(ActualWidth * 1.5), (int)(ActualHeight * 1.5), 144, 144, PixelFormats.Pbgra32);
                image.Render(this); var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
                using (var file = File.Create(storage.Resolve($"renders/{theme}-1060-overview-144dpi.png"))) encoder.Save(file);
                evidence.Add(new { View = "overview", Scenario = "144dpi-render", Theme = theme, Width = 1060, Height = 760 });
            }
        }
        catch (Exception error) { errors.Add(error.ToString()); }
        storage.AtomicJson("render-results.json", new { Cases = evidence, Errors = errors, Mode = "Offline QA: HTTP and process backends deny operations; no real tray instantiated" });
        return errors.Count == 0 ? 0 : 1;
    }
    private static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        for (var i=0; i<VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i); yield return child;
            foreach (var nested in Descendants(child)) yield return nested;
        }
    }
}
