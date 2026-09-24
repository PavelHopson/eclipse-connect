using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using EclipseConnect.Core;

namespace EclipseConnect.App;

public partial class MainWindow : Window
{
    private readonly Storage storage;
    private readonly Updates updates;
    private readonly SessionSafety safety = new();
    private readonly Launcher launcher;
    private readonly bool qa;
    private AppSettings settings;
    private readonly Dictionary<string, InstalledComponent> installed = [];
    private readonly Dictionary<string, ReleaseInfo> releases = [];
    private readonly Dictionary<string, string> updateStates = [];
    private readonly List<DiagnosticResult> results = [];
    private FixPlan? fixPlan;
    private CancellationTokenSource? work;
    private string page = "overview";
    private readonly Dictionary<string, Button> navButtons = [];
    private bool closing;
    private string selectedService = "telegram";
    private readonly HashSet<string> checkingServices = [];
    private readonly Dictionary<string, (TextBlock State, TextBlock Time)> serviceLabels = [];
    private readonly System.Windows.Threading.DispatcherTimer freshnessTimer = new() { Interval = TimeSpan.FromSeconds(30) };
    private DateTimeOffset? inventoryCheckedAt;
    public MainWindow(Storage storage, bool qa)
    {
        this.storage = storage; this.qa = qa;
        updates = qa ? new(storage, new QaDenyHttp()) : new(storage);
        launcher = new(safety, qa ? new QaDenyRuntime() : null);
        string? settingsError = null;
        try { settings = storage.LoadSettings(); }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException)
        { storage.PreserveInvalidSettings(); settings = new(); settingsError = "Настройки не прочитаны. Исходный файл сохранён в recovery. " + e.Message; }
        InitializeComponent();
        VersionLabel.Text = "Версия " + typeof(MainWindow).Assembly.GetName().Version?.ToString(3);
        InitializeTray();
        MinWidth = Math.Min(820, SystemParameters.WorkArea.Width); MinHeight = Math.Min(570, SystemParameters.WorkArea.Height);
        var area = SystemParameters.WorkArea;
        var bounds = WindowPlacement.Fit(settings.Left, settings.Top, settings.Width, settings.Height, new(area.Left, area.Top, area.Width, area.Height));
        WindowStartupLocation = WindowStartupLocation.Manual;
        Width = bounds.Width; Height = bounds.Height; Left = bounds.Left; Top = bounds.Top;
        ApplyTheme();
        foreach (var entry in new[] { ("overview", "\uE80F", "Обзор"), ("vpn", "\uE701", "VPN"), ("components", "\uE713", "Компоненты"),
            ("diagnostics", "\uE9D9", "Проверка доступа"), ("updates", "\uE895", "Обновления"),
            ("fix", "\uE703", "FIX / Подбор"), ("recovery", "\uE777", "Восстановление"),
            ("settings", "\uE115", "Настройки"), ("journal", "\uE81C", "Журнал") })
        {
            var label = new StackPanel { Orientation = Orientation.Horizontal };
            label.Children.Add(new TextBlock { Text = entry.Item2, FontFamily = new FontFamily("Segoe MDL2 Assets"), Margin = new(0,0,12,0), VerticalAlignment = VerticalAlignment.Center });
            label.Children.Add(new TextBlock { Text = entry.Item3 });
            var button = new Button { Content = label, HorizontalContentAlignment = HorizontalAlignment.Left, Padding = new(10,9,6,9), BorderThickness = new(0), FontSize = 13 };
            button.SetResourceReference(ForegroundProperty, "TextBrush");
            AutomationProperties.SetName(button, entry.Item3);
            button.Click += (_, _) => Navigate(entry.Item1);
            navButtons[entry.Item1] = button; Navigation.Children.Add(button);
        }
        Loaded += async (_, _) =>
        {
            if (!qa) await Run("Обнаружение компонентов", async ct => { Inventory.Discover(settings); await RefreshInventory(ct); });
            if (!qa && settings.CheckUpdatesOnStart && !closing) await CheckUpdates();
            if (settingsError != null) StatusText.Text = Redactor.Sanitize(settingsError);
        };
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape && work != null) { work.Cancel(); e.Handled = true; }
            if (e.Key == Key.R && Keyboard.Modifiers == ModifierKeys.Control && work == null)
            { _ = RunAccessCheck(); e.Handled = true; }
        };
        freshnessTimer.Tick += (_, _) => { if (IsVisible && work == null) RefreshServiceLabels(); };
        if (!qa) freshnessTimer.Start();
        Closing += (_, e) =>
        {
            if (WindowClosePolicy.HideInTray(settings.CloseToTray, tray != null, explicitExit, sessionEnding, qa))
            { e.Cancel = true; HideWindowToTray(); return; }
            if (!qa && !sessionEnding && (fixLink?.Connected == true && (fixLink.LastState?.Running == true || work != null) ||
                vpnLink?.Connected == true && (vpnLink.LastState?.Running == true || work != null)) &&
                MessageBox.Show(this, "Выход остановит FIX и VPN, которыми управляет это окно. Закрыть Connect? Для сохранения подключения выберите «Нет» и сверните в трей.",
                    "Остановить подключения и выйти?", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            { e.Cancel = true; return; }
            closing = true; work?.Cancel(); freshnessTimer.Stop();
            // QA sessions never alter real user preferences.
            if (!qa)
            {
                var saved = WindowState == WindowState.Normal ? new Rect(Left, Top, ActualWidth, ActualHeight) : RestoreBounds;
                settings.Width = saved.Width; settings.Height = saved.Height; settings.Left = saved.Left; settings.Top = saved.Top;
                try { storage.SaveSettings(settings); } catch (IOException) { }
            }
            fixLink?.Dispose(); vpnLink?.Dispose(); DisposeTray(); launcher.Dispose(); updates.Dispose();
        };
        Navigate("overview");
    }
    private void ApplyTheme()
    {
        var dark = settings.Theme == "Dark" || (settings.Theme == "System" &&
            Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1) is int light && light == 0);
        // Theme reads are local only. No OS or browser settings are written.
        // WPF exposes Fluent's runtime theme switch as preview even on .NET 10.
        // This is the only opt-in; all other compiler diagnostics remain errors.
#pragma warning disable WPF0001
        Application.Current.ThemeMode = settings.Theme == "Dark" ? ThemeMode.Dark : settings.Theme == "Light" ? ThemeMode.Light : ThemeMode.System;
#pragma warning restore WPF0001
        Brand.Apply(this, dark);
    }
    private void Navigate(string target)
    {
        RefreshSafety();
        page = target;
        if (page is "components" or "journal") settings.AdvancedMode = true;
        ModeButton.Content = settings.AdvancedMode ? "Обычный режим" : "Расширенный режим";
        foreach (var pair in navButtons)
        {
            pair.Value.Visibility = settings.AdvancedMode || pair.Key is not ("components" or "journal") ? Visibility.Visible : Visibility.Collapsed;
            pair.Value.Background = pair.Key == page ? (Brush)Resources["SoftBrush"] : Brushes.Transparent;
            pair.Value.FontWeight = pair.Key == page ? FontWeights.SemiBold : FontWeights.Normal;
        }
        serviceLabels.Clear(); vpnServiceLabels.Clear(); PageTools.Children.Clear(); PageContent.Children.Clear(); PageScroll.ScrollToTop();
        switch (page)
        {
            case "overview": ShowOverview(); break;
            case "components": ShowComponents(); break;
            case "diagnostics": ShowDiagnostics(); break;
            case "updates": ShowUpdates(); break;
            case "fix": ShowFix(); break;
            case "vpn": ShowVpn(); break;
            case "settings": ShowSettings(); break;
            case "journal": ShowJournal(); break;
            case "service": ShowService(); break;
            case "recovery": ShowRecovery(); break;
        }
        PageContent.IsEnabled = PageTools.IsEnabled = work == null;
    }
    private void Header(string title, string description) { PageTitle.Text = title; PageSubtitle.Text = description; }
    private static TextBlock Text(string value, double size = 14, bool strong = false) => new()
    { Text = value, FontSize = size, FontWeight = strong ? FontWeights.SemiBold : FontWeights.Normal, TextWrapping = TextWrapping.Wrap, Margin = new(0,0,0,8) };
    private TextBlock Muted(string value)
    { var text = Text(value, 13); text.SetResourceReference(TextBlock.ForegroundProperty, "MutedBrush"); return text; }
    private Button Action(string title, Func<Task> action, bool primary = false)
    {
        var button = new Button { Content = title };
        AutomationProperties.SetName(button, title);
        if (primary) { button.SetResourceReference(BackgroundProperty, "AccentBrush"); button.SetResourceReference(ForegroundProperty, "PrimaryTextBrush"); }
        button.Click += async (_, _) =>
        {
            if (work != null) return;
            try { await action(); }
            catch (Exception e) { ReportFailure(e); }
        };
        return button;
    }
    private void RowActions(params Button[] buttons)
    { var wrap = new WrapPanel { Margin = new(0,8,0,12) }; foreach (var button in buttons) wrap.Children.Add(button); PageContent.Children.Add(wrap); }
    private void Notice(string title, string body)
    {
        var stack = new StackPanel(); stack.Children.Add(Text(title, 15, true)); stack.Children.Add(Muted(body));
        var border = new Border { Child = stack, Padding = new(18), CornerRadius = new(5), Margin = new(0,0,0,18) };
        border.SetResourceReference(Border.BackgroundProperty, "SoftBrush"); PageContent.Children.Add(border);
    }
    private void Rule()
    { var line = new Border { Height = 1, Margin = new(0,12,0,20) }; line.SetResourceReference(Border.BackgroundProperty, "LineBrush"); PageContent.Children.Add(line); }
    private void ReportFailure(Exception error)
    {
        var detail = error is System.Net.Http.HttpRequestException ? "Ошибка HTTPS. Настройки сети и сертификаты не менялись." : Redactor.Sanitize(error.Message);
        StatusText.Text = "Не выполнено: " + detail;
        StatusText.SetResourceReference(TextBlock.ForegroundProperty, "ErrorBrush");
        TryLog("Ошибка операции", detail);
    }
    private bool TryLog(string action, string result)
    {
        try { storage.Log(action, result); return true; }
        catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException) { return false; }
    }
    private async Task Run(string title, Func<CancellationToken, Task> action)
    {
        if (work != null) return;
        using var current = new CancellationTokenSource(); work = current;
        PageContent.IsEnabled = PageTools.IsEnabled = false; WorkProgress.IsIndeterminate = true; WorkProgress.Visibility = Visibility.Visible;
        CancelButton.Visibility = Visibility.Visible; StatusText.Text = title + "...";
        StatusText.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        string outcome;
        try { await action(current.Token); outcome = title + ": готово. " + DateTime.Now.ToString("HH:mm"); if (!TryLog(title, "Завершено")) outcome += " Журнал недоступен."; }
        catch (OperationCanceledException) { outcome = "Операция отменена."; }
        catch (Exception error) { ReportFailure(error); outcome = StatusText.Text; }
        finally { work = null; }
        if (closing) return;
        Navigate(page); StatusText.Text = outcome;
        PageContent.IsEnabled = PageTools.IsEnabled = true; WorkProgress.Visibility = Visibility.Collapsed; CancelButton.Visibility = Visibility.Collapsed;
    }
    private void CancelWork(object sender, RoutedEventArgs e) => work?.Cancel();
    private async Task RefreshInventory(CancellationToken ct)
    {
        foreach (var spec in Catalog.All)
        {
            var path = spec == Catalog.Telegram ? settings.TelegramPath : settings.FixPath;
            var inspected = await Task.Run(() => Inventory.Inspect(spec, path, ct), ct);
            if (spec == Catalog.Telegram)
            {
                try
                {
                    var prepared = updates.ReadPrepared(spec);
                    if (prepared?.Path == inspected.Path && prepared.Sha256 == inspected.Hash) inspected = inspected with { Version = prepared.Tag };
                }
                catch (Exception e) when (e is IOException or System.Text.Json.JsonException) { storage.Log("Манифест Telegram", "Не прочитан. Требуется повторная подготовка версии."); }
            }
            installed[spec.Id] = inspected;
        }
        inventoryCheckedAt = DateTimeOffset.Now;
    }
    private Task RunAccessCheck() => CheckServices(null);
    private void ChangeMode(object sender, RoutedEventArgs e)
    {
        if (work != null) return;
        try
        {
            var next = settings.Copy(); next.AdvancedMode = !settings.AdvancedMode;
            if (!qa) storage.SaveSettings(next);
            settings = next;
            Navigate(!settings.AdvancedMode && page is ("components" or "journal") ? "overview" : page);
        }
        catch (Exception error) { ReportFailure(error); }
    }
    private void OpenUrl(string url)
    {
        if (qa) throw new InvalidOperationException("Внешние ссылки отключены в QA.");
        var uri = new Uri(url);
        if (uri.Scheme != "https" || !new[] { "github.com", "xbox-dns.ru" }.Contains(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo))
            throw new InvalidOperationException("Внешний адрес не разрешён.");
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    }
}
