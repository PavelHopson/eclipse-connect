using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Automation;
using System.Windows.Media;
using EclipseConnect.Core;

namespace EclipseConnect.App;

// Separate elevated surface. It has no updater, arbitrary URL opener, command entry, or Telegram controls.
public sealed class FixWindow : Window
{
    private readonly Storage storage;
    private readonly WindowsFixRuntime? runtime;
    private readonly bool qa;
    private readonly SessionSafety safety = new();
    private readonly ComboBox profile = new() { MinWidth = 220, DisplayMemberPath = "Name" };
    private readonly ComboBox target = new() { MinWidth = 220 };
    private readonly CheckBox gaming = new() { Content = "Расширенный игровой диапазон (1024-65535)", Margin = new(0,12,0,12) };
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0,14,0,0), MinHeight = 48 };
    private readonly TextBlock result = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0,16,0,12) };
    private readonly Button pick, start, stop, cancel, restore;
    private readonly TextBlock savedChoice = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0,10,0,8) };
    private readonly StackPanel trialRows = new();
    private readonly TextBlock stage = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0,0,0,8), FontWeight = FontWeights.SemiBold };
    private CancellationTokenSource? work;
    private IManagedProcess? owned;
    private bool closeRequested;
    public FixWindow(Storage storage, string enginePath, bool qa = false, bool? dark = null)
    {
        this.storage = storage; this.qa = qa;
        if (!qa) runtime = new(enginePath, storage);
        Title = "Eclipse Connect / FIX"; Width = 860; Height = 760; MinWidth = 640; MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterScreen; FontFamily = new("Segoe UI"); FontSize = 14;
        Brand.Apply(this, dark ?? (Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1) is int light && light == 0));
        var root = new DockPanel { Margin = new(22) }; Content = root;
        var heading = new StackPanel { Margin = new(0,0,0,16) };
        heading.Children.Add(new TextBlock { Text = "Управление FIX", FontSize = 24, FontWeight = FontWeights.SemiBold });
        heading.Children.Add(new TextBlock { Text = "Отдельное окно с правами Windows. DNS, Happ и автозагрузка не меняются.", Margin = new(0,8,0,0), TextWrapping = TextWrapping.Wrap });
        DockPanel.SetDock(heading, Dock.Top); root.Children.Add(heading);
        var bottom = new StackPanel();
        var controls = new WrapPanel();
        pick = Make("Подобрать", Pick); start = Make("Запустить FIX", Start); stop = Make("Остановить FIX", Stop);
        pick.SetResourceReference(BackgroundProperty, "AccentBrush"); pick.SetResourceReference(ForegroundProperty, "PrimaryTextBrush");
        cancel = Make("Отменить", () => { work?.Cancel(); return Task.CompletedTask; });
        restore = Make("Вернуть предыдущий выбор", RestoreChoice);
        var exit = Make("Выйти", () => { Close(); return Task.CompletedTask; });
        controls.Children.Add(pick); controls.Children.Add(start); controls.Children.Add(stop); controls.Children.Add(cancel); controls.Children.Add(exit);
        bottom.Children.Add(stage); bottom.Children.Add(controls); bottom.Children.Add(status); DockPanel.SetDock(bottom, Dock.Bottom); root.Children.Add(bottom);
        var content = new StackPanel(); root.Children.Add(new ScrollViewer { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        content.Children.Add(new TextBlock { Text = "Что должно работать", FontWeight = FontWeights.SemiBold, Margin = new(0,0,0,8) });
        target.Items.Add(new ComboBoxItem { Content = "YouTube", Tag = "youtube" });
        target.Items.Add(new ComboBoxItem { Content = "Discord", Tag = "discord" });
        target.Items.Add(new ComboBoxItem { Content = "YouTube и Discord", Tag = "all" }); target.SelectedIndex = 0;
        AutomationProperties.SetName(target, "Сервисы для подбора"); content.Children.Add(target);
        content.Children.Add(new TextBlock { Text = "Профиль для ручного запуска", FontWeight = FontWeights.SemiBold, Margin = new(0,22,0,8) });
        foreach (var p in FixCatalog.All) profile.Items.Add(p); profile.SelectedIndex = 0;
        AutomationProperties.SetName(profile, "Профиль FIX"); content.Children.Add(profile); content.Children.Add(gaming);
        LoadChoice(true);
        content.Children.Add(savedChoice); content.Children.Add(restore);
        content.Children.Add(new TextBlock { Text = "Результат подбора", FontWeight = FontWeights.SemiBold, Margin = new(0,16,0,10) });
        content.Children.Add(result); content.Children.Add(trialRows);
        result.Text = "Подбор ещё не выполнялся в этом окне.";
        var safetyNote = new TextBlock
        {
            Text = "Каждый пробный FIX останавливается. Удачный выбор сохраняется; включение только по кнопке «Запустить FIX».\n\nFIX может прервать соединения. При закрытии окна останавливается только его собственный FIX. WinDivert может зарегистрировать службу драйвера; её удаление не выполняется. DNS, Happ и чужие процессы не меняются.",
            TextWrapping = TextWrapping.Wrap
        };
        content.Children.Add(new Expander { Header = "Как работает подбор и что изменяется", Content = safetyNote, Margin = new(0,14,0,12) });
        Closing += (_, e) =>
        {
            if (work != null) { closeRequested = true; work.Cancel(); e.Cancel = true; status.Text = "Завершаю пробный FIX перед выходом..."; return; }
            if (owned?.IsRunning == true && MessageBox.Show(this, "Остановить запущенный этим окном FIX и выйти?", "Выход", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
            { e.Cancel = true; return; }
            try { CleanupOwned(); safety.Protect(); }
            catch (Exception error) { e.Cancel = true; status.Text = Redactor.Sanitize(error.Message); }
        };
        UpdateButtons(); status.Text = qa ? "Визуальная проверка: реальные запуски отключены." : "Ничего не запущено. Выберите подбор или ручной запуск.";
    }
    private Button Make(string label, Func<Task> action)
    {
        var button = new Button { Content = label }; AutomationProperties.SetName(button, label);
        button.Click += async (_, _) => { try { await action(); } catch (Exception e) { status.Text = Redactor.Sanitize(e.Message); } };
        return button;
    }
    private bool Confirm(string text) => !qa && MessageBox.Show(this, text, "Изменение сетевого соединения", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
    private void UpdateButtons()
    {
        var idle = work == null;
        pick.IsEnabled = start.IsEnabled = !qa && idle && owned?.IsRunning != true;
        stop.IsEnabled = !qa && idle && owned?.IsRunning == true;
        cancel.IsEnabled = !qa && !idle; profile.IsEnabled = target.IsEnabled = gaming.IsEnabled = idle && owned?.IsRunning != true;
        try { restore.IsEnabled = !qa && idle && owned?.IsRunning != true && new FixChoiceStore(storage).Read().Previous != null; }
        catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException) { restore.IsEnabled = false; }
    }
    private async Task Execute(string operation, Func<CancellationToken, Task> action)
    {
        if (qa || work != null) return;
        using var current = new CancellationTokenSource(); work = current; UpdateButtons();
        try { await action(current.Token); TryLog(operation, "Завершено"); }
        catch (OperationCanceledException) { status.Text = "Отменено. Пробный FIX остановлен; прежний выбор сохранён."; }
        catch (Exception error) { status.Text = "Не выполнено: " + Redactor.Sanitize(error.Message); TryLog(operation, status.Text); }
        finally { work = null; safety.Protect(); UpdateButtons(); }
        if (closeRequested) Close();
    }
    private Task Pick()
    {
        if (qa || runtime == null || work != null) return Task.CompletedTask;
        if (runtime.HasConfoundingTunnel) { status.Text = "Обнаружен Happ или другой туннель. Подбор сейчас недостоверен. Закройте его вручную только после завершения важных задач."; return Task.CompletedTask; }
        if (!Confirm("Подбор временно изменит обработку сетевых пакетов. Важные задачи должны быть завершены. После проверки кандидаты остановятся; результат не включается автоматически. Начать?")) return Task.CompletedTask;
        safety.AllowForSession(true);
        var scope = (string)((ComboBoxItem)target.SelectedItem).Tag;
        return Execute("Подбор FIX", async ct =>
        {
            trialRows.Children.Clear(); result.Text = "Сначала проверяется сеть без FIX.";
            var selected = await new FixSelector(safety, runtime).Select(scope, true,
                new Progress<string>(p => { if (work != null && !ct.IsCancellationRequested) status.Text = p; }), ct,
                new Progress<FixProgress>(p =>
                {
                    if (work == null || ct.IsCancellationRequested) return;
                    stage.Text = p.Stage + (p.Profile == null ? "" : $" · {p.Index}/{p.Total}: {FixCatalog.Get(p.Profile).Name}");
                    RenderTrials(p.Trials);
                }));
            ct.ThrowIfCancellationRequested();
            if (selected.SelectedId != null) { new FixChoiceStore(storage).Accept(selected, scope, DateTimeOffset.Now); LoadChoice(true); }
            RenderTrials(selected.Trials); result.Text = selected.Message;
            stage.Text = "Подбор завершён";
            status.Text = selected.SelectedId == null ? "Выбор не изменён. Ни один пробный FIX не оставлен работающим." : "Выбор сохранён. FIX сейчас не запущен.";
            try { storage.AtomicJson("reports/fix-last-trial.json", selected); }
            catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException)
            { status.Text += " Отчёт не записан: " + Redactor.Sanitize(e.Message); }
        });
    }
    private Task Start()
    {
        if (qa || runtime == null || work != null || owned?.IsRunning == true) return Task.CompletedTask;
        if (!Confirm("Запустить выбранный FIX? Он использует драйвер WinDivert и может прервать соединения. DNS и Happ не меняются. Закрытие этого окна остановит только этот FIX.")) return Task.CompletedTask;
        safety.AllowForSession(true); var selected = (FixProfile)profile.SelectedItem; var useGaming = gaming.IsChecked == true;
        return Execute("Запуск FIX " + selected.Name, async ct =>
        {
            owned?.Dispose(); owned = null;
            owned = await runtime.Start(selected.Id, useGaming, ct);
            status.Text = "FIX запущен: " + selected.Name + ". Работа видео и звонков требует проверки.";
        });
    }
    private Task Stop()
    {
        if (qa || !Confirm("Остановить только FIX, запущенный этим окном? Соединения могут измениться.")) return Task.CompletedTask;
        CleanupOwned(); status.Text = "Собственный FIX остановлен."; TryLog("Остановка FIX", "Остановлен собственный процесс"); UpdateButtons(); return Task.CompletedTask;
    }
    private void CleanupOwned()
    {
        if (owned == null) return;
        if (owned.IsRunning) owned.Stop();
        owned.Dispose(); owned = null;
    }
    private void LoadChoice(bool select)
    {
        try
        {
            var choice = new FixChoiceStore(storage).Read();
            savedChoice.Text = "Сохранённый выбор: " + FixChoiceStore.Describe(choice.Selected);
            if (select && choice.Selected != null) profile.SelectedItem = FixCatalog.Get(choice.Selected.ProfileId);
        }
        catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException)
        { savedChoice.Text = "Файл выбора недоступен. Исходные данные сохранены; восстановление отключено."; }
    }
    private Task RestoreChoice()
    {
        if (qa || work != null || owned?.IsRunning == true) return Task.CompletedTask;
        if (MessageBox.Show(this, "Вернуть предыдущий сохранённый выбор? Профиль не будет запущен.", "Восстановить выбор FIX?",
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return Task.CompletedTask;
        new FixChoiceStore(storage).Restore(); LoadChoice(true); UpdateButtons();
        status.Text = "Предыдущий выбор восстановлен. Ничего не запущено.";
        TryLog("Восстановление выбора FIX", "Изменён только сохранённый выбор");
        return Task.CompletedTask;
    }
    private void TryLog(string action, string detail)
    {
        try { storage.Log(action, detail); }
        catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException) { status.Text += " Журнал недоступен."; }
    }
    private void RenderTrials(IReadOnlyList<FixTrial> trials)
    {
        trialRows.Children.Clear();
        foreach (var trial in trials.Take(4))
        {
            var title = new TextBlock { Text = FixCatalog.Get(trial.Profile).Name + ": " + (trial.Passed ? "HTTPS пройден" : "Не прошёл"), FontWeight = FontWeights.SemiBold, Margin = new(0,8,0,4) };
            title.SetResourceReference(TextBlock.ForegroundProperty, trial.Passed ? "SuccessBrush" : "WarningBrush");
            trialRows.Children.Add(title);
            if (trial.Checks.Count == 0) trialRows.Children.Add(new TextBlock { Text = trial.Detail, TextWrapping = TextWrapping.Wrap });
            for (var i = 0; i < Math.Min(trial.Checks.Count, 2); i++)
            {
                var check = trial.Checks[i];
                static string Mark(bool value) => value ? "ответ" : "нет ответа";
                trialRows.Children.Add(new TextBlock { Text = $"Проверка {i + 1}: контроль - {Mark(check.ControlReady)}, YouTube - {Mark(check.Services.GetValueOrDefault("youtube"))}, Discord - {Mark(check.Services.GetValueOrDefault("discord"))}.",
                    FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new(0,0,0,4) });
                if (!check.ProcessRunning) trialRows.Children.Add(new TextBlock { Text = "Процесс FIX завершился во время проверки.", FontSize = 12 });
            }
        }
    }
    internal void SetQaTrials(IReadOnlyList<FixTrial> trials)
    {
        if (!qa) throw new InvalidOperationException("Только QA.");
        RenderTrials(trials); stage.Text = "Тестовый результат, без запуска FIX";
        result.Text = "Пример: первый профиль не прошёл, второй прошёл HTTPS-проверки. Видео и звонки не проверены.";
    }
}
