using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Automation;
using EclipseConnect.Core;

namespace EclipseConnect.App;

public partial class MainWindow
{
    private WindowsFixLink? fixLink;
    private FixRun fixDraft = new("ultimate", false, "youtube");
    private string fixMessage = "Помощник не подключён. Работающие внешние FIX не перехватываются.";
    private IReadOnlyList<FixTrial> fixTrials = [];
    private FixControlState? qaFixState;

    private void ShowFix()
    {
        Header("FIX / Подбор", "Запуск, проверка и восстановление в одном окне. DNS и Happ не меняются.");
        var connected = fixLink?.Connected == true || (qa && qaFixState != null);
        var state = qa ? qaFixState : connected ? fixLink!.LastState : null;
        var running = state?.Running == true;
        var external = state?.ExternalEngine == true || (!running && installed.GetValueOrDefault("fix")?.ProcessCount > 0);
        var connect = Action(connected ? "Обновить состояние" : "Подключить управление",
            connected ? () => RemoteFix("status") : OpenFixControl, !connected);
        connect.IsEnabled = !qa;
        var files = Action("Проверить файлы", () => Run("Проверка ресурсов FIX", async ct =>
        { foreach (var p in FixCatalog.All) await WindowsFixRuntime.InspectResources(settings.FixPath, p.Id, ct); }));
        Notice(running ? "FIX работает: " + FixCatalog.Get(state!.Active!.ProfileId).Name :
            external ? "Работает внешний FIX" : connected ? "Помощник готов, FIX остановлен" : "Управление не подключено",
            external ? "Остановить или переключить этот процесс здесь нельзя. Используйте окно, из которого его запускали." : state?.Message ?? fixMessage);
        PageContent.Children.Add(Muted("Закрытие Connect остановит FIX, запущенный этим помощником. Сворачивание в трей сохранит его работу."));
        var form = new WrapPanel { Margin = new(0,8,0,10) };
        var profile = new ComboBox { Width = 245, DisplayMemberPath = "Name", Margin = new(0,0,12,8) };
        foreach (var p in FixCatalog.All) profile.Items.Add(p);
        profile.SelectedItem = FixCatalog.Get(fixDraft.ProfileId);
        var target = new ComboBox { Width = 190, Margin = new(0,0,12,8) };
        foreach (var pair in new[] { ("youtube","YouTube"), ("discord","Discord"), ("all","YouTube и Discord") })
            target.Items.Add(new ComboBoxItem { Content = pair.Item2, Tag = pair.Item1 });
        target.SelectedItem = target.Items.Cast<ComboBoxItem>().First(i => (string)i.Tag == fixDraft.Target);
        void AddField(string label, ComboBox field)
        {
            var stack = new StackPanel(); stack.Children.Add(Text(label, 13, true)); stack.Children.Add(field); form.Children.Add(stack);
            AutomationProperties.SetName(field, label);
        }
        AddField("Профиль", profile); AddField("Что проверить", target);
        profile.SelectionChanged += (_, _) => { if (profile.SelectedItem is FixProfile p) fixDraft = fixDraft with { ProfileId = p.Id }; };
        target.SelectionChanged += (_, _) => { if (target.SelectedItem is ComboBoxItem i) fixDraft = fixDraft with { Target = (string)i.Tag }; };
        PageContent.Children.Add(form);
        var gaming = new CheckBox { Content = "Расширенный игровой диапазон", IsChecked = fixDraft.Gaming, Margin = new(0,0,0,12) };
        gaming.Checked += (_, _) => fixDraft = fixDraft with { Gaming = true };
        gaming.Unchecked += (_, _) => fixDraft = fixDraft with { Gaming = false };
        PageContent.Children.Add(gaming);
        var allowed = !qa && connected && !safety.IsProtected && !external;
        var start = Action("Запустить FIX", () => RemoteFix("start"), true); start.IsEnabled = allowed && !running;
        var stop = Action("Остановить FIX", () => RemoteFix("stop")); stop.IsEnabled = allowed && running;
        var pick = Action("Подобрать профиль", () => RemoteFix("select")); pick.IsEnabled = allowed && !running;
        var change = Action("Применить с возвратом", () => RemoteFix("switch"), true); change.IsEnabled = allowed && running;
        var restore = Action("Вернуть прошлый запуск", () => RemoteFix("restore")); restore.IsEnabled = allowed && running && state?.Previous != null;
        if (connected)
        {
            PageTools.Children.Add(running ? change : start);
            PageTools.Children.Add(running ? stop : pick);
            PageTools.Children.Add(connect);
            if (state?.Previous != null) RowActions(restore, files);
            else RowActions(files);
        }
        else { PageTools.Children.Add(connect); PageTools.Children.Add(files); }
        if (!connected) PageContent.Children.Add(Muted("Сначала подключите управление. Windows запросит права только для помощника, без запуска FIX."));
        else if (safety.IsProtected) PageContent.Children.Add(Muted("Сверху нажмите «Разрешить управление». Каждое изменение дополнительно подтверждается."));
        PageContent.Children.Add(Muted("«Применить с возвратом» проверяет новый профиль дважды. При ошибке или отмене возвращается предыдущий собственный запуск. Если оболочка закрылась, скрытого перезапуска не будет."));
        Rule();
        try
        {
            var choice = new FixChoiceStore(storage).Read();
            PageContent.Children.Add(Text("Выбор для следующего запуска", 16, true));
            PageContent.Children.Add(Muted(FixChoiceStore.Describe(choice.Selected)));
            var use = Action("Выбрать сохранённый", () =>
            {
                if (choice.Selected is { } selected) fixDraft = new(selected.ProfileId, false, selected.Target == "legacy" ? "youtube" : selected.Target);
                Navigate("fix"); return Task.CompletedTask;
            }); use.IsEnabled = choice.Selected != null; RowActions(use);
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException)
        { PageContent.Children.Add(Muted("Выбор не прочитан. Файл не изменён. " + Redactor.Sanitize(e.Message))); }
        foreach (var trial in fixTrials)
        {
            PageContent.Children.Add(Text(FixCatalog.Get(trial.Profile).Name + (trial.Passed ? ": HTTPS пройден" : ": проверка не пройдена"), 14, true));
            for (var i = 0; i < trial.Checks.Count; i++)
            {
                var check = trial.Checks[i];
                PageContent.Children.Add(Muted($"Проверка {i+1}: контроль {(check.ControlReady ? "доступен" : "недоступен")}; " +
                    string.Join(", ", check.Services.Select(p => p.Key + (p.Value ? " доступен" : " недоступен")))));
            }
        }
    }
    private Task OpenFixControl()
    {
        if (qa) { StatusText.Text = "QA: запуск помощника отключён."; return Task.CompletedTask; }
        if (string.IsNullOrWhiteSpace(settings.FixPath)) { Navigate("components"); StatusText.Text = "Сначала выберите FIX/bin/winws.exe."; return Task.CompletedTask; }
        if (MessageBox.Show(this, "Подключить ограниченный помощник Windows? Это пока не запускает FIX. Если затем запустить FIX здесь, выход из Connect остановит его; сворачивание в трей сохранит работу.",
            "Управление FIX", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return Task.CompletedTask;
        return Run("Подключение помощника FIX", async ct =>
        {
            storage.SaveSettings(settings);
            fixLink?.Dispose(); fixLink = null;
            fixLink = await WindowsFixLink.Open(ct);
            var state = await fixLink.Execute("status", null, false, ct);
            fixMessage = state.Message;
        });
    }
    private Task RemoteFix(string operation)
    {
        if (qa || fixLink?.Connected != true) return Task.CompletedTask;
        long permit = 0;
        if (operation != "status")
        {
            permit = safety.CapturePermit();
            var message = operation switch
            {
                "switch" or "restore" => "Переключить собственный FIX? Соединения могут прерваться. При неудачной проверке или отмене помощник попробует снова запустить предыдущий профиль. При потере связи с оболочкой оба запуска остановятся.",
                "select" => "Начать подбор FIX? Кандидаты временно изменят обработку пакетов и затем остановятся. Важные задачи должны быть завершены.",
                "stop" => "Остановить FIX, запущенный этим окном? Доступ к части сайтов может пропасть.",
                _ => "Запустить выбранный FIX? Он использует WinDivert и может прервать соединения. DNS и Happ не меняются."
            };
            if (MessageBox.Show(this, message, "Изменение подключения", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return Task.CompletedTask;
        }
        var chosen = operation is "start" or "switch" ? fixDraft : operation == "select" ? fixDraft with { Gaming = false } : null;
        return Run("FIX", async ct =>
        {
            Task<FixControlState> Send() => fixLink.Execute(operation, chosen, operation != "status", ct,
                new Progress<FixProgress>(p => { if (work != null) StatusText.Text = p.Stage + (p.Profile == null ? "" : ": " + FixCatalog.Get(p.Profile).Name); }));
            try
            {
                var state = await (operation == "status" ? Send() : safety.Commit(permit, ct, Send));
                fixMessage = state.Message; fixTrials = state.Trials;
            }
            finally
            {
                if (fixLink.LastState is { } last) { fixMessage = last.Message; fixTrials = last.Trials; }
                try
                {
                    using var refresh = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await RefreshInventory(refresh.Token);
                }
                catch (Exception e) when (e is IOException or OperationCanceledException or UnauthorizedAccessException)
                { TryLog("Состояние FIX", "Не удалось обновить список компонентов: " + Redactor.Sanitize(e.Message)); }
            }
        });
    }
}
