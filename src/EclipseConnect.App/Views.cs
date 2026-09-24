using System.IO;
using System.Windows;
using System.Windows.Controls;
using EclipseConnect.Core;

namespace EclipseConnect.App;

public partial class MainWindow
{
    private void ComponentSummary(ComponentSpec spec)
    {
        installed.TryGetValue(spec.Id, out var value);
        var grid = new Grid { Margin = new(0,12,0,12) };
        grid.ColumnDefinitions.Add(new ColumnDefinition()); grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new(160) });
        var title = new StackPanel(); title.Children.Add(Text(spec.Name, 16, true)); title.Children.Add(Muted(spec.Purpose)); grid.Children.Add(title);
        var state = new StackPanel { Margin = new(16,0,0,0) };
        var status = spec == Catalog.Telegram && launcher.OwnsRunningProcess ? "Запущен из Connect" : value?.State ?? "Ещё не проверен";
        state.Children.Add(Text(status, 14, true)); state.Children.Add(Muted(value == null ? "Версия не определена" : "Выбран файл: " + value.Version));
        if (spec == Catalog.Telegram && value?.Exists == true && !qa)
        {
            try
            {
                var port = TelegramEndpoint.Read(value.Path).Port;
                var listening = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(p => p.Port == port);
                state.Children.Add(Muted("Порт " + port + (listening ? " открыт" : " не открыт")));
            }
            catch (Exception e) when (e is IOException or InvalidOperationException or System.Net.NetworkInformation.NetworkInformationException) { state.Children.Add(Muted("Порт не определён")); }
        }
        Grid.SetColumn(state, 1); grid.Children.Add(state); PageContent.Children.Add(grid);
    }
    private void ShowComponents()
    {
        Header("Компоненты", "Работающие экземпляры остаются под управлением тех программ, которые их запустили.");
        if (safety.IsProtected) Notice("Запуск и остановка заблокированы", "Работающие подключения сохраняются. Разрешайте управление только после завершения важных задач.");
        RowActions(Action("Обновить состояние", () => Run("Обновление состояния", RefreshInventory), true));
        foreach (var spec in Catalog.All)
        {
            ComponentSummary(spec);
            installed.TryGetValue(spec.Id, out var value);
            var technical = new StackPanel();
            technical.Children.Add(Muted(value?.Exists == true ? value.Path : "Выберите файл компонента. Поиск не сканирует весь диск."));
            if (value?.Exists == true) technical.Children.Add(Muted("SHA-256: " + value.Hash));
            PageContent.Children.Add(new Expander { Header = "Файл и проверка подлинности", Content = technical, Margin = new(0,0,0,8) });
            var choose = Action("Выбрать файл", () => ChooseFile(spec));
            var source = Action("Официальный проект", () => { OpenUrl("https://github.com/" + spec.Repository); return Task.CompletedTask; });
            if (spec == Catalog.Telegram)
            {
                var start = Action("Запустить Telegram-прокси", StartTelegram, true);
                start.IsEnabled = !qa && !safety.IsProtected && value?.Exists == true && value.ProcessCount == 0 && !launcher.OwnsRunningProcess;
                var stop = Action("Остановить запущенный из Connect", async () =>
                {
                    if (MessageBox.Show(this, "Будет остановлен только Telegram-прокси, запущенный из этого окна. Telegram может потерять соединение. Продолжить?", "Остановить прокси?", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes)
                    {
                        await Run("Остановка Telegram", async ct =>
                        {
                            ct.ThrowIfCancellationRequested();
                            await Task.Run(() => launcher.StopOwned(true), ct);
                            await RefreshInventory(CancellationToken.None);
                        });
                    }
                });
                stop.IsEnabled = !qa && !safety.IsProtected && launcher.OwnsRunningProcess;
                RowActions(choose, source, start, stop);
                PageContent.Children.Add(Muted(qa ? "Режим визуальной проверки: запуск и остановка отключены." :
                    launcher.OwnsRunningProcess ? "Connect управляет этим запуском. После собственного обновления прокси новый процесс может стать внешним." :
                    value?.ProcessCount > 0 ? "Прокси работает отдельно. Для управления завершите его через собственный трей, затем запустите здесь. Несколько процессов могут принадлежать одному приложению." :
                    "Запуск доступен только для подтверждённого файла и после вашего согласия. Закрытие Connect не останавливает прокси."));
            }
            else
            {
                var inspect = Action("Проверить UltimateFix v9.2", () => Run("Проверка UltimateFix v9.2", async ct =>
                {
                    fixPlan = await FixProfiles.Inspect(settings.FixPath, ct);
                    storage.AtomicJson("profiles/ultimatefix-v9.2-plan.json", fixPlan);
                }));
                inspect.IsEnabled = value?.Exists == true;
                RowActions(choose, source, inspect);
                if (fixPlan != null)
                {
                    Notice("Файлы профиля проверены", $"{fixPlan.Files.Count} файлов. Движок {fixPlan.EngineVersion}. Игровой режим: {(fixPlan.GamingMode ? "включён в исходной папке" : "выключен")}. Профиль не запускался.");
                    foreach (var warning in fixPlan.Warnings) PageContent.Children.Add(Muted(warning));
                }
                RowActions(Action("Открыть FIX / Подбор", () => { Navigate("fix"); return Task.CompletedTask; }, true));
                PageContent.Children.Add(Muted("Запуск и подбор профилей находятся в отдельном окне FIX. BAT и глобальные параметры TCP не меняются."));
            }
            Rule();
        }
    }
    private async Task ChooseFile(ComponentSpec spec)
    {
        if (qa) return;
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = "Выберите " + spec.Name, Filter = "Программа Windows (*.exe)|*.exe", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        await Run("Проверка выбранного файла", async ct =>
        {
            var inspected = await Inventory.Inspect(spec, dialog.FileName, ct);
            if (spec == Catalog.Telegram) settings = new VersionSelection(storage).Select(settings, inspected.Path);
            else { var next = settings.Copy(); next.FixPath = inspected.Path; storage.SaveSettings(next); settings = next; }
            installed[spec.Id] = inspected;
        });
    }
    private async Task StartTelegram()
    {
        if (qa) return;
        safety.CapturePermit();
        var value = installed.GetValueOrDefault(Catalog.Telegram.Id);
        if (value == null) return;
        var expected = Catalog.KnownVersion(Catalog.Telegram, value.Hash) != "Не подтверждена" ? value.Hash : "";
        var prepared = updates.ReadPrepared(Catalog.Telegram);
        if (prepared != null && string.Equals(prepared.Path, value.Path, StringComparison.OrdinalIgnoreCase)) expected = prepared.Sha256;
        if (expected.Length != 64) throw new InvalidDataException("Файл не подтверждён. Подготовьте официальный релиз в разделе обновлений.");
        if (MessageBox.Show(this, "Запустить Telegram-прокси? Он откроет локальный порт и начнёт сетевые подключения. DNS, FIX и Happ изменены не будут.", "Запуск Telegram", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Run("Запуск Telegram", async ct => { await launcher.StartTelegram(value.Path, expected, true, ct); await RefreshInventory(CancellationToken.None); });
    }
    private void ShowDiagnostics()
    {
        Header("Проверка доступа", "DNS и HTTPS проверяются раздельно. Ctrl+R - повторить, Esc - отменить.");
        var export = Action("Экспортировать результат", () =>
        {
            if (results.Count == 0) return Task.CompletedTask;
            var path = storage.ExportReport(results); StatusText.Text = "Отчёт сохранён: " + path; return Task.CompletedTask;
        });
        export.IsEnabled = results.Count > 0;
        RowActions(Action("Проверить доступ", RunAccessCheck, true), export);
        if (results.Count == 0) Notice("Проверок ещё нет", "Нажмите «Проверить доступ». Будут отправлены обычные HTTPS-запросы без входа в аккаунты и без передачи журналов.");
        foreach (var result in results)
        {
            PageContent.Children.Add(Text(result.Target + "  ·  " + result.State, 15, true));
            PageContent.Children.Add(Muted(result.Detail));
            PageContent.Children.Add(Muted("Проверено " + result.CheckedAt.ToLocalTime().ToString("dd.MM HH:mm:ss"))); Rule();
        }
        PageContent.Children.Add(Muted("Прямой HTTPS без системного прокси. В браузере и Codex может быть другой DNS или маршрут. HTTP 403 — ответ с отказом, не доказательство сбоя DNS. Вход, ответы модели, видео и звонки проверяются отдельно."));
    }
    private Task CheckUpdates() => qa ? Task.CompletedTask : Run("Проверка обновлений", async ct =>
    {
        foreach (var spec in Catalog.All)
        {
            try
            {
                var release = await updates.Check(spec, ct); releases[spec.Id] = release;
                installed.TryGetValue(spec.Id, out var local);
                var known = local?.Version.StartsWith('v') == true;
                updateStates[spec.Id] = known ? ReleasePolicy.Compare(release.Tag, local!.Version) > 0 ? "Доступна новая версия " + release.Tag :
                    ReleasePolicy.Compare(release.Tag, local!.Version) == 0 ? "Версия совпадает с релизом " + release.Tag : "Локальная версия новее текущего stable-релиза" :
                    "На GitHub: " + release.Tag + ". Локальная версия не подтверждена.";
                storage.Log("Проверка релиза " + spec.Name, updateStates[spec.Id]);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e) { releases.Remove(spec.Id); updateStates[spec.Id] = Redactor.Sanitize(e.Message); }
        }
    });
    private void ShowUpdates()
    {
        Header("Обновления", "Проверить, подготовить, выбрать для следующего запуска. Без подмены работающих файлов.");
        RowActions(Action("Проверить новые версии", CheckUpdates, true));
        foreach (var spec in Catalog.All)
        {
            PageContent.Children.Add(Text(spec.Name, 18, true));
            installed.TryGetValue(spec.Id, out var selectedFile);
            PageContent.Children.Add(Muted("Для следующего запуска: " + (selectedFile?.Version ?? "файл ещё не проверен")));
            if (spec == Catalog.Telegram)
                PageContent.Children.Add(Muted(launcher.OwnsRunningProcess ? "Сейчас: процесс запущен этим окном. Версия после самообновления отдельно не подтверждается." :
                    selectedFile?.ProcessCount > 0 ? "Сейчас: прокси работает отдельно. Его версия не приравнивается к выбранному файлу." : "По последней проверке прокси не запущен."));
            PageContent.Children.Add(Muted(updateStates.GetValueOrDefault(spec.Id, "Ещё не проверялось")));
            PageContent.Children.Add(Muted("Источник: github.com/" + spec.Repository));
            var source = Action("Открыть релизы", () => { OpenUrl("https://github.com/" + spec.Repository + "/releases"); return Task.CompletedTask; });
            if (spec == Catalog.Telegram)
            {
                releases.TryGetValue(spec.Id, out var release);
                var asset = release?.Assets.FirstOrDefault(a => a.Name == spec.AssetName && a.Digest.StartsWith("sha256:"));
                var download = Action("Подготовить к запуску", () => Run("Подготовка Telegram", async ct =>
                {
                    if (release == null || asset == null) return;
                    WorkProgress.IsIndeterminate = false; WorkProgress.Value = 0;
                    var artifact = await updates.Prepare(spec, release, asset, new Progress<double>(p => WorkProgress.Value = p), ct);
                    ct.ThrowIfCancellationRequested();
                    settings = new VersionSelection(storage).Select(settings, artifact.Path);
                    await RefreshInventory(ct);
                }), true);
                download.IsEnabled = asset != null && System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.X64;
                RowActions(source, download);
                if (asset == null) PageContent.Children.Add(Muted("Для загрузки нужен проверенный релиз с SHA-256. Сначала проверьте версии."));
                try
                {
                    var prepared = updates.ReadPrepared(spec);
                    if (prepared != null)
                    {
                        Notice("Подготовлена " + prepared.Tag, string.Equals(settings.TelegramPath, prepared.Path, StringComparison.OrdinalIgnoreCase)
                            ? "Проверенная копия выбрана для следующего запуска. Работающий прокси не заменён."
                            : "Проверенная копия готова. Выберите её для следующего запуска; работающий прокси не заменится.");
                        RowActions(Action("Выбрать для следующего запуска", () => Run("Выбор подготовленной версии", async ct =>
                        {
                            var inspected = await Inventory.Inspect(spec, prepared.Path, ct);
                            if (inspected.Hash != prepared.Sha256) throw new InvalidDataException("Подготовленный файл изменён. Загрузите его заново.");
                            ct.ThrowIfCancellationRequested();
                            settings = new VersionSelection(storage).Select(settings, prepared.Path);
                            installed[spec.Id] = inspected with { Version = prepared.Tag };
                        })));
                    }
                }
                catch (Exception e) { PageContent.Children.Add(Muted("Подготовленная версия недоступна: " + Redactor.Sanitize(e.Message))); }
            }
            else RowActions(source);
            Rule();
        }
        PageContent.Children.Add(Muted("GitHub SHA-256 подтверждает совпадение с файлом релиза, но не заменяет цифровую подпись или аудит кода. EXE Telegram сейчас не подписан издателем."));
    }
    private void ShowSettings()
    {
        Header("Настройки", "Только настройки Connect. Параметры Windows, браузера и Happ остаются прежними.");
        PageContent.Children.Add(Text("Окно и трей", 17, true));
        var closeToTray = new CheckBox { Content = "Крестик скрывает Connect в трей", IsChecked = settings.CloseToTray, Margin = new(0,0,0,12) };
        closeToTray.SetResourceReference(ForegroundProperty, "TextBrush");
        System.Windows.Automation.AutomationProperties.SetName(closeToTray, "Крестик скрывает Connect в трей");
        closeToTray.Click += (_, _) =>
        {
            try { var next = settings.Copy(); next.CloseToTray = closeToTray.IsChecked == true; storage.SaveSettings(next); settings = next; }
            catch (Exception e) { closeToTray.IsChecked = settings.CloseToTray; ReportFailure(e); }
        };
        PageContent.Children.Add(closeToTray);
        PageContent.Children.Add(Muted("По умолчанию крестик закрывает Connect. Сворачивание в трей включает защиту. Выход из Connect не останавливает прокси.")); Rule();
        PageContent.Children.Add(Text("Оформление", 17, true));
        var theme = new ComboBox { Width = 240, HorizontalAlignment = HorizontalAlignment.Left, Margin = new(0,0,0,16) };
        foreach (var item in new[] { ("System", "Как в Windows"), ("Light", "Светлая"), ("Dark", "Тёмная") }) theme.Items.Add(new ComboBoxItem { Content = item.Item2, Tag = item.Item1 });
        theme.SelectedIndex = settings.Theme == "Light" ? 1 : settings.Theme == "Dark" ? 2 : 0;
        System.Windows.Automation.AutomationProperties.SetName(theme, "Оформление");
        theme.SelectionChanged += (_, _) => { settings.Theme = ((ComboBoxItem)theme.SelectedItem).Tag.ToString()!; ApplyTheme(); storage.SaveSettings(settings); };
        PageContent.Children.Add(theme);
        var check = new CheckBox { Content = "Проверять версии при открытии Connect", IsChecked = settings.CheckUpdatesOnStart, Margin = new(0,0,0,12) };
        check.SetResourceReference(ForegroundProperty, "TextBrush");
        check.Checked += (_, _) => { settings.CheckUpdatesOnStart = true; storage.SaveSettings(settings); };
        check.Unchecked += (_, _) => { settings.CheckUpdatesOnStart = false; storage.SaveSettings(settings); };
        PageContent.Children.Add(check);
        PageContent.Children.Add(Muted("Только запрос информации о релизах. Автоматической установки и перезапуска нет.")); Rule();
        PageContent.Children.Add(Text("Xbox DNS", 17, true));
        PageContent.Children.Add(Muted("DNS-over-HTTPS для ручной настройки браузера:"));
        var address = new TextBox { Text = "https://xbox-dns.ru/dns-query", IsReadOnly = true, Margin = new(0,0,0,8) };
        System.Windows.Automation.AutomationProperties.SetName(address, "Адрес Xbox DNS-over-HTTPS"); PageContent.Children.Add(address);
        RowActions(Action("Скопировать адрес", () => { Clipboard.SetText(address.Text); StatusText.Text = "Адрес DNS скопирован. Настройки не изменены."; return Task.CompletedTask; }),
            Action("Инструкция провайдера", () => { OpenUrl("https://xbox-dns.ru/#setup"); return Task.CompletedTask; }));
        PageContent.Children.Add(Muted("DNS: 111.88.96.50 / 111.88.96.51. Это сторонний сервис. DoH шифрует DNS-запросы, но сам по себе не туннелирует весь трафик.")); Rule();
        RowActions(Action("Открыть восстановление", () => { Navigate("recovery"); return Task.CompletedTask; }));
    }
    private void ShowJournal()
    {
        Header("Журнал", "Последние 200 операций. Журнал не отправляется разработчикам или внешним сервисам.");
        var entries = storage.ReadJournal();
        if (entries.Count == 0) { Notice("Пока пусто", "Здесь появятся результаты проверок, подготовка обновлений и ваши действия."); return; }
        foreach (var entry in entries.AsEnumerable().Reverse())
        {
            PageContent.Children.Add(Text(entry.Time.ToString("dd.MM HH:mm:ss") + "  ·  " + entry.Action, 14, true));
            PageContent.Children.Add(Muted(entry.Result)); Rule();
        }
    }
}
