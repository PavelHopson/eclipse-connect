using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using EclipseConnect.Core;

namespace EclipseConnect.App;

public partial class MainWindow
{
    private DiagnosticResult? ServiceResult(ServiceSpec service) =>
        results.LastOrDefault(r => r.Target == new Uri(service.Url).Host);

    private void ShowOverview()
    {
        Header("Обзор", "Доступ к сервисам и состояние ваших компонентов.");
        PageTools.Children.Add(Action("Проверить сервисы", RunAccessCheck, true));
        PageTools.Children.Add(Action("Подключить VPN", () => { Navigate("vpn"); return Task.CompletedTask; }));
        PageTools.Children.Add(Action("Управлять Telegram", () => { Navigate("components"); return Task.CompletedTask; }));
        PageTools.Children.Add(Action("Подобрать FIX", () => { Navigate("fix"); return Task.CompletedTask; }));
        var telegram = installed.GetValueOrDefault("telegram");
        var fix = installed.GetValueOrDefault("fix");
        var state = Text("Telegram-прокси: " + (launcher.OwnsRunningProcess ? "запущен из этого окна" : telegram?.State.ToLowerInvariant() ?? "не проверен") +
            "\nFIX: " + (fix?.State.ToLowerInvariant() ?? "не проверен"), 13);
        state.Margin = new(0,8,0,2); PageContent.Children.Add(state);
        PageContent.Children.Add(Muted(inventoryCheckedAt is { } time ? "Компоненты проверены в " + time.ToLocalTime().ToString("HH:mm") + ". Это не проверка доступа." : "Состояние компонентов обновляется отдельно от проверки сайтов."));
        foreach (var service in ServiceCatalog.All)
        {
            var grid = new Grid { Margin = new(0,0,0,2) };
            grid.ColumnDefinitions.Add(new() { Width = new(104) });
            grid.ColumnDefinitions.Add(new());
            grid.ColumnDefinitions.Add(new() { Width = new(110) });
            var name = Text(service.Name, 15, true); name.VerticalAlignment = VerticalAlignment.Center; name.Margin = new(0,0,8,0); grid.Children.Add(name);
            var labels = new StackPanel { Margin = new(0,0,8,0), VerticalAlignment = VerticalAlignment.Center };
            var label = Text("", 13, true); label.Margin = new(0,0,0,3);
            var stamp = Muted(""); stamp.FontSize = 12; stamp.Margin = new(0);
            labels.Children.Add(label); labels.Children.Add(stamp); Grid.SetColumn(labels, 1); grid.Children.Add(labels);
            serviceLabels[service.Id] = (label, stamp);
            var button = Action(ServiceResult(service) == null ? "Проверить" : "Подробнее",
                () => { selectedService = service.Id; return ServiceResult(service) == null ? CheckServices(service.Id) : OpenService(); });
            System.Windows.Automation.AutomationProperties.SetName(button, button.Content + " " + service.Name);
            button.Margin = new(0); button.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(button, 2); grid.Children.Add(button);
            var border = new Border { Padding = new(0,11,0,11), BorderThickness = new(0,0,0,1), Child = grid };
            border.SetResourceReference(Border.BorderBrushProperty, "LineBrush"); PageContent.Children.Add(border);
        }
        PageContent.Children.Add(Muted("Здесь проверяется HTTPS. Вход, видео, звонки и ответы приложений автоматически не подтверждаются."));
        RefreshServiceLabels();
    }
    private Task OpenService() { Navigate("service"); return Task.CompletedTask; }
    private void RefreshServiceLabels()
    {
        RefreshVpnServiceLabels();
        foreach (var service in ServiceCatalog.All)
        {
            if (!serviceLabels.TryGetValue(service.Id, out var labels)) continue;
            var health = ServiceCatalog.Describe(service, ServiceResult(service), DateTimeOffset.Now, checkingServices.Contains(service.Id));
            labels.State.Text = health.Label; labels.State.SetResourceReference(TextBlock.ForegroundProperty, health.Tone + "Brush");
            labels.Time.Text = health.Freshness;
        }
    }
    private Task CheckServices(string? id, string[]? group = null)
    {
        if (qa) { StatusText.Text = "QA: сетевые запросы отключены."; return Task.CompletedTask; }
        var selected = group != null ? group.Select(ServiceCatalog.Get).ToArray() : id == null ? ServiceCatalog.All : [ServiceCatalog.Get(id)];
        return Run("Проверка доступа", async ct =>
        {
            foreach (var s in selected) checkingServices.Add(s.Id);
            RefreshServiceLabels();
            void Keep(DiagnosticResult value) { results.RemoveAll(r => r.Target == value.Target); results.Add(value); }
            try
            {
                var pending = selected.Select(async s =>
                {
                    var value = await Diagnostics.Probe(new Uri(s.Url), ct);
                    Keep(value); checkingServices.Remove(s.Id); RefreshServiceLabels();
                }).ToList();
                // All tasks are observed even on cancellation; completed results retain their real timestamps.
                await Task.WhenAll(pending);
                RefreshServiceLabels();
                if (id == null) Keep(await Diagnostics.DnsProbe(ct));
                await RefreshInventory(ct);
            }
            finally { checkingServices.Clear(); RefreshServiceLabels(); }
        });
    }
    private void ShowService()
    {
        var service = ServiceCatalog.Get(selectedService);
        Header(service.Name, service.Scope);
        PageTools.Children.Add(Action("Назад", () => { Navigate("overview"); return Task.CompletedTask; }));
        PageTools.Children.Add(Action("Проверить снова", () => CheckServices(service.Id), true));
        var health = ServiceCatalog.Describe(service, ServiceResult(service), DateTimeOffset.Now);
        Notice(health.Label, health.Detail);
        PageContent.Children.Add(Muted(health.Freshness));
        PageContent.Children.Add(Text("Что можно сделать", 17, true));
        if (service.Id == "telegram")
        {
            PageContent.Children.Add(Muted("Для Telegram Desktop проверьте отдельный прокси. Результат Telegram Web не описывает его работу."));
            RowActions(Action("Управлять Telegram", () => { Navigate("components"); return Task.CompletedTask; }));
        }
        else if (service.Id is "youtube" or "discord")
        {
            PageContent.Children.Add(Muted("Если сайт не отвечает, можно проверить файлы и выполнить подбор FIX. После запуска отдельно проверьте видео или звонок."));
            RowActions(Action("Открыть FIX / Подбор", () => { Navigate("fix"); return Task.CompletedTask; }));
        }
        else if (service.Id == "instagram")
        {
            PageContent.Children.Add(Muted("Если имя сайта разрешается, но соединение не устанавливается, добавления домена в FIX может быть недостаточно. Требуется проверка маршрута. Xbox DNS и Telegram-прокси не подтверждают доступ к Instagram."));
            RowActions(Action("Проверка доступа", () => { Navigate("diagnostics"); return Task.CompletedTask; }));
        }
        else if (service.Id is "whatsapp" or "whatsapp-static")
        {
            PageContent.Children.Add(Muted("Если DNS выдаёт недоступный IP, один список доменов FIX не поможет. Connect может по отдельной команде найти доступный адрес, проверить HTTPS с обычной проверкой сертификата и временно записать только два имени WhatsApp в Windows hosts. VPN и общий DNS не меняются. IP может устареть; вход и сообщения приложения проверяйте отдельно."));
            WhatsAppHostsState? hosts = null;
            try { if (!qa) hosts = WindowsWhatsAppHosts.Inspect(); }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException)
            { PageContent.Children.Add(Muted("hosts не удалось прочитать: " + Redactor.Sanitize(error.Message))); }
            if (hosts?.Managed == true)
            {
                Notice("Временное сопоставление активно", "Откат удалит только блок, созданный Connect. Другие записи hosts сохраняются.");
                RowActions(Action("Убрать сопоставление WhatsApp", () => ManageWhatsAppHosts(true)));
            }
            else if (hosts?.External == true)
                Notice("В hosts уже есть записи WhatsApp", "Connect не изменяет чужие записи. Перед переходом на управление из приложения уберите их вручную после сохранения резервной копии.");
            else
                RowActions(Action("Найти адрес и временно применить", () => ManageWhatsAppHosts(false), true));
        }
        else
        {
            PageContent.Children.Add(Muted("Проверьте сайт в браузере. Если показана проверка браузера или отказ сайта, это не доказывает ошибку DNS. FIX не гарантирует доступ к этому сервису."));
            RowActions(Action("Настройки DNS", () => { Navigate("settings"); return Task.CompletedTask; }));
        }
        PageContent.Children.Add(Muted("Пробы Connect выполняют прямой HTTPS без системного прокси. DNS и маршрут браузера или Codex могут отличаться. Результаты старше 5 минут требуют повторной проверки."));
    }

    private Task ManageWhatsAppHosts(bool remove)
    {
        if (qa) { StatusText.Text = "QA: изменение hosts отключено."; return Task.CompletedTask; }
        var message = remove
            ? "Удалить только временный блок WhatsApp, созданный Connect? Приложение WhatsApp может потерять доступ. Остальной hosts останется без изменений."
            : "Найти доступный адрес WhatsApp и временно сопоставить web.whatsapp.com и static.whatsapp.net через Windows hosts? Потребуются права администратора. IP может устареть; для возврата есть отдельная кнопка. VPN, общий DNS и остальные домены не меняются.";
        if (MessageBox.Show(this, message, "WhatsApp / hosts", MessageBoxButton.YesNo,
            MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return Task.CompletedTask;
        return Run(remove ? "Откат WhatsApp hosts" : "Временный доступ WhatsApp", async ct =>
        {
            ct.ThrowIfCancellationRequested();
            var start = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!)
            {
                UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory,
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
            };
            start.ArgumentList.Add(remove ? "--whatsapp-hosts-remove" : "--whatsapp-hosts-apply");
            using var helper = System.Diagnostics.Process.Start(start)
                ?? throw new IOException("Windows не запустила помощника WhatsApp.");
            CancelButton.Visibility = Visibility.Collapsed; // The elevated operation cannot be cancelled from this window.
            await helper.WaitForExitAsync();
            var state = WindowsWhatsAppHosts.Inspect();
            if (helper.ExitCode != 0 || state.Managed == remove)
                throw new IOException("Помощник не выполнил правку. Проверьте, нет ли чужих записей WhatsApp в hosts; сеть не переключалась.");
        });
    }
}
