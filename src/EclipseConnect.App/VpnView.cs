using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using EclipseConnect.Core;
using Microsoft.Win32;

namespace EclipseConnect.App;

public partial class MainWindow
{
    private WindowsAwgLink? vpnLink;
    private AwgState? qaVpnState;
    private bool qaVpnProfile;
    private string? qaVpnError;
    private bool qaVpnRoutesExpired;
    private bool qaVpnFixMissing;
    private bool qaVpnReserve;
    private AwgProfileSlot selectedVpnSlot = AwgProfileSlot.Primary;
    private readonly Dictionary<string, (TextBlock State, TextBlock Detail)> vpnServiceLabels = [];
    private DateTimeOffset? vpnCheckedAt;
    private void ShowVpn()
    {
        Header("VPN + FIX", "Instagram и WhatsApp через VPN · YouTube и RuTracker через FIX.");
        var routesCurrent = qa ? !qaVpnRoutesExpired : MetaVpnPolicy.IsCurrent(DateTimeOffset.UtcNow);
        AwgProfile? profile = null; string? profileError = qa ? qaVpnError : null;
        if (!qa)
        {
            try { profile = new AwgProfileStore(storage, selectedVpnSlot).Load(); }
            catch (Exception e) when (e is IOException or CryptographicException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
            { profileError = "Не удалось прочитать VPN-профиль. Файл сохранён; можно повторно импортировать .conf."; }
        }
        var hasProfile = qa ? qaVpnProfile : profile != null;
        var state = qa ? qaVpnState ?? AwgState.Off : vpnLink?.Connected == true ? vpnLink.LastState ?? AwgState.Off :
            new AwgState(false, false, vpnLink == null ? "Подключение не запущено из этого окна." : "Связь с помощником потеряна. Он завершает собственные FIX и VPN; проверьте сеть.");
        var enginePresent = qa || WindowsAwgEngine.BundlePresent;
        var helperLost = !qa && vpnLink != null && !vpnLink.Connected;
        var canChange = AwgProfileSelection.CanChange(state, helperLost);
        var reservePresent = qa ? qaVpnReserve : new AwgProfileStore(storage, AwgProfileSlot.Reserve).Exists;
        var fixPresent = qa ? !qaVpnFixMissing : !string.IsNullOrWhiteSpace(settings.FixPath) && File.Exists(settings.FixPath);
        if (hasProfile && safety.IsProtected)
        {
            var allow = Action("Разрешить управление", () => { ChangeSafety(this, new RoutedEventArgs()); return Task.CompletedTask; }, true);
            allow.IsEnabled = !qa; PageTools.Children.Add(allow);
        }
        if (state.Running)
        {
            var stop = Action("Отключить VPN + FIX", DisconnectVpn, !safety.IsProtected);
            stop.IsEnabled = !qa && !safety.IsProtected && vpnLink?.Connected == true; PageTools.Children.Add(stop);
        }
        else
        {
            var connect = Action("Подключить VPN + FIX", ConnectVpn, hasProfile && !safety.IsProtected);
            connect.IsEnabled = !qa && canChange && hasProfile && profileError == null && enginePresent && fixPresent && routesCurrent && !safety.IsProtected; PageTools.Children.Add(connect);
        }
        if (!fixPresent)
        {
            var choose = Action("Выбрать FIX", () => { Navigate("components"); return Task.CompletedTask; }, true);
            choose.IsEnabled = !qa; PageTools.Children.Add(choose);
        }
        var import = Action(hasProfile || profileError != null ? "Заменить профиль" : "Импортировать .conf", ImportVpn, !hasProfile && profileError == null);
        import.IsEnabled = !qa && canChange; PageTools.Children.Add(import);
        var refresh = Action("Обновить состояние", () => Run("Проверка состояния VPN", async ct =>
        {
            if (qa || vpnLink?.Connected != true) throw new InvalidOperationException("Помощник VPN не подключён.");
            await vpnLink.Execute("status", null, false, ct); vpnCheckedAt = DateTimeOffset.Now;
        }));
        refresh.IsEnabled = !qa && vpnLink?.Connected == true; PageTools.Children.Add(refresh);
        if (!fixPresent && !state.Running) Notice("Не найден FIX", "Выберите FIX кнопкой сверху. До проверки его файлов подключение не запускается.");
        else Notice(state.Authenticated ? "VPN + FIX подключены" : state.Running ? "Соединение не подтверждено" : vpnLink != null && !vpnLink.Connected ? "Состояние требует проверки" : "Подключение отключено", state.Message);
        PageContent.Children.Add(Text("Профиль: " + AwgProfileSelection.Name(selectedVpnSlot), 16, true));
        var profileChoice = new ComboBox { Width = 280, HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new(0, 0, 0, 10), IsEnabled = !qa && canChange,
            ItemsSource = new[] { "Основной", reservePresent ? "Резервный" : "Резервный — не настроен" }, SelectedIndex = (int)selectedVpnSlot };
        System.Windows.Automation.AutomationProperties.SetName(profileChoice, "VPN-профиль для следующего подключения");
        profileChoice.SelectionChanged += (_, _) =>
        {
            if (work != null || qa || !canChange || profileChoice.SelectedIndex is < 0 or > 1) return;
            selectedVpnSlot = (AwgProfileSlot)profileChoice.SelectedIndex; Navigate("vpn");
        };
        PageContent.Children.Add(profileChoice);
        if (!canChange) PageContent.Children.Add(Muted(helperLost
            ? "Связь с помощником потеряна. Дождитесь остановки собственных компонентов и перезапустите Connect; выбор и импорт профилей заблокированы."
            : "Для выбора другого профиля сначала отключите VPN + FIX."));
        PageContent.Children.Add(Text("Через VPN — сети Instagram, Facebook и WhatsApp.", 15, true));
        PageContent.Children.Add(Text("Через ограниченный FIX — YouTube и RuTracker.", 15, true));
        PageContent.Children.Add(Muted("Остальной трафик, включая Codex, сохраняет обычный маршрут. Общий DNS не меняется. Это не VPN для всего интернета."));
        if (!state.Running) PageContent.Children.Add(Muted("WhatsApp для Windows показывает «Подключение»? Eclipse Connect сейчас не направляет его через VPN. Подключите VPN + FIX кнопкой сверху, затем проверьте приложение."));
        if (!routesCurrent) Notice("Список сетей устарел", "Нужна новая версия Connect или проверка даты Windows. Новое подключение заблокировано; работающий VPN можно отключить.");
        if (vpnCheckedAt is { } time) PageContent.Children.Add(Muted("Состояние проверено в " + time.ToLocalTime().ToString("HH:mm:ss") + ". Это снимок, не фоновый мониторинг."));
        if (profileError != null) Notice("Профиль недоступен", profileError);
        else if (hasProfile)
        {
            PageContent.Children.Add(Text(state.Running ? "Активный профиль" : "Профиль готов к подключению", 16, true));
            PageContent.Children.Add(Muted($"Instagram / Meta · IPv4 + IPv6 · MTU {profile?.Mtu ?? 1280} · пакетов маскировки: {profile?.SignaturePackets ?? 1}."));
            PageContent.Children.Add(Muted("Ключ защищён Windows и не отображается. Замена профиля не подключает VPN; предыдущая зашифрованная копия сохраняется."));
        }
        else
            PageContent.Children.Add(Text("Выберите экспортированный из Amnezia файл .conf. Ключ остаётся на этом компьютере — вставлять его в чат не нужно."));
        if (!enginePresent) Notice("Не найден VPN-движок", "Нужна полная сборка Connect с папкой components. Файлы установленного AmneziaVPN не подменяются и не используются вслепую.");
        if (hasProfile && safety.IsProtected) PageContent.Children.Add(Muted("Защита включена: разрешите управление кнопкой сверху. Это само по себе не изменяет сеть."));
        string reserveHint;
        if (qa) reserveHint = qaVpnReserve ? "Резерв сохранён. Независимость инфраструктуры не подтверждена." : AwgProfileSelection.ReserveHint(null, null);
        else
        {
            try { reserveHint = AwgProfileSelection.ReserveHint(new AwgProfileStore(storage).Load(), new AwgProfileStore(storage, AwgProfileSlot.Reserve).Load()); }
            catch (Exception e) when (e is IOException or CryptographicException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
            { reserveHint = "Один из профилей недоступен; сравнение резерва не выполнено. Выберите профиль, чтобы проверить его состояние."; }
        }
        PageContent.Children.Add(Muted(reserveHint));
        if (!reservePresent)
        {
            var addReserve = Action("Добавить резервный .conf", () => ImportVpn(AwgProfileSlot.Reserve));
            addReserve.IsEnabled = !qa && canChange; RowActions(addReserve);
        }
        PageContent.Children.Add(Muted("Автоматического переключения нет. Выбор профиля сам по себе не меняет сеть; при новом запуске выбран основной."));
        Rule();
        PageContent.Children.Add(Text("Проверить доступ", 16, true));
        var checkAll = Action("Проверить доступ", () => CheckServices(null, ["instagram", "whatsapp", "whatsapp-static", "youtube", "rutracker", "chatgpt"]));
        checkAll.IsEnabled = !qa; PageTools.Children.Add(checkAll);
        PageContent.Children.Add(Muted("Instagram · WhatsApp и файлы · YouTube · RuTracker · ChatGPT. Прямой HTTPS без системного прокси; маршруты и DNS не меняются."));
        foreach (var id in new[] { "instagram", "whatsapp", "whatsapp-static", "youtube", "rutracker", "chatgpt" })
        {
            var service = ServiceCatalog.Get(id);
            var result = ServiceResult(service);
            if (result == null) continue;
            var health = ServiceCatalog.Describe(service, result, DateTimeOffset.Now);
            var label = Text(service.Name + ": " + health.Label, 14, true);
            label.SetResourceReference(TextBlock.ForegroundProperty, health.Tone + "Brush");
            PageContent.Children.Add(label);
            var detail = Muted(health.Detail + " " + health.Freshness);
            PageContent.Children.Add(detail);
            vpnServiceLabels[id] = (label, detail);
        }
        if (!new[] { "instagram", "whatsapp", "whatsapp-static", "youtube", "rutracker", "chatgpt" }.Any(id => ServiceResult(ServiceCatalog.Get(id)) != null))
            PageContent.Children.Add(Muted("Проверок ещё нет. Кнопка «Проверить доступ» находится сверху и не включает VPN."));
        PageContent.Children.Add(Muted("Подтверждение VPN-сервера и HTTPS-ответ WhatsApp не доказывают работу входа, сообщений и звонков. Проба ChatGPT не проверяет авторизацию и ответы Codex — отправьте отдельное сообщение в Codex."));
        PageContent.Children.Add(Muted("Список сетей от " + MetaVpnPolicy.ObservedAt.ToString("dd.MM.yyyy") + ". Внешние CDN и другие заблокированные сервисы могут потребовать отдельной поддержки."));
        Rule();
        PageContent.Children.Add(Muted("Нет автозапуска подключения. При выходе останавливаются собственные FIX и VPN; трей сохраняет их. Отдельный FIX и другие VPN должны быть выключены вами. Чужие процессы Connect не останавливает."));
    }
    private void RefreshVpnServiceLabels()
    {
        foreach (var pair in vpnServiceLabels)
        {
            var service = ServiceCatalog.Get(pair.Key);
            var health = ServiceCatalog.Describe(service, ServiceResult(service), DateTimeOffset.Now, checkingServices.Contains(pair.Key));
            pair.Value.State.Text = service.Name + ": " + health.Label;
            pair.Value.State.SetResourceReference(TextBlock.ForegroundProperty, health.Tone + "Brush");
            pair.Value.Detail.Text = health.Detail + " " + health.Freshness;
        }
    }
    private Task ImportVpn() => ImportVpn(selectedVpnSlot);
    private async Task ImportVpn(AwgProfileSlot slot)
    {
        if (qa) throw new InvalidOperationException("Импорт реальных профилей отключён в QA.");
        if (!AwgProfileSelection.CanChange(vpnLink?.LastState ?? AwgState.Off, vpnLink != null && !vpnLink.Connected)) throw new InvalidOperationException("Отключите VPN и подтвердите остановку перед импортом профиля.");
        var dialog = new OpenFileDialog { Title = "Импорт AmneziaWG — " + AwgProfileSelection.Name(slot), Filter = "Профиль AmneziaWG (*.conf)|*.conf", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        var candidate = await Task.Run(() => AwgProfile.ReadLocalFile(dialog.FileName));
        if (!AwgProfileSelection.CanChange(vpnLink?.LastState ?? AwgState.Off, vpnLink != null && !vpnLink.Connected)) throw new InvalidOperationException("Состояние подключения изменилось. Импорт отменён; сначала отключите VPN.");
        var store = new AwgProfileStore(storage, slot); var exists = store.Exists;
        if (MessageBox.Show(this, (exists ? "Заменить сохранённый VPN-профиль? Предыдущая зашифрованная копия останется локально.\n\n" : "Сохранить VPN-профиль на этом компьютере?\n\n") +
            $"Слот: {AwgProfileSelection.Name(slot)}. Другой слот не изменится.\nРежим Instagram / Meta, MTU {candidate.Mtu}, пакетов маскировки: {candidate.SignaturePackets}.\nИсходный профиль не изменится. Общие DNS и default routes из него не применяются. Ключ будет защищён Windows. Подключение сейчас не включится.",
            "Импорт AmneziaWG", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Run("Импорт VPN-профиля", ct => Task.Run(() => { ct.ThrowIfCancellationRequested(); store.Save(candidate, exists); }, ct));
    }
    private async Task ConnectVpn()
    {
        if (qa) throw new InvalidOperationException("VPN отключён в QA.");
        if (!AwgProfileSelection.CanChange(vpnLink?.LastState ?? AwgState.Off, vpnLink != null && !vpnLink.Connected)) throw new InvalidOperationException("Сначала отключите текущее подключение и подтвердите его остановку.");
        var permit = safety.CapturePermit();
        var slot = selectedVpnSlot;
        var profile = new AwgProfileStore(storage, slot).Load() ?? throw new InvalidOperationException("Выбранный профиль отсутствует. Сначала импортируйте .conf.");
        MetaVpnPolicy.RequireCurrent(DateTimeOffset.UtcNow);
        if (string.IsNullOrWhiteSpace(settings.FixPath) || !File.Exists(settings.FixPath)) { Navigate("components"); return; }
        if (MessageBox.Show(this, "Профиль: " + AwgProfileSelection.Name(slot) + ". Подключить VPN и ограниченный FIX вместе?\n\nInstagram и WhatsApp — через выборочный IPv4/IPv6 VPN. YouTube и RuTracker — через FIX. Основной маршрут и общий DNS не меняются. Совместимость с Codex и WhatsApp для Windows нужно проверить после подключения.\n\nОтдельный FIX и другие VPN должны быть отключены вами. Чужие процессы Connect не останавливает. Windows запросит права администратора. При выходе собственные FIX и VPN остановятся.",
            "Подключить VPN + FIX?", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Run("Подключение VPN и ограниченного FIX", async ct =>
        {
            safety.Commit(permit, ct, () => true);
            if (vpnLink?.Connected != true) { vpnLink?.Dispose(); vpnLink = await WindowsAwgLink.Open(ct); }
            safety.Commit(permit, ct, () => true);
            try { await vpnLink.Execute("start", profile.Revision, true, ct, slot); }
            finally { results.Clear(); vpnCheckedAt = DateTimeOffset.Now; }
        });
    }
    private async Task DisconnectVpn()
    {
        if (qa || vpnLink?.Connected != true) throw new InvalidOperationException("Нет собственного VPN-подключения для управления.");
        var permit = safety.CapturePermit();
        if (MessageBox.Show(this, "Отключить FIX и VPN этого окна? Соединения через них могут прерваться. Другие подключения не изменяются.",
            "Отключить VPN + FIX?", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Run("Отключение FIX и VPN", async ct =>
        {
            safety.Commit(permit, ct, () => true);
            try { await vpnLink.Execute("stop", null, true, ct); }
            finally { results.Clear(); vpnCheckedAt = DateTimeOffset.Now; }
        });
    }
}
