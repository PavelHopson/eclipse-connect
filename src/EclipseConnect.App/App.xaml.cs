using System.IO;
using System.Windows;
using EclipseConnect.Core;

namespace EclipseConnect.App;
public partial class App : Application
{
    private Mutex? instance;
    private async void OnStartup(object sender, StartupEventArgs e)
    {
        try
        {
            var qa = e.Args.Contains("--qa") || e.Args.Contains("--self-test");
            var root = qa ? Path.Combine(AppContext.BaseDirectory, "qa-data") :
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EclipseConnect");
            var storage = new Storage(root);
            if (e.Args.Contains("--vpn-agent"))
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                if (qa || e.Args.Length != 4 || e.Args[0] != "--vpn-agent" ||
                    !int.TryParse(e.Args[2], out var vpnParentId) || !long.TryParse(e.Args[3], out var vpnParentStart))
                    throw new InvalidDataException("Неверные параметры помощника VPN.");
                await WindowsAwgAgent.Run(storage, e.Args[1], vpnParentId, vpnParentStart);
                Shutdown(0); return;
            }
            if (e.Args.Contains("--fix-agent"))
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                if (qa || e.Args.Length != 4 || e.Args[0] != "--fix-agent" ||
                    !int.TryParse(e.Args[2], out var parentId) || !long.TryParse(e.Args[3], out var parentStart))
                    throw new InvalidDataException("Неверные параметры помощника.");
                await WindowsFixAgent.Run(storage, e.Args[1], parentId, parentStart);
                Shutdown(0); return;
            }
            if (e.Args.Any(arg => arg is "--whatsapp-hosts-apply" or "--whatsapp-hosts-remove"))
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                if (qa || e.Args.Length != 1 || !WindowsFixRuntime.IsAdministrator())
                    throw new InvalidDataException("Неверный запуск помощника WhatsApp.");
                var operation = e.Args[0];
                try
                {
                    if (operation == "--whatsapp-hosts-apply")
                        await WindowsWhatsAppHosts.Apply(storage, CancellationToken.None);
                    else WindowsWhatsAppHosts.Remove(storage);
                    try { storage.AtomicJson("reports/whatsapp-hosts-last.json",
                        new { Operation = operation, Success = true, Detail = "Правка завершена." }); }
                    catch (IOException) { }
                    Shutdown(0); return;
                }
                catch (Exception error)
                {
                    try { storage.AtomicJson("reports/whatsapp-hosts-last.json",
                        new { Operation = operation, Success = false, Detail = Redactor.Sanitize(error.Message) }); }
                    catch (IOException) { }
                    Shutdown(2); return;
                }
            }
            if (e.Args.Contains("--prepare-telegram"))
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                if (!e.Args.Contains("--confirm-prepare") || qa) throw new InvalidOperationException("Подготовка требует явного подтверждения.");
                foreach (var existing in System.Diagnostics.Process.GetProcessesByName("Eclipse Connect"))
                {
                    using (existing)
                        if (existing.Id != Environment.ProcessId) throw new InvalidOperationException("Закройте другие окна Connect перед выбором версии.");
                }
                using var updater = new Updates(storage);
                var release = await updater.Check(Catalog.Telegram, default);
                var asset = release.Assets.Single(a => a.Name == Catalog.Telegram.AssetName);
                var prepared = await updater.Prepare(Catalog.Telegram, release, asset, null, default);
                var settings = storage.LoadSettings(); Inventory.Discover(settings);
                new VersionSelection(storage).Select(settings, prepared.Path);
                storage.AtomicJson("reports/telegram-preparation.json", new { prepared.Tag, prepared.Sha256, Selected = true, Started = false });
                Shutdown(0); return;
            }
            if (e.Args.Contains("--fix-control"))
            {
                if (qa || !WindowsFixRuntime.IsAdministrator()) throw new InvalidOperationException("Окно FIX требует подтверждения прав Windows.");
                instance = new Mutex(true, @"Local\EclipseConnect.FixControl", out var created);
                if (!created) { instance.Dispose(); instance = null; MessageBox.Show("Окно FIX уже открыто. Второй контроллер не запускается.", "Connect"); Shutdown(0); return; }
                var settings = storage.LoadSettings(); Inventory.Discover(settings);
                var control = new FixWindow(storage, settings.FixPath);
                MainWindow = control; control.Show(); return;
            }
            if (!qa)
            {
                instance = new Mutex(true, @"Local\EclipseConnect.Main", out var created);
                if (!created) { instance.Dispose(); instance = null; MessageBox.Show("Connect уже работает. Откройте его через значок рядом с часами.", "Connect"); Shutdown(0); return; }
            }
            var window = new MainWindow(storage, qa);
            MainWindow = window; window.Show();
            if (e.Args.Contains("--self-test")) awaitSelfTest(window);
        }
        catch (Exception error)
        {
            if (e.Args.Contains("--fix-agent") || e.Args.Contains("--vpn-agent") ||
                e.Args.Any(arg => arg is "--whatsapp-hosts-apply" or "--whatsapp-hosts-remove"))
            {
                // Never block a headless helper on an invisible dialog or log private IPC data.
                Shutdown(1); return;
            }
            if (e.Args.Contains("--prepare-telegram"))
            {
                try { new Storage(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EclipseConnect"))
                    .AtomicJson("reports/telegram-preparation-error.json", new { Error = Redactor.Sanitize(error.Message) }); }
                catch (Exception) { /* A headless failure must not block waiting for an invisible dialog. */ }
                Shutdown(1); return;
            }
            MessageBox.Show("Не удалось открыть Eclipse Connect. Настройки сети не изменены.\n\n" + Redactor.Sanitize(error.Message),
                "Eclipse Connect", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }
    protected override void OnExit(ExitEventArgs e)
    {
        if (instance != null) { instance.ReleaseMutex(); instance.Dispose(); instance = null; }
        base.OnExit(e);
    }
    private async void awaitSelfTest(MainWindow window)
    {
        var result = await window.RunRenderTests();
        Shutdown(result);
    }
}
