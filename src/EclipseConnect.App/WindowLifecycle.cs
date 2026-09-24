using System.Windows;
using System.Windows.Automation;
using EclipseConnect.Core;
using Forms = System.Windows.Forms;

namespace EclipseConnect.App;

public partial class MainWindow
{
    private Forms.NotifyIcon? tray;
    private Forms.ContextMenuStrip? trayMenu;
    private Forms.ToolStripMenuItem? trayProtection;
    private bool explicitExit;
    private bool sessionEnding;
    private WindowState restoreState = WindowState.Normal;

    private void InitializeTray()
    {
        TrayButton.IsEnabled = !qa;
        if (qa) return;
        try
        {
            trayMenu = new Forms.ContextMenuStrip();
            trayMenu.Items.Add("Открыть Connect", null, (_, _) => Dispatcher.Invoke(RestoreWindow));
            trayProtection = new Forms.ToolStripMenuItem("Защита включена") { Enabled = false };
            trayProtection.Click += (_, _) => Dispatcher.Invoke(() => { safety.Protect(); work?.Cancel(); Navigate(page); });
            trayMenu.Items.Add(trayProtection);
            trayMenu.Items.Add(new Forms.ToolStripSeparator());
            trayMenu.Items.Add("Выйти из Connect", null, (_, _) => Dispatcher.Invoke(() => { explicitExit = true; Close(); }));
            tray = new Forms.NotifyIcon
            {
                Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? System.Drawing.SystemIcons.Shield,
                Text = "Eclipse Connect: защита включена",
                ContextMenuStrip = trayMenu, Visible = true
            };
            tray.DoubleClick += (_, _) => Dispatcher.Invoke(RestoreWindow);
            Application.Current.SessionEnding += OnSessionEnding;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            DisposeTray(); TrayButton.IsEnabled = false;
            StatusText.Text = "Трей недоступен. Окно останется доступно на панели задач.";
        }
    }
    private void RefreshSafety()
    {
        SafetyButton.Content = safety.IsProtected ? "Разрешить управление" : "Заблокировать управление";
        SafetyStateLabel.Text = safety.IsProtected ? "Защита включена" : "Управление разрешено";
        AutomationProperties.SetName(SafetyButton, SafetyButton.Content.ToString());
        SafetyButton.ToolTip = safety.IsProtected ? "Запуск и остановка компонентов заблокированы" : "Заблокировать запуск и остановку компонентов";
        if (tray == null) return;
        tray.Text = safety.IsProtected ? "Eclipse Connect: защита включена" : "Eclipse Connect: управление разрешено";
        trayProtection!.Text = safety.IsProtected ? "Защита включена" : "Включить защиту подключений";
        trayProtection.Enabled = !safety.IsProtected;
    }
    private void ChangeSafety(object sender, RoutedEventArgs e)
    {
        if (!safety.IsProtected)
        {
            safety.Protect(); work?.Cancel(); Navigate(page); StatusText.Text = "Новые изменения заблокированы. Текущая операция отменяется, если она выполнялась.";
            return;
        }
        if (qa) { StatusText.Text = "QA: разрешение реального управления недоступно."; return; }
        if (work != null) { StatusText.Text = "Дождитесь завершения текущей операции."; return; }
        if (MessageBox.Show(this, "Разрешить ручное управление Telegram, FIX и VPN?\n\nЕсли важные задачи ещё идут, выберите «Нет». Разрешение действует до закрытия или сворачивания Connect в трей. Ни один компонент сейчас не будет запущен или остановлен.",
            "Разрешить управление?", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        safety.AllowForSession(true); Navigate(page);
        StatusText.Text = "Управление разрешено. Запуск и остановка по-прежнему требуют отдельного подтверждения.";
    }
    private void HideToTray(object sender, RoutedEventArgs e) => HideWindowToTray();
    private void ExitConnect(object sender, RoutedEventArgs e) { explicitExit = true; Close(); }
    private void HideWindowToTray()
    {
        if (tray == null) { StatusText.Text = "Трей недоступен. Окно не скрыто."; return; }
        if (WindowState != WindowState.Minimized) restoreState = WindowState;
        safety.Protect(); work?.Cancel(); RefreshSafety(); Hide();
    }
    private void RestoreWindow()
    {
        Show(); WindowState = restoreState; Activate(); Navigate(page);
    }
    private void OnSessionEnding(object sender, SessionEndingCancelEventArgs e)
    { sessionEnding = true; safety.Protect(); }
    private void DisposeTray()
    {
        Application.Current.SessionEnding -= OnSessionEnding;
        if (tray != null) { tray.Visible = false; tray.Dispose(); tray = null; }
        trayMenu?.Dispose(); trayMenu = null;
    }
    // Defense in depth: QA cannot reach sockets or Process.Start even if a handler regresses.
    private sealed class QaDenyHttp : System.Net.Http.HttpMessageHandler
    {
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(System.Net.Http.HttpRequestMessage request, CancellationToken ct)
            => throw new InvalidOperationException("HTTP is disabled in offline QA.");
    }
    private sealed class QaDenyRuntime : IProcessRuntime
    {
        public Task<ILaunchPreparation> Prepare(string path, string expectedHash, CancellationToken ct)
            => throw new InvalidOperationException("Component execution is disabled in offline QA.");
    }
}
