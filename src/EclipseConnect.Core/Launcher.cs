using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Cryptography;

namespace EclipseConnect.Core;

public interface IManagedProcess : IDisposable
{
    bool IsRunning { get; }
    void Stop();
}
public interface ILaunchPreparation : IDisposable
{
    bool ExternalRunning { get; }
    bool PortBusy { get; }
    bool HashKnown { get; }
    IManagedProcess Start();
}
public interface IProcessRuntime
{
    Task<ILaunchPreparation> Prepare(string path, string expectedHash, CancellationToken ct);
}

public sealed class Launcher(SessionSafety safety, IProcessRuntime? runtime = null) : IDisposable
{
    private readonly IProcessRuntime runtime = runtime ?? new WindowsProcessRuntime();
    private readonly object sync = new();
    private IManagedProcess? owned;
    private int busy;
    private bool disposed;
    public bool OwnsRunningProcess { get { lock (sync) return owned?.IsRunning == true; } }
    public static string? BlockReason(bool confirmed, bool externalRunning, bool portBusy, bool hashKnown)
    {
        if (!confirmed) return "Запуск требует явного подтверждения.";
        if (externalRunning) return "Telegram-прокси уже запущен вне Connect. Он не будет остановлен.";
        if (portBusy) return "Порт из настроек Telegram-прокси занят. Запуск второго прокси запрещён.";
        if (!hashKnown) return "Версия файла не подтверждена. Сначала подготовьте официальный релиз.";
        return null;
    }
    private void Enter()
    {
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0) throw new InvalidOperationException("Другая операция с компонентом ещё выполняется.");
    }
    public async Task StartTelegram(string path, string expectedHash, bool confirmed, CancellationToken ct)
    {
        Enter();
        try
        {
            var permit = safety.CapturePermit();
            ct.ThrowIfCancellationRequested();
            if (!confirmed) throw new InvalidOperationException(BlockReason(false, false, false, true));
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                if (owned?.IsRunning == true) throw new InvalidOperationException("Компонент уже запущен из Connect.");
            }
            using var prepared = await runtime.Prepare(path, expectedHash, ct);
            var reason = BlockReason(confirmed, prepared.ExternalRunning, prepared.PortBusy, prepared.HashKnown);
            if (reason != null) throw new InvalidOperationException(reason);
            safety.Commit(permit, ct, () =>
            {
                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposed, this);
                    owned?.Dispose(); owned = null;
                    owned = prepared.Start();
                    return true;
                }
            });
        }
        finally { Volatile.Write(ref busy, 0); }
    }
    public void StopOwned(bool confirmed)
    {
        Enter();
        try
        {
            var permit = safety.CapturePermit();
            if (!confirmed) throw new InvalidOperationException("Остановка требует подтверждения.");
            safety.Commit(permit, default, () =>
            {
                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposed, this);
                    if (owned?.IsRunning != true) throw new InvalidOperationException("У Connect нет своего работающего процесса.");
                    // Retain ownership when Windows refuses a stop, so a later explicit retry is possible.
                    owned.Stop(); owned.Dispose(); owned = null;
                    return true;
                }
            });
        }
        finally { Volatile.Write(ref busy, 0); }
    }
    // Closing releases handles only. It never disconnects the component.
    public void Dispose()
    {
        safety.Protect();
        lock (sync) { disposed = true; owned?.Dispose(); owned = null; }
    }
}

internal sealed class WindowsProcessRuntime : IProcessRuntime
{
    public async Task<ILaunchPreparation> Prepare(string path, string expectedHash, CancellationToken ct)
    {
        Storage.AssertNoLinks(path);
        if (!Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Выберите EXE-файл Telegram-прокси.");
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (file.Length > 256L * 1024 * 1024) throw new InvalidDataException("Файл компонента слишком большой.");
            var actual = Convert.ToHexString(await SHA256.HashDataAsync(file, ct));
            return new Preparation(path, file, expectedHash.Length == 64 && actual.Equals(expectedHash, StringComparison.OrdinalIgnoreCase), TelegramEndpoint.Read(path).Port);
        }
        catch { file.Dispose(); throw; }
    }
    private static bool External(string path)
    {
        var external = Inventory.CountProcesses(path) > 0;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { external |= process.ProcessName.StartsWith("TgWsProxy", StringComparison.OrdinalIgnoreCase); }
                catch (InvalidOperationException) { }
            }
        }
        return external;
    }
    private sealed class Preparation(string path, FileStream file, bool hashKnown, int port) : ILaunchPreparation
    {
        public bool ExternalRunning => External(path);
        public bool PortBusy => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e => e.Port == port);
        public bool HashKnown => hashKnown;
        public IManagedProcess Start()
        {
            // Recheck immediately before execution; the verified file remains locked against writes.
            var reason = Launcher.BlockReason(true, ExternalRunning, PortBusy, HashKnown);
            if (reason != null) throw new InvalidOperationException(reason);
            var process = Process.Start(new ProcessStartInfo(path) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(path)!, CreateNoWindow = true })
                ?? throw new InvalidOperationException("Windows не запустила компонент.");
            return new OwnedProcess(process);
        }
        public void Dispose() => file.Dispose();
    }
    private sealed class OwnedProcess(Process process) : IManagedProcess
    {
        public bool IsRunning => !process.HasExited;
        public void Stop()
        {
            process.Kill(entireProcessTree: true);
            if (!process.WaitForExit(5000)) throw new IOException("Прокси не подтвердил остановку. Повторный запуск запрещён.");
        }
        public void Dispose() => process.Dispose();
    }
}
