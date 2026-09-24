using System.Diagnostics;
using System.Security.Cryptography;

namespace EclipseConnect.Core;

public static class Inventory
{
    public static void Discover(AppSettings settings)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrEmpty(settings.TelegramPath) && Directory.Exists(desktop))
            settings.TelegramPath = Directory.EnumerateFiles(desktop, "TgWsProxy*.exe", SearchOption.TopDirectoryOnly).FirstOrDefault() ?? "";
        if (string.IsNullOrEmpty(settings.FixPath))
        {
            var parent = Path.GetDirectoryName(desktop);
            if (parent != null && File.Exists(Path.Combine(parent, "FIX", "bin", "winws.exe"))) settings.FixPath = Path.Combine(parent, "FIX", "bin", "winws.exe");
        }
    }
    public static async Task<InstalledComponent> Inspect(ComponentSpec spec, string path, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return new(spec, path, "", "Не определена",
            spec == Catalog.Telegram ? CountTelegramProcesses() : CountFixProcesses());
        if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Выберите EXE компонента.");
        Storage.AssertNoLinks(path);
        var info = new FileInfo(path);
        if (info.Length > 256 * 1024 * 1024) throw new InvalidDataException("Компонент слишком большой.");
        await using var file = File.OpenRead(path);
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(file, ct)).ToLowerInvariant();
        var version = Catalog.KnownVersion(spec, hash);
        return new(spec, Path.GetFullPath(path), hash, version, spec == Catalog.Telegram ? CountTelegramProcesses() : CountFixProcesses());
    }
    public static int CountFixProcesses()
    {
        var count = 0;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { if (process.ProcessName.ToLowerInvariant() is "winws" or "winws2" or "goodbyedpi") count++; }
                catch (InvalidOperationException) { }
            }
        }
        return count; // Observation only. A name never grants ownership or authority to stop.
    }
    public static int CountTelegramProcesses()
    {
        var count = 0;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { if (process.ProcessName.StartsWith("TgWsProxy", StringComparison.OrdinalIgnoreCase)) count++; }
                catch (InvalidOperationException) { }
            }
        }
        return count;
    }
    public static int CountProcesses(string path)
    {
        var count = 0;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { if (string.Equals(process.MainModule?.FileName, path, StringComparison.OrdinalIgnoreCase)) count++; }
                catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
        return count;
    }
}
