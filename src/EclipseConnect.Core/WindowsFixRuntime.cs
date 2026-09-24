using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public sealed class WindowsFixRuntime(string enginePath, Storage storage) : IFixRuntime
{
    public static readonly IReadOnlyDictionary<string, string> BinaryHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["bin/winws.exe"] = "31d68a175abebab19f7f39bf6d0845ec5c18ab653eeeea6ee830b22d799b7e55",
        ["bin/WinDivert.dll"] = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
        ["bin/WinDivert64.sys"] = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
        ["bin/cygwin1.dll"] = "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b"
    };
    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    private static bool AnyProcess(params string[] names)
    {
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { if (names.Contains(process.ProcessName, StringComparer.OrdinalIgnoreCase)) return true; }
                catch (InvalidOperationException) { }
            }
        }
        return false;
    }
    public bool HasExternalEngine => AnyProcess("winws", "winws2", "goodbyedpi");
    public bool HasConfoundingTunnel => AnyProcess("Happ", "sing-box", "xray", "v2ray", "clash", "clash-verge", "nekobox") || WindowsAwgEngine.HasActiveTunnel();
    public static string Root(string path)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(path, @"^[A-Za-z]:[\\/]") || path[2..].Contains(':'))
            throw new InvalidDataException("FIX должен находиться на локальном диске, не на сетевом ресурсе или ADS.");
        if (!Path.GetFileName(path).Equals("winws.exe", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Выберите FIX/bin/winws.exe.");
        var root = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(path)))!;
        Storage.AssertNoLinks(root); return root;
    }
    public static async Task<int> InspectResources(string enginePath, string profileId, CancellationToken ct)
    {
        var root = Root(enginePath); var resources = FixCatalog.Resources(profileId, false);
        foreach (var relative in resources)
        {
            if (relative == TelegramFixCompatibility.ResourcePath)
            {
                await using var generated = TelegramFixCompatibility.OpenResource();
                if (generated.Length == 0 || generated.Length > 32 * 1024) throw new InvalidDataException("Неверный список совместимости Telegram.");
                continue;
            }
            var path = Path.Combine(root, relative); Storage.AssertNoLinks(path);
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length > 32 * 1024 * 1024) throw new InvalidDataException("Ресурс FIX слишком большой.");
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(input, ct)).ToLowerInvariant();
            if (BinaryHashes.TryGetValue(relative, out var expected) && expected != hash) throw new InvalidDataException("Не подтверждён " + relative);
        }
        return resources.Length;
    }
    public async Task<IManagedProcess> Start(string profileId, bool gaming, CancellationToken ct)
    {
        FixCatalog.Get(profileId);
        return await StartCore(FixCatalog.Arguments(profileId, gaming), FixCatalog.Resources(profileId, gaming), null, ct);
    }
    internal Task<IManagedProcess> StartCompanion(int endpointPort, WindowsAwgRuntime owner, CancellationToken ct) =>
        StartCore(WebFixPolicy.Arguments(endpointPort), WebFixPolicy.Resources, owner, ct);
    internal async Task InspectCompanion(CancellationToken ct)
    {
        var root = Root(enginePath);
        foreach (var relative in WebFixPolicy.Resources)
        {
            var path = Path.Combine(root, relative); Storage.AssertNoLinks(path);
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length == 0 || input.Length > 32 * 1024 * 1024) throw new InvalidDataException("Неверный ресурс FIX.");
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(input, ct)).ToLowerInvariant();
            if (BinaryHashes.TryGetValue(relative, out var expected) && hash != expected) throw new InvalidDataException("Версия FIX не подтверждена.");
        }
    }
    private async Task<IManagedProcess> StartCore(string[] arguments, string[] resources, WindowsAwgRuntime? companionOwner, CancellationToken ct)
    {
        if (!IsAdministrator()) throw new InvalidOperationException("Для драйвера откройте отдельное окно FIX с правами администратора.");
        void Guard()
        {
            if (HasExternalEngine) throw new InvalidOperationException("Внешний FIX уже работает. Connect не будет его останавливать.");
            if (companionOwner != null) companionOwner.AssertCompanionAllowed();
            else if (HasConfoundingTunnel) throw new InvalidOperationException("Сначала отключите VPN/туннель в его управляющей программе. Совместный запуск отдельного FIX запрещён.");
        }
        Guard();
        var root = Root(enginePath);
        // Copy only approved resources. Never load DLLs from the original collection's working directory.
        var session = storage.Resolve("fix-sessions/" + Guid.NewGuid().ToString("N"));
        var locks = new List<FileStream>();
        Process? process = null; ProcessJob? job = null;
        var modeLease = companionOwner == null ? WindowsNetworkModeLease.Acquire() : null;
        try
        {
            foreach (var relative in resources)
            {
                var source = Path.Combine(root, relative); Storage.AssertNoLinks(source);
                await using Stream input = relative == TelegramFixCompatibility.ResourcePath
                    ? TelegramFixCompatibility.OpenResource()
                    : new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (input.Length > 32 * 1024 * 1024) throw new InvalidDataException("Слишком большой ресурс FIX: " + relative);
                var hash = Convert.ToHexString(await SHA256.HashDataAsync(input, ct)).ToLowerInvariant();
                if (BinaryHashes.TryGetValue(relative, out var expected) && hash != expected) throw new InvalidDataException("Не подтверждён " + relative + ". Запуск запрещён.");
                input.Position = 0;
                var destination = Path.Combine(session, relative);
                Storage.AssertNoLinks(destination); Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { await input.CopyToAsync(output, ct); output.Flush(true); }
                var locked = new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read); locks.Add(locked);
                var copiedHash = Convert.ToHexString(await SHA256.HashDataAsync(locked, ct)).ToLowerInvariant();
                if (hash != copiedHash) throw new InvalidDataException("Ресурс изменён при подготовке. Запуск запрещён.");
            }
            ct.ThrowIfCancellationRequested();
            Guard();
            var start = new ProcessStartInfo(Path.Combine(session, "bin/winws.exe"))
            { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.Combine(session, "bin") };
            foreach (var arg in arguments)
            {
                var equals = arg.IndexOf('=');
                var value = equals >= 0 ? arg[(equals + 1)..] : "";
                start.ArgumentList.Add(value.StartsWith("bin/") || value.StartsWith("lists/") ? arg[..(equals + 1)] + Path.Combine(session, value) : arg);
            }
            job = new ProcessJob();
            process = Process.Start(start) ?? throw new InvalidOperationException("Windows не запустила winws.");
            job.Assign(process);
            await Task.Delay(1600, ct);
            if (process.HasExited) throw new InvalidOperationException("FIX завершился при запуске (код " + process.ExitCode + "). Проверьте совместимость драйвера; защита Windows не отключалась.");
            return new FixOwned(process, job, locks, modeLease);
        }
        catch
        {
            try { if (process is { HasExited: false }) { process.Kill(true); process.WaitForExit(5000); } }
            finally
            {
                try { job?.Dispose(); process?.Dispose(); foreach (var file in locks) file.Dispose(); }
                finally { modeLease?.Dispose(); }
            }
            throw;
        }
    }
    public async Task<FixProbe> Probe(CancellationToken ct)
    {
        // No system HTTP proxy, cookies, credentials, redirects, body logs, or TLS bypass.
        // A TUN can still change this route; the selector rejects known tunnel processes.
        using var handler = new HttpClientHandler { UseProxy = false, UseCookies = false, AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("EclipseConnect/0.2 connectivity-test");
        async Task<bool> Check(string url)
        {
            try
            {
                using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
                return response.StatusCode == HttpStatusCode.OK && !response.Headers.Contains("cf-mitigated");
            }
            catch (HttpRequestException) { return false; }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
        }
        var checks = await Task.WhenAll(Check("https://api.github.com/"), Check("https://www.youtube.com/"), Check("https://discord.com/"));
        return new(checks[0], new Dictionary<string, bool> { ["youtube"] = checks[1], ["discord"] = checks[2] });
    }
    private sealed class FixOwned(Process process, ProcessJob job, List<FileStream> locks, WindowsNetworkModeLease? modeLease) : IManagedProcess
    {
        public bool IsRunning => !process.HasExited;
        public void Stop()
        {
            if (!process.HasExited) process.Kill(true);
            if (!process.WaitForExit(5000)) throw new IOException("FIX не подтвердил остановку. Новый профиль не запускается.");
            modeLease?.Dispose();
        }
        // FIX differs from Telegram: the explicit FIX-window consent covers stopping on close/crash.
        public void Dispose()
        {
            try { job.Dispose(); process.Dispose(); foreach (var file in locks) file.Dispose(); }
            finally { modeLease?.Dispose(); }
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class ProcessJob : IDisposable
{
    private readonly SafeFileHandle handle;
    public ProcessJob()
    {
        handle = CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var info = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(handle, 9, ref info, (uint)Marshal.SizeOf<ExtendedLimits>()))
        { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new System.ComponentModel.Win32Exception(error); }
    }
    public void Assign(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.Handle)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
    public void Dispose() => handle.Dispose();
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    { public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinWorking, MaxWorking; public uint ActiveLimit; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref ExtendedLimits info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
}
