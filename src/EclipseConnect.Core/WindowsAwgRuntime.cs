using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public sealed class WindowsAwgRuntime : IAwgRuntime
{
    private WindowsAwgService? service;
    private ProcessJob? job;
    private Process? process;
    private WindowsNetworkModeLease? modeLease;
    private readonly List<FileStream> locks = [];
    private string? directory;
    private string? configurationPath;
    private DateTimeOffset began;
    internal void AssertCompanionAllowed()
    {
        if (modeLease == null || service == null || process == null || process.HasExited)
            throw new InvalidOperationException("Совместный FIX требует собственный работающий VPN этого контроллера.");
        var state = service.Status();
        if (state.State != 4 || state.ProcessId != process.Id)
            throw new InvalidOperationException("Владелец VPN не подтверждён. FIX не запущен.");
        var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(a => a.Name == WindowsAwgEngine.TunnelName && a.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up).ToArray();
        if (adapters.Length != 1 || WindowsAwgEngine.HasActiveTunnelExcept(adapters[0].Id) || WindowsAwgEngine.ProcessesExist("Happ"))
            throw new InvalidOperationException("Обнаружен другой туннель или собственный интерфейс не подтверждён. FIX не запущен.");
    }
    public async Task<AwgState> Status(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (service == null) return AwgState.Off;
        var status = service.Status();
        if (status.State == 1) return new(false, false, "VPN-служба остановлена. Подключение не подтверждено.");
        if (status.State != 4 || process == null || process.HasExited) return new(true, false, "Служба VPN меняет состояние. Доступ пока не подтверждён.");
        var handshake = await Handshake(ct);
        var verified = handshake != null && handshake >= began.AddSeconds(-5) && handshake <= DateTimeOffset.UtcNow.AddSeconds(5) && DateTimeOffset.UtcNow - handshake < TimeSpan.FromMinutes(3);
        return new(true, verified, verified ? "Подключён · VPN-сервер подтвердил соединение." : "Служба запущена, но свежего подтверждения VPN-сервера нет.", handshake);
    }
    public async Task<AwgState> Start(AwgProfile profile, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (service != null || modeLease != null) throw new InvalidOperationException("Сначала отключите собственный VPN. Профиль не переключается на ходу.");
        modeLease = WindowsNetworkModeLease.Acquire();
        try
        {
            if (WindowsAwgEngine.ProcessesExist("winws", "winws2", "goodbyedpi"))
                throw new InvalidOperationException("Сначала остановите FIX в его управляющем окне. Connect не будет завершать внешний фильтр.");
            if (WindowsAwgEngine.HasActiveTunnel()) throw new InvalidOperationException("Обнаружен другой VPN/туннель. Отключите его в исходной программе и повторите. Чужое подключение не изменено.");
            var serviceConfiguration = MetaVpnPolicy.ServiceConfiguration(profile, DateTimeOffset.UtcNow);
            using (var resolution = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                resolution.CancelAfter(TimeSpan.FromSeconds(5));
                try { MetaVpnPolicy.CheckEndpoint(await Dns.GetHostAddressesAsync(profile.EndpointHost, resolution.Token)); }
                catch (System.Net.Sockets.SocketException) { throw new IOException("Ошибка DNS VPN-сервера. Имя Endpoint не разрешено; служба не запускалась, профиль не переключён."); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException("Тайм-аут DNS VPN-сервера. Служба не запускалась; проверьте сеть и профиль."); }
            }
            directory = WindowsAwgEngine.PrepareProtectedCopy();
            locks.AddRange(WindowsAwgEngine.VerifyAndLock(directory));
            configurationPath = Path.Combine(directory, WindowsAwgEngine.TunnelName + ".conf.dpapi");
            var clear = Encoding.UTF8.GetBytes(serviceConfiguration);
            try
            {
                // Machine DPAPI is needed for LocalSystem. The folder ACL grants only System/Administrators.
                var encrypted = WindowsDataProtection.Protect(clear, WindowsAwgEngine.TunnelName, true);
                using var output = new FileStream(configurationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                output.Write(encrypted); output.Flush(true);
            }
            finally { CryptographicOperations.ZeroMemory(clear); }
            locks.Add(new FileStream(configurationPath, FileMode.Open, FileAccess.Read, FileShare.Read));
            ct.ThrowIfCancellationRequested();
            if (WindowsAwgEngine.HasActiveTunnel() || WindowsAwgEngine.ProcessesExist("winws", "winws2", "goodbyedpi"))
                throw new InvalidOperationException("Во время подготовки появился другой VPN/FIX. Подключение отменено, чужой процесс не изменён.");
            service = WindowsAwgService.Create(Path.Combine(directory, "amneziawg.exe"), configurationPath);
            job = new ProcessJob(); began = DateTimeOffset.UtcNow;
            ct.ThrowIfCancellationRequested(); service.Start();
            var readyBy = DateTimeOffset.UtcNow.AddSeconds(15);
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var state = service.Status();
                if (state.State == 1) throw new IOException("VPN-служба завершилась при запуске (код Windows " + state.Win32Exit + ").");
                if (state.ProcessId != 0 && process == null)
                {
                    process = Process.GetProcessById(checked((int)state.ProcessId));
                    if (!string.Equals(process.MainModule?.FileName, Path.Combine(directory, "amneziawg.exe"), StringComparison.OrdinalIgnoreCase))
                    { process.Dispose(); process = null; throw new UnauthorizedAccessException("Windows запустила неожиданный процесс службы."); }
                    job.Assign(process);
                }
                if (state.State == 4 && process != null) break;
                if (DateTimeOffset.UtcNow > readyBy) throw new TimeoutException("VPN-служба не стала готова вовремя.");
                await Task.Delay(200, ct);
            }
            service.DeleteWhenStopped();
            // Generate normal traffic through the configured routes. HTTP alone never proves a VPN handshake.
            using var probeCancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var probe = Warmup(probeCancellation.Token);
            try
            {
                var deadline = DateTimeOffset.UtcNow.AddSeconds(20);
                do
                {
                    var status = await Status(ct);
                    if (status.Authenticated) { ct.ThrowIfCancellationRequested(); return status; }
                    if (!status.Running) throw new IOException("VPN завершился до подтверждения соединения.");
                    await Task.Delay(650, ct);
                } while (DateTimeOffset.UtcNow < deadline);
            }
            finally { probeCancellation.Cancel(); await probe; }
            throw new TimeoutException("VPN-сервер не подтвердил соединение. Выполняется остановка подключения; возможны недоступность UDP, неверный профиль или отказ сервера. Другой профиль автоматически не включается.");
        }
        catch
        {
            // Only our just-created tunnel is rolled back; the user's previous VPN/FIX is never touched.
            try { await Stop(CancellationToken.None); }
            catch { throw new IOException("Подключение не завершено, а остановка VPN не подтверждена. Нажмите «Отключить VPN» или выйдите из Connect и проверьте сеть."); }
            throw;
        }
    }
    public async Task<AwgState> Stop(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (service != null)
        {
            service.RequestStop();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
            while (service.Status().State != 1 && DateTimeOffset.UtcNow < deadline) await Task.Delay(150, CancellationToken.None);
            if (service.Status().State != 1)
            {
                job?.Dispose(); job = null; // Exact owned Job Object, never stop-by-name.
                var forceDeadline = DateTimeOffset.UtcNow.AddSeconds(4);
                while (service.Status().State != 1 && DateTimeOffset.UtcNow < forceDeadline) await Task.Delay(100, CancellationToken.None);
                if (service.Status().State != 1) throw new IOException("Windows не подтвердила остановку собственной VPN-службы. Управление сохранено для повторной попытки.");
            }
            service.Dispose(); service = null;
        }
        job?.Dispose(); job = null; process?.Dispose(); process = null;
        modeLease?.Dispose(); modeLease = null;
        foreach (var file in locks) file.Dispose(); locks.Clear();
        if (configurationPath != null && File.Exists(configurationPath))
        {
            Storage.AssertNoLinks(configurationPath);
            File.Delete(configurationPath); // Only the encrypted, temporary config created by this session.
        }
        configurationPath = null; directory = null;
        return new(false, false, "Собственный VPN остановлен. Другие подключения не изменялись.");
    }
    public async ValueTask DisposeAsync()
    {
        try { await Stop(CancellationToken.None); }
        finally
        {
            // Last-resort process lifetime containment even when SCM cleanup fails.
            job?.Dispose(); job = null; process?.Dispose(); process = null;
            try { service?.Dispose(); }
            finally
            {
                modeLease?.Dispose(); modeLease = null;
                service = null; foreach (var file in locks) file.Dispose(); locks.Clear();
            }
        }
    }
    private async Task<DateTimeOffset?> Handshake(CancellationToken ct)
    {
        if (directory == null) return null;
        var start = new ProcessStartInfo(Path.Combine(directory, "awg.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = directory };
        start.ArgumentList.Add("show"); start.ArgumentList.Add(WindowsAwgEngine.TunnelName); start.ArgumentList.Add("latest-handshakes");
        using var command = Process.Start(start) ?? throw new IOException("Не удалось проверить подтверждение VPN-сервера.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(3));
        var stdout = Bounded(command.StandardOutput, timeout.Token); var stderr = Bounded(command.StandardError, timeout.Token);
        try
        {
            await Task.WhenAll(stdout, stderr, command.WaitForExitAsync(timeout.Token));
            if (command.ExitCode != 0) return null; // Raw upstream errors and key material never reach UI/journal.
            var rows = stdout.Result.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (rows.Length != 1) return null;
            var fields = rows[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 2 || !long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) || seconds is <= 0 or > 253402300799) return null;
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        finally
        {
            timeout.Cancel();
            if (!command.HasExited) command.Kill(true);
            try { await Task.WhenAll(stdout, stderr); } catch (Exception e) when (e is IOException or OperationCanceledException) { }
        }
    }
    private static async Task<string> Bounded(StreamReader reader, CancellationToken ct)
    {
        var buffer = new char[1024]; var output = new StringBuilder(); int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), ct)) != 0)
        {
            if (output.Length + count > 4096) throw new IOException("Ответ проверки VPN превысил безопасный размер.");
            output.Append(buffer, 0, count);
        }
        return output.ToString();
    }
    private static async Task Warmup(CancellationToken ct)
    {
        try
        {
            using var handler = new HttpClientHandler { UseProxy = false, UseCookies = false, AllowAutoRedirect = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(6) };
            using var request = new HttpRequestMessage(HttpMethod.Head, "https://www.instagram.com/");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException) { }
    }
}
