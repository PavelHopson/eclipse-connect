using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public static class FixPipeSecurity
{
    public static string Name(string nonce, string component = "Fix") => Guid.TryParseExact(nonce, "N", out _) && component is "Fix" or "Vpn" ? "EclipseConnect." + component + "." + nonce
        : throw new InvalidDataException("Неверное имя канала.");
    public static NamedPipeServerStream Create(string nonce, string component = "Fix")
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new InvalidOperationException("Не определён пользователь Windows.");
        var acl = new PipeSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(user);
        acl.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        acl.AddAccessRule(new(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        // CurrentUserOnly also compares elevation on Windows, so use an explicit user ACL instead.
        return NamedPipeServerStreamAcl.Create(Name(nonce, component), PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 4096, 4096, acl);
    }
    public static void VerifyClient(PipeStream pipe, int expected)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var actual) || actual != expected)
            throw new UnauthorizedAccessException("Подключился неизвестный процесс, управление FIX запрещено.");
    }
    public static void VerifyServer(PipeStream pipe, int expected)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var actual) || actual != expected)
            throw new UnauthorizedAccessException("Не подтверждён процесс оболочки Connect.");
    }
    public static Process VerifyParent(int pid, long startedAt)
    {
        var parent = Process.GetProcessById(pid);
        try
        {
            if (parent.HasExited || parent.StartTime.ToUniversalTime().Ticks != startedAt ||
                !string.Equals(parent.MainModule?.FileName, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Процесс запуска Connect изменился.");
            if (!OpenProcessToken(parent.Handle, 8, out var token)) throw new UnauthorizedAccessException("Не подтверждён пользователь оболочки.");
            using (token)
            using (var parentIdentity = new WindowsIdentity(token.DangerousGetHandle()))
            using (var ownIdentity = WindowsIdentity.GetCurrent())
                if (parentIdentity.User != ownIdentity.User) throw new UnauthorizedAccessException("Помощник принадлежит другому пользователю.");
            return parent; // Hold the process handle, preventing PID identity from being inferred from a name.
        }
        catch { parent.Dispose(); throw; }
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
}

[SupportedOSPlatform("windows")]
public sealed class WindowsFixLink : IDisposable
{
    private readonly NamedPipeServerStream pipe;
    private readonly Process helper;
    private readonly SemaphoreSlim writes = new(1, 1);
    private int busy;
    private long sequence;
    public FixControlState? LastState { get; private set; }
    public bool Connected { get { try { return pipe.IsConnected && !helper.HasExited; } catch (InvalidOperationException) { return false; } } }
    private WindowsFixLink(NamedPipeServerStream pipe, Process helper) { this.pipe = pipe; this.helper = helper; }
    public static async Task<WindowsFixLink> Open(CancellationToken ct)
    {
        if (Mutex.TryOpenExisting(@"Local\EclipseConnect.FixControl", out var oldController))
        {
            oldController.Dispose();
            throw new InvalidOperationException("Уже открыто старое или другое окно FIX. Оно не будет закрыто автоматически. Для перехода нужен согласованный перезапуск.");
        }
        var nonce = Guid.NewGuid().ToString("N");
        var pipe = FixPipeSecurity.Create(nonce);
        Process? helper = null;
        try
        {
            using var current = Process.GetCurrentProcess();
            var start = new ProcessStartInfo(Environment.ProcessPath!)
            { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory, WindowStyle = ProcessWindowStyle.Hidden };
            start.ArgumentList.Add("--fix-agent"); start.ArgumentList.Add(nonce);
            start.ArgumentList.Add(current.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            start.ArgumentList.Add(current.StartTime.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
            helper = Process.Start(start) ?? throw new IOException("Windows не запустила помощника.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(20));
            var connected = pipe.WaitForConnectionAsync(timeout.Token);
            var exited = helper.WaitForExitAsync(timeout.Token);
            try
            {
                if (await Task.WhenAny(connected, exited) == exited)
                    throw new IOException("Помощник FIX завершился. Возможно, ещё открыто старое окно FIX.");
                await connected;
                ct.ThrowIfCancellationRequested();
                FixPipeSecurity.VerifyClient(pipe, helper.Id);
                return new(pipe, helper);
            }
            finally
            {
                timeout.Cancel();
                try { await Task.WhenAll(connected, exited); }
                catch (OperationCanceledException) { }
            }
        }
        catch { pipe.Dispose(); helper?.Dispose(); throw; } // EOF/handshake timeout makes helper exit; never kill by name.
    }
    public async Task<FixControlState> Execute(string operation, FixRun? run, bool confirmed,
        CancellationToken ct, IProgress<FixProgress>? progress = null)
    {
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0) throw new InvalidOperationException("Команда FIX уже выполняется.");
        using var finished = new CancellationTokenSource();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        Task? cancelTask = null;
        var sent = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            var request = new FixControlRequest(1, Guid.NewGuid().ToString("N"), operation, run, confirmed, sequence + 1);
            FixControlPolicy.Validate(request);
            sequence = request.Sequence;
            sent = true;
            await Send(request, deadline.Token);
            cancelTask = CancelWhenRequested(request, ct, finished.Token, deadline);
            while (true)
            {
                var reply = await FixWire.Read<FixControlReply>(pipe, deadline.Token);
                if (reply.Id != request.Id) throw new InvalidDataException("Ответ не соответствует операции FIX.");
                if (reply.Kind == "progress" && reply.Progress != null) { progress?.Report(reply.Progress); continue; }
                if (reply.Kind != "reply" || reply.State == null) throw new InvalidDataException("Повреждён ответ помощника.");
                LastState = reply.State;
                if (reply.Error != null) throw new InvalidOperationException(reply.Error);
                return reply.State;
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException or OperationCanceledException or System.Text.Json.JsonException)
        { if (sent) { pipe.Dispose(); LastState = null; } throw; }
        finally
        {
            finished.Cancel();
            if (cancelTask != null) await cancelTask;
            Volatile.Write(ref busy, 0);
        }
    }
    private async Task Send(FixControlRequest request, CancellationToken ct)
    {
        await writes.WaitAsync(ct);
        try { await FixWire.Write(pipe, request, ct); }
        finally { writes.Release(); }
    }
    private async Task CancelWhenRequested(FixControlRequest request, CancellationToken cancellation, CancellationToken finished,
        CancellationTokenSource deadline)
    {
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellation, finished);
        try { await Task.Delay(Timeout.Infinite, combined.Token); }
        catch (OperationCanceledException) { }
        if (finished.IsCancellationRequested || !cancellation.IsCancellationRequested) return;
        try
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(40));
            await Send(request with { Operation = "cancel", Run = null, Confirmed = false }, deadline.Token);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
        { pipe.Dispose(); }
    }
    public void Dispose() { pipe.Dispose(); helper.Dispose(); LastState = null; }
}
