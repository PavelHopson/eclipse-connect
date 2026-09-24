using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public sealed class WindowsAwgLink : IDisposable
{
    private readonly NamedPipeServerStream pipe;
    private readonly Process helper;
    private readonly SemaphoreSlim writes = new(1, 1);
    private int busy;
    private long sequence;
    public AwgState? LastState { get; private set; }
    public bool Connected { get { try { return pipe.IsConnected && !helper.HasExited; } catch (InvalidOperationException) { return false; } } }
    private WindowsAwgLink(NamedPipeServerStream pipe, Process helper) { this.pipe = pipe; this.helper = helper; }
    public static async Task<WindowsAwgLink> Open(CancellationToken ct)
    {
        var nonce = Guid.NewGuid().ToString("N"); var pipe = FixPipeSecurity.Create(nonce, "Vpn"); Process? helper = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            using var current = Process.GetCurrentProcess();
            var start = new ProcessStartInfo(Environment.ProcessPath!)
            { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory, WindowStyle = ProcessWindowStyle.Hidden };
            start.ArgumentList.Add("--vpn-agent"); start.ArgumentList.Add(nonce);
            start.ArgumentList.Add(current.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            start.ArgumentList.Add(current.StartTime.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
            helper = Process.Start(start) ?? throw new IOException("Windows не запустила помощника VPN.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(25));
            var connected = pipe.WaitForConnectionAsync(timeout.Token); var exited = helper.WaitForExitAsync(timeout.Token);
            try
            {
                if (await Task.WhenAny(connected, exited) == exited) throw new IOException("Помощник VPN завершился. Проверьте, не открыт ли другой контроллер Connect.");
                await connected; ct.ThrowIfCancellationRequested(); FixPipeSecurity.VerifyClient(pipe, helper.Id); return new(pipe, helper);
            }
            finally { timeout.Cancel(); try { await Task.WhenAll(connected, exited); } catch (OperationCanceledException) { } }
        }
        catch { pipe.Dispose(); helper?.Dispose(); throw; }
    }
    public async Task<AwgState> Execute(string operation, string? revision, bool confirmed, CancellationToken ct,
        AwgProfileSlot profileSlot = AwgProfileSlot.Primary)
    {
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0) throw new InvalidOperationException("Команда VPN уже выполняется.");
        using var finished = new CancellationTokenSource();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        Task? cancellation = null; var sent = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            var request = new AwgRequest(1, Guid.NewGuid().ToString("N"), operation, revision, confirmed, sequence + 1, profileSlot);
            AwgControlPolicy.Validate(request); sequence = request.Sequence; sent = true;
            await Send(request, deadline.Token);
            cancellation = CancelWhenRequested(request, ct, finished.Token, deadline);
            var reply = await FixWire.Read<AwgReply>(pipe, deadline.Token);
            if (reply.Id != request.Id || reply.State == null) throw new InvalidDataException("Ответ не соответствует команде VPN.");
            LastState = reply.State;
            if (reply.Error != null) throw new InvalidOperationException(reply.Error);
            return reply.State;
        }
        catch (Exception e) when (e is IOException or InvalidDataException or OperationCanceledException or System.Text.Json.JsonException)
        { if (sent) { pipe.Dispose(); LastState = null; } throw; }
        finally
        {
            finished.Cancel(); if (cancellation != null) await cancellation; Volatile.Write(ref busy, 0);
        }
    }
    private async Task Send(AwgRequest request, CancellationToken ct)
    { await writes.WaitAsync(ct); try { await FixWire.Write(pipe, request, ct); } finally { writes.Release(); } }
    private async Task CancelWhenRequested(AwgRequest request, CancellationToken cancellation, CancellationToken finished, CancellationTokenSource deadline)
    {
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellation, finished);
        try { await Task.Delay(Timeout.Infinite, combined.Token); } catch (OperationCanceledException) { }
        if (finished.IsCancellationRequested || !cancellation.IsCancellationRequested) return;
        try
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(40));
            await Send(request with { Operation = "cancel", Revision = null, Confirmed = false, ProfileSlot = AwgProfileSlot.Primary }, deadline.Token);
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException) { pipe.Dispose(); }
    }
    public void Dispose() { pipe.Dispose(); helper.Dispose(); LastState = null; }
}
