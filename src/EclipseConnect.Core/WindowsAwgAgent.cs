using System.IO.Pipes;
using System.Runtime.Versioning;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public static class WindowsAwgAgent
{
    public static async Task Run(Storage storage, string nonce, int parentId, long parentStart)
    {
        if (!WindowsFixRuntime.IsAdministrator()) throw new UnauthorizedAccessException("Помощнику VPN нужны подтверждённые права Windows.");
        using var parent = FixPipeSecurity.VerifyParent(parentId, parentStart);
        using var instance = new Mutex(false, @"Global\EclipseConnect.VpnControl", out var created);
        if (!created) throw new InvalidOperationException("Другой VPN-контроллер уже открыт.");
        using var pipe = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce, "Vpn"), PipeDirection.InOut,
            PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Identification);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        FixPipeSecurity.VerifyServer(pipe, parentId);
        if (parent.HasExited) throw new UnauthorizedAccessException("Оболочка завершилась.");
        var vpn = new WindowsAwgRuntime();
        var fix = new WindowsFixRuntime(storage.LoadSettings().FixPath, storage);
        var combined = new CombinedAwgRuntime(vpn, (profile, ct) =>
        {
            var endpoint = profile.Configuration.Split('\n').Single(line => line.StartsWith("Endpoint = ", StringComparison.Ordinal));
            var port = int.Parse(endpoint[(endpoint.LastIndexOf(':') + 1)..], System.Globalization.CultureInfo.InvariantCulture);
            return fix.StartCompanion(port, vpn, ct);
        }, fix.InspectCompanion);
        var session = new AwgControlSession(combined, slot => new AwgProfileStore(storage, slot).Load());
        await Serve(pipe, session).ConfigureAwait(false);
    }
    // Real local-pipe regression tests use this exact server with a fake runtime: no UAC/driver/network.
    internal static async Task Serve(Stream pipe, AwgControlSession session)
    {
        using var lifetime = new CancellationTokenSource();
        CancellationTokenSource? operation = null; Task? pending = null; AwgRequest? active = null;
        var replyStarted = false;
        async Task Handle(AwgRequest request, CancellationToken ct)
        {
            string? error = null;
            try { await session.Execute(request, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { error = "Операция VPN отменена. Проверьте состояние подключения."; }
            catch (Exception e) { error = Redactor.Sanitize(e.Message); }
            Volatile.Write(ref replyStarted, true);
            try { await FixWire.Write(pipe, new AwgReply(request.Id, session.State, error), lifetime.Token).ConfigureAwait(false); }
            catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException) { lifetime.Cancel(); pipe.Dispose(); }
        }
        try
        {
            while (true)
            {
                var request = await FixWire.Read<AwgRequest>(pipe, lifetime.Token).ConfigureAwait(false);
                AwgControlPolicy.Validate(request);
                if (request.Operation == "cancel")
                {
                    if (active?.Id == request.Id && active.Sequence == request.Sequence && pending?.IsCompleted == false) operation?.Cancel();
                    continue;
                }
                if (pending?.IsCompleted == false)
                {
                    if (!Volatile.Read(ref replyStarted)) throw new InvalidDataException("Параллельная команда VPN запрещена.");
                    await pending.ConfigureAwait(false);
                }
                operation?.Dispose(); operation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                operation.CancelAfter(TimeSpan.FromSeconds(60)); active = request; Volatile.Write(ref replyStarted, false);
                pending = Handle(request, operation.Token);
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException or OperationCanceledException or System.Text.Json.JsonException)
        { /* EOF/malformed request: no more commands, revoke pending work and stop only our own tunnel. */ }
        finally
        {
            lifetime.Cancel(); operation?.Cancel();
            if (pending != null) await pending.ConfigureAwait(false);
            operation?.Dispose(); await session.DisposeAsync().ConfigureAwait(false);
        }
    }
}
