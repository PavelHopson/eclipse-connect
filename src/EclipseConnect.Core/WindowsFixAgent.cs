using System.IO.Pipes;
using System.Runtime.Versioning;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public static class WindowsFixAgent
{
    public static async Task Run(Storage storage, string nonce, int parentId, long parentStart)
    {
        if (!WindowsFixRuntime.IsAdministrator()) throw new UnauthorizedAccessException("Помощнику нужны подтверждённые права Windows.");
        using var parent = FixPipeSecurity.VerifyParent(parentId, parentStart);
        // Presence marker, not a thread-owned lock held across awaits. Legacy windows use the same name.
        using var instance = new Mutex(false, @"Local\EclipseConnect.FixControl", out var created);
        if (!created) throw new InvalidOperationException("Другой контроллер FIX уже открыт.");
            using var pipe = new NamedPipeClientStream(".", FixPipeSecurity.Name(nonce), PipeDirection.InOut,
                PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Identification);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            FixPipeSecurity.VerifyServer(pipe, parentId);
            if (parent.HasExited) throw new UnauthorizedAccessException("Оболочка уже завершилась.");
            var settings = storage.LoadSettings(); Inventory.Discover(settings);
            var runtime = new WindowsFixRuntime(settings.FixPath, storage);
            using var session = new FixControlSession(runtime, storage, (id, ct) => WindowsFixRuntime.InspectResources(settings.FixPath, id, ct));
            await Serve(pipe, session).ConfigureAwait(false);
    }
    // Shared with offline transport tests. Production constructs only the fixed Windows runtime above.
    internal static async Task Serve(Stream pipe, FixControlSession session)
    {
        using var lifetime = new CancellationTokenSource();
        using var writes = new SemaphoreSlim(1, 1);
        CancellationTokenSource? operation = null;
        Task? pending = null;
        FixControlRequest? active = null;
        var replyStarted = false;
        long sequence = 0;
        async Task Send(FixControlReply reply)
        {
            await writes.WaitAsync(lifetime.Token).ConfigureAwait(false);
            try { await FixWire.Write(pipe, reply, lifetime.Token).ConfigureAwait(false); }
            finally { writes.Release(); }
        }
        async Task Handle(FixControlRequest request, CancellationToken ct)
        {
            string? error = null;
            try
            {
                await session.Execute(request, ct, lifetime.Token, new InlineProgress<FixProgress>(
                    p => Send(new(request.Id, "progress", Progress: p)).GetAwaiter().GetResult()));
            }
            catch (OperationCanceledException) { error = "Операция отменена. Проверьте состояние FIX ниже."; }
            catch (Exception e) { error = Redactor.Sanitize(e.Message); }
            var reply = new FixControlReply(request.Id, "reply", session.State, Error: error);
            // The parent may read our reply before this task's write continuation runs.
            // In that handoff window a next request is legitimate, not parallel execution.
            Volatile.Write(ref replyStarted, true);
            try { await Send(reply); }
            catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
            { lifetime.Cancel(); pipe.Dispose(); }
        }
        try
        {
            while (true)
            {
                var request = await FixWire.Read<FixControlRequest>(pipe, lifetime.Token).ConfigureAwait(false);
                FixControlPolicy.Validate(request);
                if (request.Operation == "cancel")
                {
                    if (active?.Id == request.Id && active.Sequence == request.Sequence && pending?.IsCompleted == false)
                        operation?.Cancel();
                    continue;
                }
                if (request.Sequence != sequence + 1) throw new InvalidDataException("Повторная команда FIX отклонена.");
                if (pending?.IsCompleted == false)
                {
                    if (!Volatile.Read(ref replyStarted)) throw new InvalidDataException("Параллельная команда FIX отклонена.");
                    await pending.ConfigureAwait(false);
                }
                sequence = request.Sequence;
                operation?.Dispose(); operation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                operation.CancelAfter(TimeSpan.FromMinutes(2));
                active = request; Volatile.Write(ref replyStarted, false); pending = Handle(request, operation.Token);
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException or InvalidOperationException or OperationCanceledException or System.Text.Json.JsonException)
        { /* Broken/invalid pipe: revoke the operation and release only the owned job. */ }
        finally
        {
            lifetime.Cancel(); operation?.Cancel();
            if (pending != null) await pending;
            operation?.Dispose();
            session.Dispose();
        }
    }
    private sealed class InlineProgress<T>(Action<T> action) : IProgress<T>
    { public void Report(T value) => action(value); }
}
