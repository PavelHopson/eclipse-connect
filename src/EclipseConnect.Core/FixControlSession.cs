namespace EclipseConnect.Core;

public sealed record FixRun(string ProfileId, bool Gaming, string Target);
public sealed record FixControlState(bool Running, FixRun? Active, FixRun? Previous, bool ExternalEngine,
    string Message, IReadOnlyList<FixTrial> Trials);
public sealed record FixControlRequest(int Version, string Id, string Operation, FixRun? Run = null, bool Confirmed = false, long Sequence = 1);
public sealed record FixControlReply(string Id, string Kind, FixControlState? State = null, FixProgress? Progress = null, string? Error = null);

public static class FixControlPolicy
{
    public static void Validate(FixControlRequest request)
    {
        if (request.Version != 1 || request.Sequence <= 0 || !Guid.TryParseExact(request.Id, "N", out _))
            throw new InvalidDataException("Версия или идентификатор команды не поддерживается.");
        if (request.Operation is not ("status" or "start" or "stop" or "select" or "switch" or "restore" or "cancel"))
            throw new InvalidDataException("Команда FIX не разрешена.");
        var needsRun = request.Operation is "start" or "select" or "switch";
        if (needsRun != (request.Run != null)) throw new InvalidDataException("Неверные параметры команды.");
        if (request.Run is { } run)
        {
            _ = FixCatalog.Get(run.ProfileId); _ = FixCatalog.Candidates(run.Target);
            if (request.Operation == "select" && run.Gaming) throw new InvalidDataException("Подбор не включает игровой диапазон.");
        }
        if (request.Operation is not ("status" or "cancel") && !request.Confirmed)
            throw new InvalidOperationException("Изменение FIX требует отдельного подтверждения.");
    }
}

// Own handles only. No PID adoption, Windows settings writes, shell or arbitrary paths in commands.
public sealed class FixControlSession(IFixRuntime runtime, Storage storage,
    Func<string, CancellationToken, Task> validateResources) : IDisposable
{
    private IManagedProcess? owned;
    private FixRun? active, previous;
    private int busy;
    private string message = "Помощник готов. FIX не запущен.";
    private IReadOnlyList<FixTrial> trials = [];
    public FixControlState State => new(owned?.IsRunning == true, owned?.IsRunning == true ? active : null,
        previous, owned?.IsRunning != true && runtime.HasExternalEngine, message, trials);

    public async Task<FixControlState> Execute(FixControlRequest request, CancellationToken ct,
        CancellationToken lifetime, IProgress<FixProgress>? progress = null)
    {
        FixControlPolicy.Validate(request);
        if (request.Operation == "cancel") throw new InvalidOperationException("Отмена обрабатывается каналом текущей операции.");
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0) throw new InvalidOperationException("Другая операция FIX ещё выполняется.");
        try
        {
            ct.ThrowIfCancellationRequested(); lifetime.ThrowIfCancellationRequested();
            if (request.Operation == "status") return State;
            switch (request.Operation)
            {
                case "start":
                    if (State.Running || runtime.HasExternalEngine) throw new InvalidOperationException("FIX уже работает. Чужой процесс не останавливается.");
                    if (runtime.HasConfoundingTunnel) throw new InvalidOperationException("Отключите VPN перед ручным запуском FIX. Чужое подключение не изменяется.");
                    await validateResources(request.Run!.ProfileId, ct);
                    if (runtime.HasConfoundingTunnel) throw new InvalidOperationException("Во время подготовки появился VPN. FIX не запущен.");
                    owned?.Dispose(); owned = null;
                    owned = await runtime.Start(request.Run.ProfileId, request.Run.Gaming, ct);
                    try
                    {
                        ct.ThrowIfCancellationRequested(); lifetime.ThrowIfCancellationRequested();
                        if (!owned.IsRunning) throw new IOException("FIX завершился сразу после запуска.");
                    }
                    catch { StopOwned(); throw; }
                    active = request.Run; message = "FIX запущен из этого окна. Видео и звонки проверьте отдельно.";
                    break;
                case "stop":
                    if (!State.Running) throw new InvalidOperationException("Нет собственного работающего FIX.");
                    StopOwned(); message = "Собственный FIX остановлен.";
                    break;
                case "select":
                    if (State.Running) throw new InvalidOperationException("Перед подбором нужно явно остановить собственный FIX.");
                    var safety = new SessionSafety(); safety.AllowForSession(true);
                    var selected = await new FixSelector(safety, runtime).Select(request.Run!.Target, true, null, ct, progress);
                    trials = selected.Trials;
                    ct.ThrowIfCancellationRequested();
                    if (selected.SelectedId != null) new FixChoiceStore(storage).Accept(selected, request.Run.Target, DateTimeOffset.Now);
                    message = selected.Message;
                    break;
                case "switch":
                    await Switch(request.Run!, ct, lifetime);
                    break;
                case "restore":
                    if (previous == null) throw new InvalidOperationException("Предыдущего запуска в этой сессии нет.");
                    await Switch(previous, ct, lifetime);
                    break;
            }
            return State;
        }
        finally { Volatile.Write(ref busy, 0); }
    }
    private async Task Switch(FixRun desired, CancellationToken ct, CancellationToken lifetime)
    {
        if (!State.Running || active == null) throw new InvalidOperationException("Переключать можно только FIX, запущенный этим помощником.");
        if (runtime.HasConfoundingTunnel) throw new InvalidOperationException("Во время работы туннеля проверяемое переключение недостоверно. Текущий FIX сохранён.");
        var before = active;
        if (before == desired) throw new InvalidOperationException("Эта конфигурация уже запущена.");
        // Validate and journal BEFORE interrupting the current process. A disk/preflight failure leaves it running.
        await validateResources(desired.ProfileId, ct);
        await validateResources(before.ProfileId, ct);
        ct.ThrowIfCancellationRequested();
        storage.AtomicJson("recovery/fix-runtime.json", new { Schema = 1, Before = before, Desired = desired, Pending = true, At = DateTimeOffset.Now });
        ct.ThrowIfCancellationRequested();
        StopOwned(); // If stopping fails, abort; never attempt another engine.
        try
        {
            owned = await runtime.Start(desired.ProfileId, desired.Gaming, ct);
            active = desired;
            bool Pass(FixProbe p) => p.ControlReady && (desired.Target == "all" ? new[] { "youtube", "discord" } : [desired.Target])
                .All(t => p.Services.GetValueOrDefault(t));
            var first = await runtime.Probe(ct); var second = await runtime.Probe(ct);
            if (!State.Running || !Pass(first) || !Pass(second)) throw new IOException("Новый профиль не прошёл две HTTPS-проверки.");
            if (runtime.HasConfoundingTunnel) throw new IOException("Во время проверки появился туннель.");
            ct.ThrowIfCancellationRequested(); lifetime.ThrowIfCancellationRequested();
            previous = before;
            message = "Профиль переключён. Две HTTPS-проверки пройдены; видео и звонки не проверены.";
            if (!Record(before, desired, "switched")) message += " Отчёт восстановления не обновлён.";
        }
        catch (Exception original)
        {
            StopOwned();
            if (lifetime.IsCancellationRequested) throw; // Owner disappeared: no hidden restart.
            using var rollback = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
            rollback.CancelAfter(TimeSpan.FromSeconds(30));
            try
            {
                owned = await runtime.Start(before.ProfileId, before.Gaming, rollback.Token);
                try
                {
                    rollback.Token.ThrowIfCancellationRequested();
                    if (!owned.IsRunning) throw new IOException("Восстановленный FIX сразу завершился.");
                }
                catch { StopOwned(); throw; }
                active = before;
                message = "Переключение не завершено. Предыдущий FIX снова запущен; доступ требует проверки.";
                if (!Record(before, desired, "restored")) message += " Отчёт восстановления не обновлён.";
            }
            catch (Exception restoreError)
            {
                message = "Не удалось вернуть предыдущий FIX. Проверьте подключение вручную.";
                throw new IOException(message, new AggregateException(original, restoreError));
            }
        }
    }
    private bool Record(FixRun before, FixRun desired, string outcome)
    {
        // Recovery state contains only catalog IDs, never credentials or arbitrary commands.
        try
        {
            storage.AtomicJson("recovery/fix-runtime.json", new { Schema = 1, Before = before, Desired = desired, Pending = false, Outcome = outcome, At = DateTimeOffset.Now });
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }
    private void StopOwned()
    {
        if (owned == null) return;
        if (owned.IsRunning) owned.Stop();
        owned.Dispose(); owned = null; active = null;
    }
    public void Dispose() { owned?.Dispose(); owned = null; active = null; }
}
