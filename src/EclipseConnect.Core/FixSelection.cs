namespace EclipseConnect.Core;

public sealed record FixProbe(bool ControlReady, IReadOnlyDictionary<string, bool> Services);
public sealed record FixCheck(bool ControlReady, IReadOnlyDictionary<string, bool> Services, bool ProcessRunning);
public sealed record FixTrial(string Profile, bool Passed, string Detail)
{
    public IReadOnlyList<FixCheck> Checks { get; init; } = [];
}
public sealed record FixProgress(string Stage, string? Profile, int Index, int Total, IReadOnlyList<FixTrial> Trials);
public sealed record FixSelectionResult(string? SelectedId, string Message, IReadOnlyList<FixTrial> Trials);

public interface IFixRuntime
{
    bool HasExternalEngine { get; }
    bool HasConfoundingTunnel { get; }
    Task<IManagedProcess> Start(string profileId, bool gaming, CancellationToken ct);
    Task<FixProbe> Probe(CancellationToken ct);
}

public sealed class FixSelector(SessionSafety safety, IFixRuntime runtime)
{
    private int busy;
    public async Task<FixSelectionResult> Select(string target, bool confirmed, IProgress<string>? progress, CancellationToken ct,
        IProgress<FixProgress>? details = null)
    {
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0) throw new InvalidOperationException("Подбор уже выполняется.");
        try
        {
            var permit = safety.CapturePermit();
            if (!confirmed) throw new InvalidOperationException("Подбор изменяет обработку сетевых пакетов и требует подтверждения.");
            var candidates = FixCatalog.Candidates(target);
            string[] targets = target == "all" ? ["youtube", "discord"] : [target];
            void Guard() => safety.Commit(permit, ct, () =>
            {
                if (runtime.HasExternalEngine) throw new InvalidOperationException("Уже работает FIX. Остановите его в программе, из которой запускали.");
                if (runtime.HasConfoundingTunnel) throw new InvalidOperationException("Обнаружен Happ или другой туннель. Подбор будет недостоверным. Connect его не отключает.");
                return true;
            });
            bool Pass(FixProbe probe) => probe.ControlReady && targets.All(t => probe.Services.GetValueOrDefault(t));
            Guard(); progress?.Report("Проверка сети без FIX...");
            details?.Report(new("Исходная сеть", null, 0, candidates.Length, []));
            var baseline = await runtime.Probe(ct);
            if (!baseline.ControlReady) return new(null, "Контрольный HTTPS-адрес недоступен. Подбор не начат.", []);
            if (Pass(baseline)) return new(null, "Проверяемые сайты уже доступны без FIX. Профиль не нужен для этих проверок.", []);
            var trials = new List<FixTrial>();
            var index = 0;
            foreach (var profile in candidates)
            {
                Guard(); index++; progress?.Report($"Профиль {index}/{candidates.Length}: " + profile.Name);
                details?.Report(new("Запуск кандидата", profile.Id, index, candidates.Length, trials.ToArray()));
                IManagedProcess? owned = null;
                var passed = false;
                try
                {
                    owned = await runtime.Start(profile.Id, false, ct);
                    // Runtime must implement a bounded startup and cancellation cleanup.
                    details?.Report(new("HTTPS-проверка 1/2", profile.Id, index, candidates.Length, trials.ToArray()));
                    var first = await runtime.Probe(ct);
                    var firstRunning = owned.IsRunning;
                    details?.Report(new("HTTPS-проверка 2/2", profile.Id, index, candidates.Length, trials.ToArray()));
                    var second = await runtime.Probe(ct);
                    passed = firstRunning && owned.IsRunning && Pass(first) && Pass(second);
                    safety.Commit(permit, ct, () => true);
                    if (runtime.HasConfoundingTunnel) throw new InvalidOperationException("Во время подбора появился туннель. Результат не сохранён.");
                    trials.Add(new(profile.Id, passed, passed ? "Две HTTPS-проверки пройдены" : "Не все HTTPS-проверки пройдены")
                    {
                        Checks = [new(first.ControlReady, first.Services, firstRunning), new(second.ControlReady, second.Services, owned.IsRunning)]
                    });
                }
                finally
                {
                    // Cleanup is part of the user's original trial consent, even after Cancel/Protect.
                    // Only the exact trial handle can be stopped. Failure aborts selection, never starts another engine.
                    if (owned != null) { try { if (owned.IsRunning) owned.Stop(); } finally { owned.Dispose(); } }
                }
                details?.Report(new("Кандидат остановлен", profile.Id, index, candidates.Length, trials.ToArray()));
                if (passed) return new(profile.Id, "Профиль прошёл две HTTPS-проверки. Видео и звонки проверьте отдельно.", trials);
            }
            return new(null, "Подходящий профиль не найден. Все пробные процессы остановлены; прежний выбор сохранён.", trials);
        }
        finally { Volatile.Write(ref busy, 0); }
    }
}
