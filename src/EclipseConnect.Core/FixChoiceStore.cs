using System.Text.Json;

namespace EclipseConnect.Core;

// Data only. Restoring a choice never starts a process or writes Windows networking settings.
public sealed record FixChoice(string ProfileId, string Target, DateTimeOffset? CheckedAt);
public sealed record FixChoiceState(int Schema, FixChoice? Selected, FixChoice? Previous);
public sealed class FixChoiceStore(Storage storage, Action<FixChoiceState>? save = null)
{
    private readonly Action<FixChoiceState> save = save ?? (state => storage.AtomicJson("profiles/fix-state.json", state));
    public FixChoiceState Read()
    {
        var path = storage.Resolve("profiles/fix-state.json");
        if (File.Exists(path))
        {
            var state = ReadFile<FixChoiceState>(path);
            if (state == null || state.Schema != 1) throw new InvalidDataException("Формат выбора FIX не поддерживается.");
            Validate(state.Selected); Validate(state.Previous); return state;
        }
        var legacy = storage.Resolve("fix-selection.json");
        if (!File.Exists(legacy)) return new(1, null, null);
        var old = ReadFile<FixSelectionResult>(legacy);
        if (old?.SelectedId == null) return new(1, null, null);
        _ = FixCatalog.Get(old.SelectedId);
        // Older files did not record target or time. Do not invent verification evidence.
        return new(1, new(old.SelectedId, "legacy", null), null);
    }
    public FixChoiceState Accept(FixSelectionResult result, string target, DateTimeOffset now)
    {
        _ = FixCatalog.Candidates(target);
        var current = Read();
        if (result.SelectedId == null) return current;
        _ = FixCatalog.Get(result.SelectedId);
        if (!FixCatalog.Candidates(target).Any(p => p.Id == result.SelectedId))
            throw new InvalidDataException("Профиль не соответствует выбранным сервисам.");
        var trial = result.Trials?.SingleOrDefault(t => t.Profile == result.SelectedId);
        var required = target == "all" ? new[] { "youtube", "discord" } : [target];
        if (trial?.Passed != true || trial.Checks is not { Count: 2 } ||
            trial.Checks.Any(c => !c.ControlReady || !c.ProcessRunning || required.Any(t => !c.Services.GetValueOrDefault(t))))
            throw new InvalidDataException("Нет двух успешных проверок выбранного профиля.");
        var selected = new FixChoice(result.SelectedId, target, now);
        var previous = current.Selected?.ProfileId == selected.ProfileId && current.Selected.Target == selected.Target
            ? current.Previous : current.Selected;
        var next = new FixChoiceState(1, selected, previous); save(next); return next;
    }
    public FixChoiceState Restore()
    {
        var current = Read();
        if (current.Previous == null) throw new InvalidDataException("Предыдущий выбор FIX ещё не сохранён.");
        var next = new FixChoiceState(1, current.Previous, null); save(next); return next;
    }
    private static T? ReadFile<T>(string path)
    {
        if (new FileInfo(path).Length > 65536) throw new InvalidDataException("Файл выбора FIX слишком большой.");
        return JsonSerializer.Deserialize<T>(File.ReadAllText(path));
    }
    private static void Validate(FixChoice? choice)
    {
        if (choice == null) return;
        _ = FixCatalog.Get(choice.ProfileId);
        if (choice.Target != "legacy") _ = FixCatalog.Candidates(choice.Target);
    }
    public static string Describe(FixChoice? choice) => choice == null ? "Выбор ещё не сохранён" :
        FixCatalog.Get(choice.ProfileId).Name + (choice.CheckedAt is { } time
            ? " · HTTPS: " + time.ToLocalTime().ToString("dd.MM HH:mm") : " · старый выбор, дата проверки неизвестна");
}
