using System.Text.Json;

namespace EclipseConnect.Core;

// A single atomic settings write commits both selection and rollback reference.
// Returning a copy also keeps the UI unchanged if the disk write fails.
public sealed class VersionSelection(Storage storage, Action<AppSettings>? save = null)
{
    private readonly Action<AppSettings> save = save ?? storage.SaveSettings;
    public AppSettings Select(AppSettings current, string path)
    {
        Validate(path);
        if (string.Equals(current.TelegramPath, path, StringComparison.OrdinalIgnoreCase)) return current;
        var next = current.Copy(); next.PreviousTelegramPath = current.TelegramPath; next.TelegramPath = path;
        save(next); return next;
    }
    public AppSettings Restore(AppSettings current)
    {
        var previous = current.PreviousTelegramPath;
        if (string.IsNullOrWhiteSpace(previous))
        {
            var legacy = storage.Resolve("settings-before-update.json");
            if (!File.Exists(legacy)) throw new InvalidDataException("Предыдущая версия ещё не сохранена.");
            if (new FileInfo(legacy).Length > 65536) throw new InvalidDataException("Резервная настройка слишком большая.");
            previous = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(legacy))?.TelegramPath ?? "";
        }
        Validate(previous);
        var next = current.Copy(); next.TelegramPath = previous; next.PreviousTelegramPath = "";
        save(next); return next;
    }
    private static void Validate(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Нужен полный путь к EXE-файлу Telegram-прокси.");
        Storage.AssertNoLinks(path);
        if (!File.Exists(path)) throw new FileNotFoundException("Файл больше не найден. Выберите его в разделе компонентов.");
    }
}
