using System.Text.Json;

namespace EclipseConnect.Core;

public sealed class AppSettings
{
    public string TelegramPath { get; set; } = "";
    public string FixPath { get; set; } = "";
    public string Theme { get; set; } = "System";
    public bool CheckUpdatesOnStart { get; set; }
    public bool CloseToTray { get; set; }
    public bool AdvancedMode { get; set; }
    public double? Left { get; set; }
    public double? Top { get; set; }
    public string PreviousTelegramPath { get; set; } = "";
    public AppSettings Copy() => (AppSettings)MemberwiseClone();
    public double Width { get; set; } = 1060;
    public double Height { get; set; } = 760;
}

public sealed class Storage
{
    public string Root { get; }
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    public Storage(string root) { Root = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar); AssertNoLinks(Root); Directory.CreateDirectory(Root); }
    public static void AssertNoLinks(string path)
    {
        for (var current = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(path))!); current != null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Путь через ссылку или junction запрещён.");
        if ((File.Exists(path) || Directory.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Путь через ссылку запрещён.");
    }
    public string Resolve(string relative)
    {
        if (Path.IsPathRooted(relative)) throw new IOException("Требуется относительный путь.");
        if (relative.IndexOfAny([':', '<', '>', '"', '|', '?', '*', '\0']) >= 0) throw new IOException("Недопустимое имя файла.");
        var path = Path.GetFullPath(Path.Combine(Root, relative));
        if (!path.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new IOException("Выход за папку приложения запрещён.");
        AssertNoLinks(path);
        return path;
    }
    public AppSettings LoadSettings()
    {
        var path = Resolve("settings.json");
        if (!File.Exists(path)) return new();
        if (new FileInfo(path).Length > 64 * 1024) throw new InvalidDataException("Файл настроек слишком большой.");
        return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path)) ?? new();
    }
    public void SaveSettings(AppSettings settings) => AtomicJson("settings.json", settings);
    public void PreserveInvalidSettings()
    {
        var path = Resolve("settings.json");
        if (!File.Exists(path)) return;
        var backup = Resolve("recovery/settings-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N") + ".json");
        Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
        File.Copy(path, backup, false);
    }
    public void AtomicJson<T>(string relative, T data)
    {
        var path = Resolve(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { JsonSerializer.Serialize(stream, data, JsonOptions); stream.Flush(true); }
            AssertNoLinks(path);
            File.Move(temp, path, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public List<JournalEntry> ReadJournal()
    {
        var path = Resolve("journal.json");
        if (!File.Exists(path) || new FileInfo(path).Length > 2 * 1024 * 1024) return [];
        try { return JsonSerializer.Deserialize<List<JournalEntry>>(File.ReadAllText(path)) ?? []; }
        catch (JsonException) { return []; }
    }
    public void Log(string action, string result)
    {
        var rows = ReadJournal(); rows.Add(new(DateTimeOffset.Now, Redactor.Sanitize(action), Redactor.Sanitize(result)));
        AtomicJson("journal.json", rows.TakeLast(200).ToArray());
    }
    public string ExportReport(IEnumerable<DiagnosticResult> results)
    {
        var relative = $"reports/check-{DateTime.Now:yyyyMMdd-HHmmss}.json";
        AtomicJson(relative, results.Select(r => r with { Detail = Redactor.Sanitize(r.Detail) }).ToArray());
        return Resolve(relative);
    }
}
