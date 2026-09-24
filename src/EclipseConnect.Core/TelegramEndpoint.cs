using System.Net;
using System.Text.Json;

namespace EclipseConnect.Core;

public sealed record TelegramEndpoint(int Port)
{
    public static TelegramEndpoint Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (!root.TryGetProperty("port", out var value) || !value.TryGetInt32(out var port) || port is < 1 or > 65535)
            throw new InvalidDataException("В настройках Telegram-прокси некорректный порт.");
        if (root.TryGetProperty("host", out var host))
        {
            var text = host.GetString();
            if (text is not ("localhost" or "0.0.0.0" or "::") && (!IPAddress.TryParse(text, out var address) || !IPAddress.IsLoopback(address)))
                throw new InvalidDataException("Telegram-прокси настроен не на локальный адрес. Нужна отдельная проверка.");
        }
        return new(port);
    }
    public static TelegramEndpoint Read(string executable)
    {
        var portable = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(executable))!, "TgWsProxy_data");
        var directory = Directory.Exists(portable) ? portable : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TgWsProxy");
        var path = Path.Combine(directory, "config.json"); Storage.AssertNoLinks(path);
        if (!File.Exists(path)) return new(1443);
        if (new FileInfo(path).Length > 65536) throw new InvalidDataException("Настройки Telegram-прокси слишком большие.");
        try { return Parse(File.ReadAllText(path)); }
        catch (JsonException) { throw new InvalidDataException("Не удалось прочитать порт Telegram-прокси. Настройки не менялись."); }
    }
}
