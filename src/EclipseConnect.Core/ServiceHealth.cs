namespace EclipseConnect.Core;

public sealed record ServiceSpec(string Id, string Name, string Url, string Scope);
public sealed record ServiceHealth(string Label, string Detail, string Freshness, string Tone);

public static class ServiceCatalog
{
    public static readonly ServiceSpec[] All =
    [
        new("telegram", "Telegram", "https://web.telegram.org/", "Проверяется Telegram Web, не Desktop-прокси и не звонки."),
        new("youtube", "YouTube", "https://www.youtube.com/", "Проверяется сайт, не воспроизведение видео."),
        new("rutracker", "RuTracker", "https://rutracker.org/", "Проверяется сайт, не вход и не загрузка торрентов."),
        new("discord", "Discord", "https://discord.com/", "Проверяется сайт, не голосовой канал."),
        new("instagram", "Instagram", "https://www.instagram.com/", "Проверяется сайт Instagram, не вход, фото или видео."),
        new("whatsapp", "WhatsApp", "https://web.whatsapp.com/", "Проверяется веб-узел. Вход и сообщения приложения Windows отдельно не подтверждены."),
        new("whatsapp-static", "WhatsApp файлы", "https://static.whatsapp.net/", "Проверяется узел загрузки файлов. Работа приложения Windows отдельно не подтверждена."),
        new("chatgpt", "ChatGPT", "https://chatgpt.com/", "Проверяется сайт, не вход в аккаунт и не ответы модели."),
        new("github", "GitHub", "https://api.github.com/", "Проверяется API GitHub, не загрузка файлов релизов.")
    ];
    public static ServiceSpec Get(string id) => All.FirstOrDefault(s => s.Id == id)
        ?? throw new InvalidDataException("Неизвестный сервис.");
    public static ServiceHealth Describe(ServiceSpec service, DiagnosticResult? result, DateTimeOffset now, bool checking = false)
    {
        if (checking) return new("Проверяется", "Подключения не переключаются.", "Выполняется HTTPS-запрос", "Muted");
        if (result == null || result.Target != new Uri(service.Url).Host)
            return new("Не проверен", service.Scope, "Нажмите «Проверить сервисы»", "Muted");
        var age = now - result.CheckedAt;
        var time = result.CheckedAt.ToLocalTime().ToString("dd.MM HH:mm");
        if (age < TimeSpan.Zero || age >= TimeSpan.FromMinutes(5))
            return new("Нужна новая проверка", "Ранее: " + result.State, "Результат от " + time, "Muted");
        var tone = result.State == "HTTPS доступен" ? "Success" :
            result.State is "Проверка браузера" or "Нужна проверка" || result.Code is DiagnosticCode.HttpAuthentication or DiagnosticCode.HttpRateLimited ? "Warning" : "Error";
        return new(result.State, result.Detail, "Проверено " + time, tone);
    }
}

public sealed record WindowBounds(double Left, double Top, double Width, double Height);
public static class WindowPlacement
{
    public static WindowBounds Fit(double? left, double? top, double width, double height, WindowBounds area)
    {
        var w = Math.Clamp(double.IsFinite(width) ? width : 1060, Math.Min(820, area.Width), area.Width);
        var h = Math.Clamp(double.IsFinite(height) ? height : 760, Math.Min(570, area.Height), area.Height);
        var x = left.HasValue && double.IsFinite(left.Value) ? left.Value : area.Left + (area.Width - w) / 2;
        var y = top.HasValue && double.IsFinite(top.Value) ? top.Value : area.Top + (area.Height - h) / 2;
        return new(Math.Clamp(x, area.Left, area.Left + area.Width - w),
            Math.Clamp(y, area.Top, area.Top + area.Height - h), w, h);
    }
}
