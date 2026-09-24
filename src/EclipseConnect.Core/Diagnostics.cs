using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EclipseConnect.Core;

public static class Diagnostics
{
    public static DiagnosticResult Classify(string target, int status, string? mitigated, string body)
    {
        var stamp = DateTimeOffset.Now;
        if (mitigated == "challenge" || body.Contains("challenge-platform", StringComparison.OrdinalIgnoreCase))
            return new(target, "Проверка браузера", $"HTTP {status}. Получен запрос проверки браузера. Это не ошибка DNS; вход и работа сервиса не подтверждены.", stamp, DiagnosticCode.BrowserChallenge, status);
        if (body.Contains("Unable to load site", StringComparison.OrdinalIgnoreCase))
            return new(target, "Отказ сайта", $"HTTP {status}. Получен ответ Unable to load site. Это не ошибка разрешения DNS.", stamp, DiagnosticCode.HttpDenied, status);
        if (status == 403) return new(target, "Доступ отклонён (403)", "Веб-сервер или его защитный слой ответил отказом. Причина не установлена: это не доказательство ошибки DNS или блокировки провайдером. Проверьте доступ в браузере; DNS и сертификаты менять не нужно.", stamp, DiagnosticCode.HttpDenied, status);
        if (status == 401) return new(target, "Нужна авторизация (401)", "Сервер доступен, но требует авторизацию. Connect не передаёт токены и не входит в аккаунт.", stamp, DiagnosticCode.HttpAuthentication, status);
        if (status == 429) return new(target, "Ограничение запросов (429)", "Сервер ограничил запросы. Повторите проверку позже; автоматических повторов и переключений нет.", stamp, DiagnosticCode.HttpRateLimited, status);
        if (status >= 500) return new(target, "Ошибка HTTP " + status, "Сервер или промежуточный узел ответил ошибкой. DNS уже не единственная возможная причина; повторите проверку позже.", stamp, DiagnosticCode.HttpServerError, status);
        if (status is >= 200 and < 400) return new(target, "HTTPS доступен", $"HTTP {status}. Авторизация, сообщения и файлы отдельно не проверялись." + (status >= 300 ? " Перенаправление не выполнялось." : ""), stamp, DiagnosticCode.HttpsResponse, status);
        return new(target, "Нужна проверка", $"HTTP {status}. Сервер ответил; полная работа сервиса не подтверждена.", stamp, DiagnosticCode.HttpsResponse, status);
    }
    public static DiagnosticResult ClassifyTransport(string target, HttpRequestError error, SocketError? socket = null)
    {
        var (state, detail, code) = error switch
        {
            HttpRequestError.NameResolutionError => ("Ошибка DNS", "Не удалось разрешить имя узла. Проверьте системный DNS; это не ответ HTTP 403.", DiagnosticCode.DnsFailure),
            HttpRequestError.SecureConnectionError => ("Ошибка TLS", "Защищённое соединение не установлено. Проверьте дату Windows и доверие сертификатам; проверка TLS не отключалась.", DiagnosticCode.TlsFailure),
            HttpRequestError.ProxyTunnelError => ("Ошибка прокси", "Прокси не создал HTTPS-туннель. Работоспособность конечного сервиса не установлена.", DiagnosticCode.ProxyFailure),
            HttpRequestError.ConnectionError when socket == SocketError.ConnectionRefused => ("Соединение отклонено", "Соединение отклонено до получения HTTP-ответа. Это не HTTP 403; проверьте сеть и доступность узла.", DiagnosticCode.ConnectionFailure),
            HttpRequestError.ConnectionError when socket == SocketError.TimedOut => ("Тайм-аут соединения", "Не получен ответ при установлении соединения. Недоступность узла, фильтрация и неполадки сети пока не различены.", DiagnosticCode.Timeout),
            HttpRequestError.ConnectionError => ("Ошибка соединения", "Соединение не установлено или сброшено до получения HTTP-ответа. Это не доказывает блокировку: возможны неполадки сети или сервера.", DiagnosticCode.ConnectionFailure),
            _ => ("Ошибка HTTPS", "Не удалось получить корректный HTTP-ответ. Проверка сертификатов включена; причина не установлена.", DiagnosticCode.Unknown)
        };
        return new(target, state, detail, DateTimeOffset.Now, code);
    }
    private static void ValidateTarget(Uri uri)
    {
        var allowed = ServiceCatalog.All.Select(s => new Uri(s.Url).Host);
        if (!uri.IsAbsoluteUri || uri.Scheme != "https" || !uri.IsDefaultPort || !allowed.Contains(uri.Host) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.UserInfo) || uri.Query.Length > 0 || uri.Fragment.Length > 0) throw new InvalidDataException("Адрес проверки не разрешён.");
    }
    public static Task<DiagnosticResult> Probe(Uri uri, CancellationToken ct)
    {
        ValidateTarget(uri);
        return ProbeCore(uri, new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(5) }, ct);
    }
    // Injected handlers allow deterministic offline regressions without DNS, credentials or network changes.
    internal static async Task<DiagnosticResult> ProbeCore(Uri uri, HttpMessageHandler handler, CancellationToken ct,
        TimeSpan? headersDeadline = null, TimeSpan? bodyDeadline = null)
    {
        using var client = new HttpClient(handler) { Timeout = headersDeadline ?? TimeSpan.FromSeconds(10) };
        ValidateTarget(uri); ct.ThrowIfCancellationRequested();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("EclipseConnect/0.8 diagnostic");
        try
        {
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
            var data = new byte[32768]; var used = 0;
            var mitigated = response.Headers.TryGetValues("cf-mitigated", out var values) ? values.FirstOrDefault() : null;
            try
            {
                using var bodyTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct); bodyTimeout.CancelAfter(bodyDeadline ?? TimeSpan.FromSeconds(5));
                await using var stream = await response.Content.ReadAsStreamAsync(bodyTimeout.Token);
                while (used < data.Length)
                { var n = await stream.ReadAsync(data.AsMemory(used), bodyTimeout.Token); if (n == 0) break; used += n; }
            }
            catch (Exception e) when (e is OperationCanceledException or IOException or HttpRequestException)
            {
                ct.ThrowIfCancellationRequested();
                var partial = Classify(uri.Host, (int)response.StatusCode, mitigated, Encoding.UTF8.GetString(data, 0, used));
                return partial.Code == DiagnosticCode.HttpsResponse
                    ? partial with { State = "Ответ неполный", Detail = $"HTTP {(int)response.StatusCode} получен, но чтение ответа прервано. Доступ к странице не подтверждён.", Code = DiagnosticCode.IncompleteResponse }
                    : partial with { Detail = partial.Detail + " Тело ответа прочитано не полностью." };
            }
            return Classify(uri.Host, (int)response.StatusCode, mitigated, Encoding.UTF8.GetString(data, 0, used));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new(uri.Host, "Тайм-аут", "HTTP-ответ не получен за отведённое время. Причина требует отдельной проверки; сеть не переключалась.", DateTimeOffset.Now, DiagnosticCode.Timeout); }
        catch (HttpRequestException e) { ct.ThrowIfCancellationRequested(); return ClassifyTransport(uri.Host, e.HttpRequestError, (e.InnerException as SocketException)?.SocketErrorCode); }
    }
    public static async Task<DiagnosticResult> DnsProbe(CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(5));
            var addresses = await Dns.GetHostAddressesAsync("chatgpt.com", timeout.Token);
            return new("Системный DNS", "Ответ получен", $"Адресов: {addresses.Length}. DNS и маршрут браузера с прокси могут отличаться.", DateTimeOffset.Now);
        }
        catch (Exception e) when (e is System.Net.Sockets.SocketException or OperationCanceledException)
        { ct.ThrowIfCancellationRequested(); return new("Системный DNS", "Нет ответа", "Не удалось разрешить chatgpt.com. Настройки не изменены.", DateTimeOffset.Now); }
    }
}
