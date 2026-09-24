using System.Text.RegularExpressions;

namespace EclipseConnect.Core;

public sealed record AwgState(bool Running, bool Authenticated, string Message, DateTimeOffset? Handshake = null)
{
    public static AwgState Off => new(false, false, "VPN отключён.");
}
public enum AwgProfileSlot { Primary, Reserve }
public static class AwgProfileSelection
{
    public static string Name(AwgProfileSlot slot) => slot switch { AwgProfileSlot.Primary => "Основной", AwgProfileSlot.Reserve => "Резервный", _ => throw new InvalidDataException("Неизвестный слот VPN-профиля.") };
    public static bool CanChange(AwgState state, bool helperLost) => !state.Running && !helperLost;
    public static string ReserveHint(AwgProfile? primary, AwgProfile? reserve) => reserve == null
        ? "Резерв не настроен. Импортируйте второй .conf от независимого сервера; текущий профиль сохранится."
        : primary != null && primary.Revision == reserve.Revision ? "Это копия основного профиля, а не независимый резерв."
        : primary != null && string.Equals(primary.EndpointHost, reserve.EndpointHost, StringComparison.OrdinalIgnoreCase) ? "У профилей одинаковый адрес сервера. Такой резерв не защищает от его недоступности."
        : "Резерв сохранён. Другой адрес не доказывает независимость инфраструктуры; работу нужно проверить отдельно.";
}
public sealed record AwgRequest(int Schema, string Id, string Operation, string? Revision, bool Confirmed, long Sequence,
    AwgProfileSlot ProfileSlot = AwgProfileSlot.Primary);
public sealed record AwgReply(string Id, AwgState State, string? Error = null);
public static class AwgControlPolicy
{
    public static void Validate(AwgRequest request)
    {
        if (request.Schema != 1 || !Guid.TryParseExact(request.Id, "N", out _) || request.Sequence < 1 ||
            !Enum.IsDefined(request.ProfileSlot) || request.Operation != "start" && request.ProfileSlot != AwgProfileSlot.Primary ||
            request.Operation is not ("status" or "start" or "stop" or "cancel") ||
            request.Operation == "start" && (request.Revision == null || !Regex.IsMatch(request.Revision, @"\A[A-F0-9]{64}\z")) ||
            request.Operation != "start" && request.Revision != null ||
            request.Operation is "start" or "stop" && !request.Confirmed || request.Operation is "status" or "cancel" && request.Confirmed)
            throw new InvalidDataException("Недопустимая или неподтверждённая команда VPN.");
    }
}
public interface IAwgRuntime : IAsyncDisposable
{
    Task<AwgState> Status(CancellationToken ct);
    Task<AwgState> Start(AwgProfile profile, CancellationToken ct);
    Task<AwgState> Stop(CancellationToken ct);
}
public sealed class AwgControlSession(IAwgRuntime runtime, Func<AwgProfileSlot, AwgProfile?> loadProfile) : IAsyncDisposable
{
    public AwgControlSession(IAwgRuntime runtime, Func<AwgProfile?> loadProfile) : this(runtime,
        slot => slot == AwgProfileSlot.Primary ? loadProfile() : null) { }
    private int busy;
    private long sequence;
    public AwgState State { get; private set; } = AwgState.Off;
    public async Task<AwgState> Execute(AwgRequest request, CancellationToken ct)
    {
        AwgControlPolicy.Validate(request);
        if (request.Operation == "cancel") throw new InvalidDataException("Отмена обрабатывается только транспортом активной команды.");
        if (Interlocked.CompareExchange(ref busy, 1, 0) != 0) throw new InvalidOperationException("Команда VPN уже выполняется.");
        try
        {
            ct.ThrowIfCancellationRequested();
            if (request.Sequence != sequence + 1) throw new InvalidDataException("Повторная команда VPN отклонена.");
            sequence = request.Sequence;
            switch (request.Operation)
            {
                case "status": State = await runtime.Status(ct); break;
                case "start":
                    State = await runtime.Status(ct);
                    if (State.Running) throw new InvalidOperationException("Сначала отключите текущее подключение. Профили не переключаются на ходу.");
                    var profile = loadProfile(request.ProfileSlot) ?? throw new InvalidOperationException("Выбранный профиль отсутствует. Импортируйте его; другой профиль автоматически не используется.");
                    if (profile.Revision != request.Revision) throw new InvalidOperationException("Профиль изменился после подтверждения. Проверьте его и повторите подключение.");
                    State = await runtime.Start(profile, ct); break;
                case "stop": State = await runtime.Stop(ct); break;
            }
            return State;
        }
        catch
        {
            try { State = await runtime.Status(CancellationToken.None); }
            catch { State = new(State.Running, false, "Состояние VPN не удалось подтвердить. Проверьте подключение перед выходом."); }
            throw;
        }
        finally { Volatile.Write(ref busy, 0); }
    }
    public ValueTask DisposeAsync() => runtime.DisposeAsync();
}
