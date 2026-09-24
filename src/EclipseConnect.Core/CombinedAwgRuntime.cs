namespace EclipseConnect.Core;

// Commands are serialized by AwgControlSession. VPN keeps the global lease until FIX stops.
internal sealed class CombinedAwgRuntime(IAwgRuntime vpn,
    Func<AwgProfile, CancellationToken, Task<IManagedProcess>> startFix,
    Func<CancellationToken, Task> preflight) : IAwgRuntime
{
    private IManagedProcess? fix;
    private bool started;
    public async Task<AwgState> Status(CancellationToken ct)
    {
        var state = await vpn.Status(ct);
        if (!started && fix == null) return state;
        if (fix?.IsRunning != true || !state.Authenticated)
            return new(true, false, "Совместное подключение требует проверки: VPN или FIX не подтверждён. Отключите подключение перед повторным запуском.", state.Handshake);
        return state with { Message = "VPN подтверждён, FIX работает. Доступ к сайтам проверяется отдельно." };
    }
    public async Task<AwgState> Start(AwgProfile profile, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (started || fix != null) throw new InvalidOperationException("Сначала отключите текущее подключение.");
        await preflight(ct); // Do not alter the network if FIX resources are missing/invalid.
        started = true;
        try
        {
            var state = await vpn.Start(profile, ct);
            if (!state.Authenticated) throw new IOException("VPN не подтверждён; FIX не запущен.");
            fix = await startFix(profile, ct);
            ct.ThrowIfCancellationRequested();
            if (!fix.IsRunning) throw new IOException("FIX завершился при подключении.");
            return await Status(ct);
        }
        catch
        {
            try { await Stop(CancellationToken.None); }
            catch { throw new IOException("Подключение не завершено; остановка одного из компонентов не подтверждена. Нажмите «Отключить VPN + FIX» повторно."); }
            throw;
        }
    }
    public async Task<AwgState> Stop(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (fix != null)
        {
            fix.Stop(); // Failure retains the exact process and VPN/interlock for retry.
            fix.Dispose(); fix = null;
        }
        await vpn.Stop(CancellationToken.None);
        started = false;
        return new(false, false, "Собственные FIX и VPN отключены. Другие подключения не изменялись.");
    }
    public async ValueTask DisposeAsync()
    {
        try { await Stop(CancellationToken.None); }
        finally
        {
            try { fix?.Dispose(); fix = null; }
            finally { await vpn.DisposeAsync(); }
        }
    }
}
