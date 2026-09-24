namespace EclipseConnect.Core;

// An accident-prevention interlock, not an OS authorization boundary. Never persisted.
public sealed class SessionSafety
{
    private readonly object sync = new();
    private bool protectedMode = true;
    private long generation;
    public bool IsProtected { get { lock (sync) return protectedMode; } }
    public void Protect() { lock (sync) { protectedMode = true; generation++; } }
    public void AllowForSession(bool confirmed)
    {
        if (!confirmed) throw new InvalidOperationException("Разрешение управления требует подтверждения.");
        lock (sync) { protectedMode = false; generation++; }
    }
    public long CapturePermit()
    {
        lock (sync)
        {
            if (protectedMode) throw new InvalidOperationException("Защита включена. Запуск и остановка компонентов заблокированы.");
            return generation;
        }
    }
    public T Commit<T>(long permit, CancellationToken ct, Func<T> action)
    {
        lock (sync)
        {
            ct.ThrowIfCancellationRequested();
            if (protectedMode || permit != generation) throw new InvalidOperationException("Разрешение управления отозвано. Действие не выполнено.");
            return action();
        }
    }
}

public static class WindowClosePolicy
{
    public static bool HideInTray(bool closeToTray, bool trayAvailable, bool explicitExit, bool sessionEnding, bool qa)
        => closeToTray && trayAvailable && !explicitExit && !sessionEnding && !qa;
}
