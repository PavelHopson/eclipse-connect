using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace EclipseConnect.Core;

// A fixed, demand-start service. Never use upstream /installtunnelservice (it enables auto-start).
[SupportedOSPlatform("windows")]
internal sealed class WindowsAwgService : IDisposable
{
    private readonly ServiceHandle service;
    private bool deleted;
    private WindowsAwgService(ServiceHandle service) { this.service = service; }
    internal static WindowsAwgService Create(string executable, string configuration)
    {
        if (executable.Contains('"') || configuration.Contains('"')) throw new InvalidDataException("Недопустимый путь VPN.");
        using var manager = OpenSCManager(null, null, 3); Check(manager);
        var handle = CreateService(manager, WindowsAwgEngine.ServiceName, "Eclipse Connect VPN (временный)", 0xF01FF,
            0x10, 3, 1, $"\"{executable}\" /tunnelservice \"{configuration}\"", null, IntPtr.Zero, "Nsi\0TcpIp\0\0", null, null);
        if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось создать собственную службу VPN. Внешняя служба не заменялась."); }
        var result = new WindowsAwgService(handle);
        try { uint sidType = 1; if (!ChangeServiceConfig2(handle, 5, ref sidType)) throw new Win32Exception(Marshal.GetLastWin32Error()); return result; }
        catch { result.Dispose(); throw; }
    }
    internal void Start() { if (!StartService(service, 0, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows не запустила службу VPN."); }
    internal ServiceStatus Status()
    {
        if (!QueryServiceStatusEx(service, 0, out var status, (uint)Marshal.SizeOf<ServiceStatus>(), out _)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось проверить собственную службу VPN.");
        return status;
    }
    internal void RequestStop()
    {
        if (Status().State == 1) return;
        if (!ControlService(service, 1, out _) && Marshal.GetLastWin32Error() != 1062) throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows не подтвердила остановку VPN.");
    }
    internal void DeleteWhenStopped()
    {
        if (deleted) return;
        if (!DeleteService(service)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось убрать временную службу VPN.");
        deleted = true; // Windows retains the running service while our handle is open, then removes it on stop/close.
    }
    internal static bool IsActive(string name)
    {
        using var manager = OpenSCManager(null, null, 1); Check(manager);
        using var handle = OpenService(manager, name, 4);
        if (handle.IsInvalid)
        {
            var code = Marshal.GetLastWin32Error(); if (code == 1060) return false;
            if (code == 1072) return true; // A previous marked-for-delete instance must finish first.
            throw new Win32Exception(code, "Не удалось проверить конфликтующие VPN-службы.");
        }
        if (!QueryServiceStatusEx(handle, 0, out var status, (uint)Marshal.SizeOf<ServiceStatus>(), out _)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return status.State != 1;
    }
    private static void Check(ServiceHandle handle) { if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Диспетчер служб Windows недоступен."); }
    public void Dispose() { try { DeleteWhenStopped(); } finally { service.Dispose(); } }
    [StructLayout(LayoutKind.Sequential)] internal struct ServiceStatus
    {
        public uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint, ProcessId, Flags;
    }
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern ServiceHandle CreateService(ServiceHandle manager, string name, string display, uint access, uint type, uint start, uint error,
        string binary, string? group, IntPtr tag, string dependencies, string? account, string? password);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool StartService(ServiceHandle service, uint count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(ServiceHandle service, int kind, out ServiceStatus status, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ControlService(ServiceHandle service, uint control, out ServiceStatus status);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig2(ServiceHandle service, uint kind, ref uint data);
    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeleteService(ServiceHandle service);
    [DllImport("advapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
}
