using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public static class WindowsAwgEngine
{
    public const string Version = "3.1.0";
    public const string TunnelName = "EclipseConnectVPN";
    public const string ServiceName = "AmneziaWGTunnel$" + TunnelName;
    private static readonly (string Name, long Length, string Hash)[] Files =
    [
        ("amneziawg.exe", 9214392, "BA446F6E1A4093E43A65D6FF45F4B8C7B6485DC419327EEDAA1A218549740E3A"),
        ("awg.exe", 157624, "272BADACE73CAEB26DC42656F318B3EB7F10028C2F76FAAD1F52D6FE1E0CED12"),
        ("wintun.dll", 427552, "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE")
    ];
    public static string Bundle => Path.Combine(AppContext.BaseDirectory, "components", "amneziawg", Version);
    public static bool BundlePresent => Files.All(file => File.Exists(Path.Combine(Bundle, file.Name)));
    internal static List<FileStream> VerifyAndLock(string directory)
    {
        var held = new List<FileStream>();
        try
        {
            Storage.AssertNoLinks(directory);
            foreach (var file in Files)
            {
                var path = Path.Combine(directory, file.Name); Storage.AssertNoLinks(path);
                var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); held.Add(stream);
                if (stream.Length != file.Length || Convert.ToHexString(SHA256.HashData(stream)) != file.Hash)
                    throw new InvalidDataException("Движок AmneziaWG не совпадает с проверенным официальным релизом. Подключение запрещено.");
                stream.Position = 0;
            }
            return held;
        }
        catch { foreach (var stream in held) stream.Dispose(); throw; }
    }
    internal static string PrepareProtectedCopy()
    {
        if (!WindowsFixRuntime.IsAdministrator()) throw new UnauthorizedAccessException("Для VPN нужны подтверждённые права Windows.");
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EclipseConnectVpn");
        PrivateDirectory(root);
        var directory = Path.Combine(root, Guid.NewGuid().ToString("N")); PrivateDirectory(directory);
        var held = VerifyAndLock(Bundle);
        try
        {
            foreach (var source in held)
            {
                using var target = new FileStream(Path.Combine(directory, Path.GetFileName(source.Name)), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                source.CopyTo(target); target.Flush(true);
            }
        }
        finally { foreach (var stream in held) stream.Dispose(); }
        return directory;
    }
    internal static void PrivateDirectory(string path)
    {
        Storage.AssertNoLinks(path);
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false); acl.SetOwner(admin);
            foreach (var sid in new[] { admin, system }) acl.AddAccessRule(new(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            directory.Create(acl);
        }
        Storage.AssertNoLinks(path);
        var actual = directory.GetAccessControl(); var owner = actual.GetOwner(typeof(SecurityIdentifier));
        if (!actual.AreAccessRulesProtected || owner == null || !owner.Equals(admin) && !owner.Equals(system))
            throw new UnauthorizedAccessException("Папка VPN не защищена администратором. Автоматическое исправление прав не выполняется.");
        foreach (FileSystemAccessRule rule in actual.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !rule.IdentityReference.Equals(admin) && !rule.IdentityReference.Equals(system))
                throw new UnauthorizedAccessException("К папке VPN имеет доступ посторонняя учётная запись. Подключение запрещено.");
    }
    public static bool HasActiveTunnel()
        => HasActiveTunnelExcept(null);
    // Caller must first validate its own live SCM/process handles; no exemption by name alone.
    internal static bool HasActiveTunnelExcept(string? ownedAdapterId)
    {
        // GUI processes alone do not prove Amnezia is connected. Never inspect its profile store.
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        foreach (var name in services?.GetSubKeyNames() ?? [])
            if (!(ownedAdapterId != null && name.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)) &&
                (name.StartsWith("AmneziaWGTunnel$", StringComparison.OrdinalIgnoreCase) || name.StartsWith("WireGuardTunnel$", StringComparison.OrdinalIgnoreCase)) && WindowsAwgService.IsActive(name)) return true;
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            if (adapter.Id != ownedAdapterId && adapter.OperationalStatus == OperationalStatus.Up && new[] { "amnezia", "wireguard", "happ", "sing-box", "wintun" }
                .Any(n => (adapter.Name + " " + adapter.Description).Contains(n, StringComparison.OrdinalIgnoreCase))) return true;
        return ProcessesExist("sing-box", "xray", "v2ray", "clash", "clash-verge", "nekobox");
    }
    internal static bool ProcessesExist(params string[] names)
    {
        foreach (var name in names)
        {
            var processes = Process.GetProcessesByName(name);
            try { if (processes.Length > 0) return true; }
            finally { foreach (var process in processes) process.Dispose(); }
        }
        return false;
    }
}
