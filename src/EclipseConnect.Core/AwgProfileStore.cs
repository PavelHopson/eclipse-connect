using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace EclipseConnect.Core;

[SupportedOSPlatform("windows")]
public static class WindowsDataProtection
{
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    public static byte[] Protect(byte[] input, string description, bool machine = false) => Transform(input, description, true, machine);
    public static byte[] Unprotect(byte[] input, string description) => Transform(input, description, false, false);
    private static byte[] Transform(byte[] input, string description, bool encrypt, bool machine)
    {
        var source = new Blob { Length = input.Length, Data = Marshal.AllocHGlobal(input.Length) };
        Blob output = default; IntPtr actualDescription = IntPtr.Zero;
        try
        {
            Marshal.Copy(input, 0, source.Data, input.Length);
            var ok = encrypt ? CryptProtectData(ref source, description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, machine ? 5u : 1u, out output)
                : CryptUnprotectData(ref source, out actualDescription, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok || !encrypt && Marshal.PtrToStringUni(actualDescription) != description) throw new CryptographicException("Windows не смогла открыть защищённый VPN-профиль этого пользователя.");
            if (output.Length is < 1 or > 128 * 1024) throw new CryptographicException("Недопустимый размер защищённого профиля.");
            var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result;
        }
        finally
        {
            if (source.Data != IntPtr.Zero) { Clear(source.Data, source.Length); Marshal.FreeHGlobal(source.Data); }
            if (output.Data != IntPtr.Zero) { Clear(output.Data, output.Length); LocalFree(output.Data); }
            if (actualDescription != IntPtr.Zero) LocalFree(actualDescription);
        }
    }
    private static void Clear(IntPtr memory, int length) { for (var i = 0; i < length; i++) Marshal.WriteByte(memory, i, 0); }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input, out IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
}

[SupportedOSPlatform("windows")]
public sealed class AwgProfileStore(Storage storage, AwgProfileSlot slot = AwgProfileSlot.Primary)
{
    private string Purpose => slot switch { AwgProfileSlot.Primary => "EclipseConnect.AmneziaWG.MetaProfile.v1", AwgProfileSlot.Reserve => "EclipseConnect.AmneziaWG.MetaReserve.v1", _ => throw new InvalidDataException("Неизвестный слот VPN-профиля.") };
    private string Relative => slot switch { AwgProfileSlot.Primary => "profiles/awg-meta-current.dpapi", AwgProfileSlot.Reserve => "profiles/awg-meta-reserve.dpapi", _ => throw new InvalidDataException("Неизвестный слот VPN-профиля.") };
    private string Previous => slot == AwgProfileSlot.Primary ? "profiles/awg-meta-previous.dpapi" : "profiles/awg-meta-reserve-previous.dpapi";
    public bool Exists => File.Exists(storage.Resolve(Relative));
    public AwgProfile? Load()
    {
        if (!Exists) return null;
        var encrypted = ReadBounded(storage.Resolve(Relative));
        var clear = WindowsDataProtection.Unprotect(encrypted, Purpose);
        try { return AwgProfile.Parse(new UTF8Encoding(false, true).GetString(clear)); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    public void Save(AwgProfile profile, bool replaceConfirmed)
    {
        var existed = Exists;
        if (existed && !replaceConfirmed) throw new InvalidOperationException("Замена VPN-профиля требует подтверждения.");
        var bytes = Encoding.UTF8.GetBytes(profile.Configuration);
        try
        {
            var encrypted = WindowsDataProtection.Protect(bytes, Purpose);
            if (existed) Atomic(Previous, ReadBounded(storage.Resolve(Relative)));
            Atomic(Relative, encrypted, existed && replaceConfirmed);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static byte[] ReadBounded(string path)
    {
        Storage.AssertNoLinks(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > 128 * 1024) throw new InvalidDataException("Повреждён защищённый VPN-профиль. Исходный файл не изменён.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes); return bytes;
    }
    private void Atomic(string relative, byte[] bytes, bool overwrite = true)
    {
        var path = storage.Resolve(relative); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { stream.Write(bytes); stream.Flush(true); }
            Storage.AssertNoLinks(path); File.Move(temp, path, overwrite);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
