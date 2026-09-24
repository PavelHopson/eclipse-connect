using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using EclipseConnect.Core;

// Opt-in local parser/evaluator only. No WinDivertOpen, service, tunnel, packet capture or send.
[SupportedOSPlatform("windows")]
internal static class CombinedFilterOffline
{
    public static async Task<int> Run(string engine)
    {
        var root = WindowsFixRuntime.Root(engine);
        var storage = new Storage(Path.Combine(Path.GetTempPath(), "connect-hybrid-offline-" + Guid.NewGuid().ToString("N")));
        await new WindowsFixRuntime(engine, storage).InspectCompanion(default);
        var locks = new List<FileStream>();
        IntPtr library = IntPtr.Zero;
        try
        {
            foreach (var relative in WebFixPolicy.Resources)
            {
                var source = Path.Combine(root, relative); Storage.AssertNoLinks(source);
                await using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (input.Length is <= 0 or > 32 * 1024 * 1024) throw new InvalidDataException("Invalid resource size");
                var hash = Convert.ToHexString(await SHA256.HashDataAsync(input));
                if (WindowsFixRuntime.BinaryHashes.TryGetValue(relative, out var pinned) && !hash.Equals(pinned, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Unverified binary");
                input.Position = 0; var target = storage.Resolve(relative); Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { await input.CopyToAsync(output); output.Flush(true); }
                var held = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read); locks.Add(held);
                if (Convert.ToHexString(await SHA256.HashDataAsync(held)) != hash) throw new IOException("Copy changed");
            }
            // Dependency search is restricted to this verified directory and System32.
            library = LoadLibraryEx(storage.Resolve("bin/WinDivert.dll"), IntPtr.Zero, 0x1100);
            if (library == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            var compile = Marshal.GetDelegateForFunctionPointer<Compile>(NativeLibrary.GetExport(library, "WinDivertHelperCompileFilter"));
            var evaluate = Marshal.GetDelegateForFunctionPointer<Evaluate>(NativeLibrary.GetExport(library, "WinDivertHelperEvalFilter"));
            var cases = 0;
            foreach (var port in new[] { 4500, 443, 65535 })
            {
                var path = storage.Resolve("filter-" + port + ".txt");
                await Parse(storage, port, path); // --wf-save exits before driver initialization.
                if (new FileInfo(path).Length is <= 0 or > 16384) throw new IOException("Invalid generated filter size");
                var full = File.ReadAllText(path);
                var exclusion = WebFixPolicy.ExclusionFilter(port);
                foreach (var filter in new[] { exclusion, full })
                {
                    if (!compile(filter, 0, IntPtr.Zero, 0, out var error, out var position))
                        throw new InvalidDataException("Filter compile failed at " + position + ": " + Marshal.PtrToStringAnsi(error));
                    cases++;
                }
                void Expect(string filter, IPAddress remote, bool outbound, bool udp, int remotePort, bool expected, IPAddress? localAddress = null)
                {
                    var v6 = remote.GetAddressBytes().Length == 16;
                    var local = localAddress ?? IPAddress.Parse(v6 ? "2001:4860:4860::8844" : "8.8.4.4");
                    var packet = Packet(outbound ? local : remote, outbound ? remote : local, udp,
                        outbound ? 32123 : remotePort, outbound ? remotePort : 32123, outbound);
                    var addr = new byte[80];
                    BinaryPrimitives.WriteUInt32LittleEndian(addr.AsSpan(8), (outbound ? 1u << 17 : 0) | (v6 ? 1u << 20 : 0));
                    var actual = evaluate(filter, packet, (uint)packet.Length, addr);
                    var nativeError = Marshal.GetLastWin32Error();
                    if (!actual && nativeError != 0 || actual != expected) throw new IOException($"Packet case {cases} failed: error={nativeError}; expected={expected}; actual={actual}");
                    cases++;
                }
                foreach (var prefix in MetaVpnPolicy.Prefixes)
                {
                    var network = IPNetwork.Parse(prefix); var upper = network.BaseAddress.GetAddressBytes();
                    for (var bit = network.PrefixLength; bit < upper.Length * 8; bit++) upper[bit / 8] |= (byte)(1 << (7 - bit % 8));
                    foreach (var ip in new[] { network.BaseAddress, new IPAddress(upper) })
                    foreach (var outbound in new[] { false, true })
                    foreach (var udp in new[] { false, true })
                    {
                        Expect(exclusion, ip, outbound, udp, 443, false);
                        Expect(full, ip, outbound, udp, 443, false);
                    }
                }
                foreach (var ip in new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2606:4700:4700::1111") })
                foreach (var outbound in new[] { false, true })
                {
                    Expect(exclusion, ip, outbound, true, port, false);
                    Expect(full, ip, outbound, true, port, false);
                    Expect(exclusion, ip, outbound, false, 443, true);
                    Expect(full, ip, outbound, false, 443, true);
                    Expect(exclusion, ip, outbound, true, 443, port != 443);
                    if (outbound) Expect(full, ip, true, true, 443, port != 443);
                    Expect(full, ip, outbound, false, 22, false);
                }
                foreach (var remote in new[] { "10.0.0.1", "127.0.0.1", "100.64.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "224.0.0.1", "::1", "fd00::1", "fe80::1", "ff02::1" })
                foreach (var outbound in new[] { false, true }) Expect(full, IPAddress.Parse(remote), outbound, false, 443, false);
                foreach (var outbound in new[] { false, true })
                {
                    Expect(full, IPAddress.Parse("1.1.1.1"), outbound, false, 443, true, IPAddress.Parse("192.168.1.2"));
                    Expect(full, IPAddress.Parse("2606:4700:4700::1111"), outbound, false, 443, true, IPAddress.Parse("fd00::2"));
                }
                Console.WriteLine($"HYBRID OFFLINE endpointPort={port}; parser/filter/evaluation passed; filterChars={full.Length}; no activation");
            }
            storage.AtomicJson("result.json", new { Cases = cases, Errors = 0, DriverOpened = false, NetworkChanged = false });
            Console.WriteLine($"HYBRID OFFLINE total={cases}; errors=0; driver not opened; report=" + storage.Resolve("result.json"));
            return 0;
        }
        catch (Exception error)
        {
            storage.AtomicJson("result.json", new { Errors = 1, Error = Redactor.Sanitize(error.Message), DriverOpened = false, NetworkChanged = false });
            Console.Error.WriteLine("HYBRID OFFLINE failed; report=" + storage.Resolve("result.json"));
            return 1;
        }
        finally { if (library != IntPtr.Zero) NativeLibrary.Free(library); foreach (var held in locks) held.Dispose(); }
    }
    private static async Task Parse(Storage storage, int port, string outputPath)
    {
        var start = new ProcessStartInfo(storage.Resolve("bin/winws.exe"))
        { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = storage.Resolve("bin"), RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("--dry-run"); start.ArgumentList.Add("--wf-save=" + outputPath);
        foreach (var arg in WebFixPolicy.Arguments(port))
        {
            var equals = arg.IndexOf('='); var value = equals < 0 ? "" : arg[(equals + 1)..];
            start.ArgumentList.Add(value.StartsWith("bin/", StringComparison.Ordinal) ? arg[..(equals + 1)] + storage.Resolve(value) : arg);
        }
        using var process = Process.Start(start) ?? throw new IOException("Offline parser did not start");
        var stdout = Drain(process.StandardOutput); var stderr = Drain(process.StandardError);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch { if (!process.HasExited) process.Kill(); throw; } // Exact test-only process.
        await Task.WhenAll(stdout, stderr);
        if (process.ExitCode != 0) throw new IOException("Offline parser exit=" + process.ExitCode + ": " + Redactor.Sanitize(await stderr));
    }
    private static async Task<string> Drain(StreamReader reader)
    {
        var tail = new System.Text.StringBuilder(); var buffer = new char[1024]; int count;
        while ((count = await reader.ReadAsync(buffer)) != 0)
        { tail.Append(buffer, 0, count); if (tail.Length > 2048) tail.Remove(0, tail.Length - 2048); }
        return tail.ToString();
    }
    private static byte[] Packet(IPAddress source, IPAddress destination, bool udp, int sourcePort, int destPort, bool outbound)
    {
        var v6 = source.GetAddressBytes().Length == 16; var ipLen = v6 ? 40 : 20; var transportLen = udp ? 8 : 20;
        var packet = new byte[ipLen + transportLen + 1]; packet[0] = v6 ? (byte)0x60 : (byte)0x45;
        if (v6)
        { BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), (ushort)(transportLen + 1)); packet[6] = udp ? (byte)17 : (byte)6; packet[7] = 64; }
        else
        { BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length); packet[8] = 64; packet[9] = udp ? (byte)17 : (byte)6; }
        source.GetAddressBytes().CopyTo(packet, v6 ? 8 : 12); destination.GetAddressBytes().CopyTo(packet, v6 ? 24 : 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLen), (ushort)sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLen + 2), (ushort)destPort);
        if (udp) BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLen + 4), (ushort)(transportLen + 1));
        else { packet[ipLen + 12] = 0x50; packet[ipLen + 13] = outbound ? (byte)0x18 : (byte)0x12; }
        return packet;
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Compile(string filter, int layer, IntPtr output, uint length, out IntPtr error, out uint position);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Evaluate(string filter, byte[] packet, uint length, byte[] address);
    [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
}
