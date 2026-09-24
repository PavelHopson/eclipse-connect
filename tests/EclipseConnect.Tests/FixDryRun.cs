using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using EclipseConnect.Core;

// Opt-in engine parser check. --dry-run exits before WinDivert setup; no filter is activated.
[SupportedOSPlatform("windows")]
internal static class FixDryRun
{
    private static async Task<string> ErrorSummary(StreamReader reader)
    {
        var tail = new System.Text.StringBuilder(); var buffer = new char[1024]; int count;
        while ((count = await reader.ReadAsync(buffer)) > 0)
        {
            tail.Append(buffer, 0, count);
            if (tail.Length > 8192) tail.Remove(0, tail.Length - 8192);
        }
        return Redactor.Sanitize(tail.ToString());
    }
    public static async Task<int> Run()
    {
        if (!WindowsFixRuntime.IsAdministrator())
        { Console.WriteLine("DRY_RUN refused: use an explicitly approved UAC launch; no process started."); return 2; }
        if (Inventory.CountFixProcesses() != 0)
        { Console.WriteLine("DRY_RUN refused: close the existing FIX using its owning controller; no process stopped or started."); return 3; }
        var settings = new AppSettings(); Inventory.Discover(settings);
        var root = WindowsFixRuntime.Root(settings.FixPath);
        var storage = new Storage(Path.Combine(Path.GetTempPath(), "connect-fix-dry-run-" + Guid.NewGuid().ToString("N")));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(55));
        var evidence = new List<object>();
        foreach (var profile in FixCatalog.All)
        {
            await WindowsFixRuntime.InspectResources(settings.FixPath, profile.Id, deadline.Token);
            foreach (var relative in FixCatalog.Resources(profile.Id, true))
            {
                var destination = storage.Resolve(relative);
                if (File.Exists(destination)) continue;
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                var source = Path.Combine(root, relative); Storage.AssertNoLinks(source);
                await using Stream input = relative == TelegramFixCompatibility.ResourcePath
                    ? TelegramFixCompatibility.OpenResource() : File.OpenRead(source);
                if (input.Length > 32 * 1024 * 1024) throw new InvalidDataException("Oversized resource");
                var hash = Convert.ToHexString(await SHA256.HashDataAsync(input, deadline.Token)).ToLowerInvariant();
                if (WindowsFixRuntime.BinaryHashes.TryGetValue(relative, out var expected) && hash != expected)
                    throw new InvalidDataException("Unverified binary");
                input.Position = 0;
                await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await input.CopyToAsync(output, deadline.Token); output.Flush(true);
            }
        }
        var locks = Directory.EnumerateFiles(storage.Root, "*", SearchOption.AllDirectories)
            .Select(path => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)).ToArray();
        try
        {
            foreach (var profile in FixCatalog.All)
            foreach (var gaming in new[] { false, true })
            {
                var start = new ProcessStartInfo(storage.Resolve("bin/winws.exe"))
                { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = storage.Resolve("bin"), RedirectStandardOutput = true, RedirectStandardError = true };
                start.ArgumentList.Add("--dry-run");
                foreach (var arg in FixCatalog.Arguments(profile.Id, gaming))
                {
                    var equals = arg.IndexOf('='); var value = equals >= 0 ? arg[(equals + 1)..] : "";
                    start.ArgumentList.Add(value.StartsWith("bin/") || value.StartsWith("lists/") ? arg[..(equals + 1)] + storage.Resolve(value) : arg);
                }
                using var process = Process.Start(start) ?? throw new IOException("Dry-run did not start");
                // Bounded, sanitized parser output only; no debug flag or packet capture.
                var stdout = ErrorSummary(process.StandardOutput);
                var stderr = ErrorSummary(process.StandardError);
                try { await process.WaitForExitAsync(deadline.Token); }
                catch { if (!process.HasExited) process.Kill(); throw; }
                await Task.WhenAll(stdout, stderr);
                evidence.Add(new { Profile = profile.Id, Gaming = gaming, process.ExitCode, FilterActivated = false,
                    Error = process.ExitCode == 0 ? "" : (await stdout) + "\n" + (await stderr) });
                Console.WriteLine($"DRY_RUN {profile.Id}; gaming={gaming}; exit={process.ExitCode}; filter not activated");
                if (process.ExitCode != 0) { storage.AtomicJson("result.json", evidence); return 1; }
            }
        }
        finally { foreach (var file in locks) file.Dispose(); }
        storage.AtomicJson("result.json", evidence);
        Console.WriteLine("DRY_RUN_REPORT=" + storage.Resolve("result.json"));
        return 0;
    }
}
