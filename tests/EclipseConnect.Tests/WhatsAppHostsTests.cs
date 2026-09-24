using System.Net;
using System.Runtime.Versioning;
using EclipseConnect.Core;

internal static class WhatsAppHostsTests
{
    private static void Check(bool value) { if (!value) throw new Exception("Assertion failed"); }
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest)
    {
        const string original = "127.0.0.1 localhost\r\n# TailscaleHostsSectionStart\r\n100.1.2.3 example.ts.net\r\n# TailscaleHostsSectionEnd\r\n";
        var address = IPAddress.Parse("57.144.249.32");
        test("WhatsApp hosts patch is exact and reversible", () =>
        {
            var applied = WhatsAppHostsPolicy.Apply(original, address);
            Check(WhatsAppHostsPolicy.IsManaged(applied));
            Check(applied.Contains("\r\n57.144.249.32 web.whatsapp.com static.whatsapp.net\r\n"));
            Check(WhatsAppHostsPolicy.Remove(applied) == original);
            Check(!applied.Contains("instagram.com") && applied.Contains("100.1.2.3 example.ts.net"));
        });
        test("WhatsApp hosts refuses foreign mappings", () =>
        {
            try { WhatsAppHostsPolicy.Apply(original + "1.2.3.4 web.whatsapp.com\r\n", address); }
            catch (InvalidOperationException) { return; }
            throw new Exception("Expected refusal");
        });
        test("WhatsApp hosts refuses private and tampered addresses", () =>
        {
            foreach (var value in new[] { "127.0.0.1", "10.0.0.1", "8.8.8.8" })
            {
                try { WhatsAppHostsPolicy.Apply(original, IPAddress.Parse(value)); }
                catch (InvalidDataException) { continue; }
                throw new Exception("Expected refusal");
            }
            var tampered = WhatsAppHostsPolicy.Apply(original, address).Replace(
                "57.144.249.32 web.whatsapp.com static.whatsapp.net", "8.8.8.8 web.whatsapp.com static.whatsapp.net");
            try { WhatsAppHostsPolicy.Remove(tampered); }
            catch (InvalidDataException) { return; }
            throw new Exception("Expected refusal");
        });
        test("WhatsApp hosts refuses duplicate apply", () =>
        {
            try { WhatsAppHostsPolicy.Apply(WhatsAppHostsPolicy.Apply(original, address), address); }
            catch (InvalidOperationException) { return; }
            throw new Exception("Expected refusal");
        });
        if (OperatingSystem.IsWindows()) await asyncTest("WhatsApp candidate skips blocked and non-Meta IPs", CheckCandidateSelection);
    }

    [SupportedOSPlatform("windows")]
    private static async Task CheckCandidateSelection()
    {
        var address = IPAddress.Parse("57.144.249.32");
        var checkedAddresses = new List<IPAddress>();
            var selected = await WindowsWhatsAppHosts.FindCandidate(
                (name, _) => Task.FromResult(name switch
                {
                    "web.whatsapp.com" => new[] { IPAddress.Parse("10.0.0.1"), IPAddress.Parse("157.240.253.60") },
                    "media-fra3-1.cdn.whatsapp.net" => [address],
                    _ => Array.Empty<IPAddress>()
                }),
                (candidate, _) =>
                {
                    checkedAddresses.Add(candidate);
                    return Task.FromResult(candidate.Equals(address));
                }, default);
            Check(selected.Equals(address));
            Check(checkedAddresses.SequenceEqual([IPAddress.Parse("157.240.253.60"), address]));
    }
}
