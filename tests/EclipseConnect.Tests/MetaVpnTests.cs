using System.Net;
using System.Net.Sockets;
using EclipseConnect.Core;

internal static class MetaVpnTests
{
    private static void Check(bool value) { if (!value) throw new Exception("Selective VPN assertion failed"); }
    private static void Reject(Action action)
    {
        try { action(); } catch (InvalidDataException) { return; } catch (InvalidOperationException) { return; }
        throw new Exception("Expected selective VPN rejection");
    }
    public static void Run(Action<string, Action> test)
    {
        var now = MetaVpnPolicy.ObservedAt.AddHours(1);
        var profile = AwgProfile.Parse(AwgTests.Fixture);
        test("Meta snapshot 40 IPv4 and 2 IPv6 networks, no overlaps", () =>
        {
            var routes = MetaVpnPolicy.ParseRoutes(MetaVpnPolicy.Prefixes);
            Check(routes.Length == 42 && routes.Count(r => r.BaseAddress.AddressFamily == AddressFamily.InterNetwork) == 40);
        });
        test("Meta routes Instagram IPv4 and IPv6", () => Check(
            MetaVpnPolicy.RoutesAddress(IPAddress.Parse("157.240.22.174")) &&
            MetaVpnPolicy.RoutesAddress(IPAddress.Parse("2a03:2880:f101:83:face:b00c:0:25de"))));
        test("Meta routes observed WhatsApp web and static IPv4 and IPv6", () =>
        {
            foreach (var address in new[] { "157.240.253.60", "57.144.249.32",
                "2a03:2880:f37a:120:face:b00c:0:167", "2a03:2880:f37c:120:face:b00c:0:167" })
                Check(MetaVpnPolicy.RoutesAddress(IPAddress.Parse(address)));
        });
        test("Meta leaves public DNS Cloudflare and local networks outside VPN", () =>
        {
            foreach (var address in new[] { "1.1.1.1", "8.8.8.8", "104.18.32.7", "172.64.155.209",
                "2606:4700::1111", "10.0.0.1", "192.168.0.1", "::1", "fc00::1", "::ffff:157.240.22.174" })
                Check(!MetaVpnPolicy.RoutesAddress(IPAddress.Parse(address)));
        });
        test("Meta configuration preserves original and all secret fields", () =>
        {
            var original = profile.Configuration; var revision = profile.Revision;
            var result = MetaVpnPolicy.ServiceConfiguration(profile, now);
            foreach (var line in original.Split('\n').Where(l => l.Length > 0 &&
                !l.StartsWith("DNS = ") && !l.StartsWith("Address = ") && !l.StartsWith("AllowedIPs = ")))
                Check(result.Split('\n').Contains(line));
            Check(profile.Configuration == original && profile.Revision == revision);
        });
        test("Meta config has only reviewed routes and no DNS or default routes", () =>
        {
            var result = MetaVpnPolicy.ServiceConfiguration(profile, now);
            Check(!result.Contains("DNS =") && !result.Contains("0.0.0.0/0") && !result.Contains("::/0"));
            var allowed = result.Split('\n').Single(l => l.StartsWith("AllowedIPs = "))[13..].Split(", ");
            Check(allowed.SequenceEqual(MetaVpnPolicy.Prefixes));
        });
        test("Meta interface addresses always use host masks", () =>
        {
            var broad = AwgProfile.Parse(AwgTests.Fixture.Replace("172.16.0.2,", "172.16.0.2/0,").Replace("2001:db8::2\n", "2001:db8::2/0\n"));
            var result = MetaVpnPolicy.ServiceConfiguration(broad, now);
            Check(result.Contains("Address = 172.16.0.2/32, 2001:db8::2/128\n"));
        });
        test("Meta empty or corrupt route list never falls back to full VPN", () =>
        {
            Reject(() => MetaVpnPolicy.ParseRoutes([]));
            Reject(() => MetaVpnPolicy.ParseRoutes(["bad", "2a03:2880::/32"]));
            Reject(() => MetaVpnPolicy.ParseRoutes(["157.240.0.0/17", "157.240.0.0/17", "2a03:2880::/32"]));
            Reject(() => MetaVpnPolicy.ParseRoutes(["157.240.0.0/17", "157.240.1.0/24", "2a03:2880::/32"]));
            Reject(() => MetaVpnPolicy.ParseRoutes(Enumerable.Repeat("157.240.0.0/17", 129)));
        });
        test("Meta rejects default half-default private shared and noncanonical routes", () =>
        {
            foreach (var route in new[] { "0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/16",
                "192.168.0.0/16", "127.0.0.0/16", "169.254.0.0/16", "224.0.0.0/16",
                "104.18.0.0/16", "172.64.0.0/16", "157.240.1.1/24" })
                Reject(() => MetaVpnPolicy.ParseRoutes([route, "2a03:2880::/32"]));
            foreach (var route in new[] { "::/0", "::/1", "8000::/1", "fc00::/32", "fe80::/32",
                "ff00::/32", "2001:db8::/32", "2606:4700::/32", "::ffff:9dF0:0/112" })
                Reject(() => MetaVpnPolicy.ParseRoutes(["157.240.0.0/17", route]));
        });
        test("Meta rejects single-family routing", () =>
        {
            Reject(() => MetaVpnPolicy.ParseRoutes(["157.240.0.0/17", "31.13.64.0/18"]));
            Reject(() => MetaVpnPolicy.ParseRoutes(["2a03:2880::/32", "2620:0:1c00::/40"]));
        });
        test("Meta expired or future snapshot refuses activation", () =>
        {
            Check(MetaVpnPolicy.IsCurrent(now));
            Reject(() => MetaVpnPolicy.ServiceConfiguration(profile, MetaVpnPolicy.ObservedAt.AddTicks(-1)));
            Reject(() => MetaVpnPolicy.ServiceConfiguration(profile, MetaVpnPolicy.ValidUntil));
        });
        test("Meta endpoint cannot route recursively into itself", () =>
        {
            MetaVpnPolicy.CheckEndpoint([IPAddress.Parse("162.159.192.1"), IPAddress.Parse("2606:4700:d0::1")]);
            Reject(() => MetaVpnPolicy.CheckEndpoint([]));
            Reject(() => MetaVpnPolicy.CheckEndpoint([IPAddress.Parse("157.240.0.1")]));
            Reject(() => MetaVpnPolicy.CheckEndpoint([IPAddress.Parse("2a03:2880::1")]));
            Reject(() => MetaVpnPolicy.CheckEndpoint(Enumerable.Repeat(IPAddress.Parse("1.1.1.1"), 33)));
        });
        test("Meta rejects unusable interface addresses", () =>
        {
            foreach (var address in new[] { "0.0.0.0", "127.0.0.1", "224.0.0.1", "157.240.0.1" })
                Reject(() => MetaVpnPolicy.ServiceConfiguration(AwgProfile.Parse(AwgTests.Fixture.Replace("172.16.0.2", address)), now));
            foreach (var address in new[] { "::", "::1", "fe80::2", "ff00::2", "2a03:2880::2" })
                Reject(() => MetaVpnPolicy.ServiceConfiguration(AwgProfile.Parse(AwgTests.Fixture.Replace("2001:db8::2", address)), now));
        });
        test("Meta no generated hooks TableOff or arbitrary runtime config input", () =>
        {
            var result = MetaVpnPolicy.ServiceConfiguration(profile, now);
            Check(!result.Contains("Table") && !result.Contains("PostUp") && !result.Contains("PreUp"));
            Reject(() => AwgProfile.Parse(result)); // Only the fixed internal policy can produce split routes.
        });
    }
}
