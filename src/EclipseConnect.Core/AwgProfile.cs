using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace EclipseConnect.Core;

// Deliberately not a record: no generated ToString/JSON property may contain credentials.
public sealed class AwgProfile
{
    public const int MaxBytes = 64 * 1024;
    private readonly string configuration;
    public string Revision { get; }
    public int Mtu { get; }
    public int SignaturePackets { get; }
    public string EndpointHost { get; }
    internal string Configuration => configuration;
    private AwgProfile(string text, int mtu, int signatures, string endpointHost)
    {
        configuration = text; Mtu = mtu; SignaturePackets = signatures; EndpointHost = endpointHost;
        var bytes = Encoding.UTF8.GetBytes(text);
        try { Revision = Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public override string ToString() => "AmneziaWG: профиль скрыт";
    private static InvalidDataException Invalid(int line, string reason) =>
        new($"Профиль, строка {line}: {reason}"); // Never include input values, unknown field names or source lines.
    private static bool Match(string value, string pattern) => Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    public static AwgProfile Parse(string text)
    {
        if (text.Length > MaxBytes || Encoding.UTF8.GetByteCount(text) > MaxBytes) throw Invalid(0, "файл больше 64 КиБ.");
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var peer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var section = 0; var sawInterface = false; var sawPeer = false; var lineNumber = 0;
        foreach (var source in text.TrimStart('\uFEFF').Split('\n'))
        {
            lineNumber++;
            var line = source.Split('#')[0].Trim();
            if (line.Length == 0 || line.StartsWith(';')) continue;
            if (line.Any(c => char.IsControl(c) && c != '\t')) throw Invalid(lineNumber, "недопустимый управляющий символ.");
            if (line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase))
            {
                if (sawInterface || sawPeer) throw Invalid(lineNumber, "требуется один раздел Interface перед Peer.");
                sawInterface = true; section = 1; continue;
            }
            if (line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase))
            {
                if (!sawInterface || sawPeer) throw Invalid(lineNumber, "поддерживается один VPN-сервер в профиле.");
                sawPeer = true; section = 2; continue;
            }
            var equals = line.IndexOf('=');
            if (section == 0 || equals < 1) throw Invalid(lineNumber, "ожидается параметр внутри Interface или Peer.");
            var key = line[..equals].Trim(); var value = line[(equals + 1)..].Trim();
            var allowed = section == 1 ? InterfaceKeys : PeerKeys;
            var canonicalKey = allowed.FirstOrDefault(k => k.Equals(key, StringComparison.OrdinalIgnoreCase));
            if (canonicalKey == null) throw Invalid(lineNumber, "неподдерживаемый параметр. Команды Pre/PostUp/Down и произвольные расширения запрещены.");
            if (value.Length == 0) throw Invalid(lineNumber, "пустое значение параметра.");
            var target = section == 1 ? fields : peer;
            if (!target.TryAdd(canonicalKey, value)) throw Invalid(lineNumber, "повторный параметр запрещён.");
            switch (canonicalKey)
            {
                case "PrivateKey": case "PublicKey": case "PresharedKey":
                    if (!Match(value, @"\A[A-Za-z0-9+/]{43}=\z")) throw Invalid(lineNumber, "ключ должен быть Base64 из 32 байтов. Импортируйте исходный .conf локально.");
                    var keyBytes = Convert.FromBase64String(value);
                    try { if (keyBytes.Length != 32 || keyBytes.All(b => b == 0) || Convert.ToBase64String(keyBytes) != value) throw Invalid(lineNumber, "недопустимый ключ."); }
                    finally { CryptographicOperations.ZeroMemory(keyBytes); }
                    break;
                case "Address": case "AllowedIPs":
                    target[canonicalKey] = string.Join(", ", List(value, lineNumber).Select(v => Cidr(v, lineNumber))); break;
                case "DNS":
                    target[canonicalKey] = string.Join(", ", List(value, lineNumber).Select(v => ParseIp(v, lineNumber).ToString())); break;
                case "Endpoint": target[canonicalKey] = Endpoint(value, lineNumber); break;
                case "I1": case "I2": case "I3": case "I4": case "I5": ValidateSignature(value, lineNumber); break;
                case "H1": case "H2": case "H3": case "H4": Header(value, lineNumber); break;
                default:
                    var max = canonicalKey == "Jc" ? 128u : canonicalKey is "Jmin" or "Jmax" or "S1" or "S2" or "S3" or "S4" ? 2048u : 65535u;
                    if (!uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number > max ||
                        canonicalKey == "MTU" && number < 1280) throw Invalid(lineNumber, "числовой параметр вне поддерживаемого диапазона.");
                    target[canonicalKey] = number.ToString(CultureInfo.InvariantCulture); break;
            }
        }
        if (!sawInterface || !sawPeer || !new[] { "PrivateKey", "Address", "DNS" }.All(fields.ContainsKey) ||
            !new[] { "PublicKey", "AllowedIPs", "Endpoint" }.All(peer.ContainsKey)) throw Invalid(0, "не хватает обязательных параметров Interface/Peer.");
        var addresses = fields["Address"].Split(", ");
        // First integration is intentionally full-tunnel dual-stack; unsupported split routes fail closed.
        if (!addresses.Any(a => a.Contains(':')) || !addresses.Any(a => !a.Contains(':')) ||
            !peer["AllowedIPs"].Split(", ").Order().SequenceEqual(new[] { "0.0.0.0/0", "::/0" }.Order()))
            throw Invalid(0, "эта версия поддерживает полный IPv4/IPv6-туннель: оба Address и AllowedIPs = 0.0.0.0/0, ::/0.");
        if (Number(fields, "Jmin") > Number(fields, "Jmax")) throw Invalid(0, "Jmin не может превышать Jmax.");
        var headers = Enumerable.Range(1, 4).Select(n => Header(fields.GetValueOrDefault("H" + n, n.ToString(CultureInfo.InvariantCulture)), 0)).ToArray();
        for (var a = 0; a < headers.Length; a++) for (var b = a + 1; b < headers.Length; b++)
            if (headers[a].Min <= headers[b].Max && headers[b].Min <= headers[a].Max) throw Invalid(0, "значения H1–H4 не должны пересекаться.");
        if (!fields.ContainsKey("MTU")) fields["MTU"] = "1280";
        var output = new StringBuilder("[Interface]\n");
        foreach (var key in InterfaceKeys) if (fields.TryGetValue(key, out var value)) output.Append(key).Append(" = ").Append(value).Append('\n');
        output.Append("\n[Peer]\n");
        foreach (var key in PeerKeys) if (peer.TryGetValue(key, out var value)) output.Append(key).Append(" = ").Append(value).Append('\n');
        var endpoint = peer["Endpoint"];
        return new(output.ToString(), (int)Number(fields, "MTU"), fields.Keys.Count(k => Match(k, "^I[1-5]$")), endpoint[..endpoint.LastIndexOf(':')].Trim('[', ']'));
    }
    private static readonly string[] InterfaceKeys = ["PrivateKey", "MTU", "Address", "DNS", "ListenPort", "S1", "S2", "S3", "S4", "Jc", "Jmin", "Jmax", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"];
    private static readonly string[] PeerKeys = ["PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"];
    private static uint Number(Dictionary<string, string> fields, string key) => uint.Parse(fields.GetValueOrDefault(key, "0"), CultureInfo.InvariantCulture);
    private static string[] List(string value, int line)
    {
        var values = value.Split(',').Select(v => v.Trim()).ToArray();
        if (values.Length > 16 || values.Any(v => v.Length == 0)) throw Invalid(line, "некорректный список адресов.");
        return values;
    }
    private static IPAddress ParseIp(string value, int line)
    {
        if (value.Contains('%') || !IPAddress.TryParse(value, out var ip) || ip.IsIPv4MappedToIPv6 ||
            (ip.AddressFamily == AddressFamily.InterNetwork && (value.Split('.').Length != 4 || ip.ToString() != value)))
            throw Invalid(line, "некорректный IPv4/IPv6-адрес.");
        return ip;
    }
    private static string Cidr(string value, int line)
    {
        var parts = value.Split('/'); var ip = ParseIp(parts[0], line); var bits = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (parts.Length > 2 || parts.Length == 2 && (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out bits) || bits < 0 || bits > (ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)))
            throw Invalid(line, "неверная длина сетевой маски.");
        return ip + "/" + bits.ToString(CultureInfo.InvariantCulture);
    }
    private static string Endpoint(string value, int line)
    {
        var colon = value.LastIndexOf(':');
        if (colon < 1 || !ushort.TryParse(value[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port == 0)
            throw Invalid(line, "Endpoint должен иметь вид сервер:порт.");
        var host = value[..colon];
        if (host.StartsWith('[') && host.EndsWith(']'))
        {
            if (ParseIp(host[1..^1], line).AddressFamily != AddressFamily.InterNetworkV6) throw Invalid(line, "ожидается IPv6 Endpoint.");
        }
        else if (host.Length > 253 || !host.Split('.').All(label => Match(label, @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z")))
            throw Invalid(line, "некорректное имя Endpoint.");
        return host.ToLowerInvariant() + ":" + port.ToString(CultureInfo.InvariantCulture);
    }
    private static (uint Min, uint Max) Header(string value, int line)
    {
        var range = value.Split('-');
        if (range.Length > 2 || !uint.TryParse(range[0], NumberStyles.None, CultureInfo.InvariantCulture, out var min)) throw Invalid(line, "неверный H-параметр.");
        var max = min;
        if (range.Length == 2 && (!uint.TryParse(range[1], NumberStyles.None, CultureInfo.InvariantCulture, out max) || max < min)) throw Invalid(line, "неверный диапазон H.");
        return (min, max);
    }
    private static void ValidateSignature(string value, int line)
    {
        var offset = 0; var total = 0; var count = 0; var timestamp = false;
        while (offset < value.Length)
        {
            var end = value.IndexOf('>', offset);
            if (end < 0 || value[offset] != '<' || ++count > 64) throw Invalid(line, "неверный CPS-пакет I1–I5. Используйте .conf без экранирования из чата.");
            var tag = value[(offset + 1)..end];
            if (Match(tag, @"\Ab 0x(?:[a-fA-F0-9]{2})+\z")) total += (tag.Length - 4) / 2;
            else if (Match(tag, @"\Ar(?:c|d)? [0-9]{1,4}\z"))
            {
                var size = int.Parse(tag[(tag.IndexOf(' ') + 1)..], CultureInfo.InvariantCulture);
                if (size is < 1 or > 1000) throw Invalid(line, "длина случайного CPS-блока вне диапазона 1–1000.");
                total += size;
            }
            else if (tag == "t")
            {
                if (timestamp) throw Invalid(line, "в CPS-пакете разрешён только один timestamp.");
                timestamp = true; total += 4;
            }
            else throw Invalid(line, "неподдерживаемый CPS-тег. Пакет не будет удалён или изменён молча.");
            if (total > 2048) throw Invalid(line, "CPS-пакет больше поддерживаемых 2048 байтов.");
            offset = end + 1;
        }
    }
    public static AwgProfile ReadLocalFile(string path)
    {
        if (!Match(path, @"\A[A-Za-z]:[\\/]") || path[2..].Contains(':') || !Path.GetExtension(path).Equals(".conf", StringComparison.OrdinalIgnoreCase))
            throw Invalid(0, "выберите локальный файл .conf, не сетевой путь или ссылку.");
        Storage.AssertNoLinks(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxBytes) throw Invalid(0, "файл больше 64 КиБ.");
        var bytes = new byte[(int)stream.Length];
        try { stream.ReadExactly(bytes); return Parse(new UTF8Encoding(false, true).GetString(bytes)); }
        catch (DecoderFallbackException) { throw Invalid(0, "нужен текстовый .conf в UTF-8."); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
