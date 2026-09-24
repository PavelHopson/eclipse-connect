using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace EclipseConnect.Core;

public static class FixWire
{
    public const int MaxFrame = 32768;
    private static readonly JsonSerializerOptions Options = new()
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 16 };
    public static async Task Write<T>(Stream stream, T value, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Options);
        if (bytes.Length > MaxFrame) throw new InvalidDataException("Ответ FIX превышает лимит.");
        var prefix = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(prefix, bytes.Length);
        await stream.WriteAsync(prefix, ct); await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct);
    }
    public static async Task<T> Read<T>(Stream stream, CancellationToken ct)
    {
        var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, ct);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length is <= 0 or > MaxFrame) throw new InvalidDataException("Размер сообщения FIX недопустим.");
        var bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, ct);
        return JsonSerializer.Deserialize<T>(bytes, Options) ?? throw new InvalidDataException("Пустая команда FIX.");
    }
}
