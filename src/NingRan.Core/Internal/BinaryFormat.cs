using System.Buffers.Binary;
using System.Text;

namespace NingRan.Core.Internal;

internal static class BinaryFormat
{
    public const int MaximumNameBytes = 32 * 1024;

    public static async ValueTask ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new EndOfStreamException("加密文件不完整。");
            }

            read += count;
        }
    }

    public static async ValueTask<int> ReadAtMostAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            read += count;
        }

        return read;
    }

    public static async ValueTask WriteUInt32Async(
        Stream stream,
        uint value,
        CancellationToken cancellationToken)
    {
        var bytes = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask WriteInt64Async(
        Stream stream,
        long value,
        CancellationToken cancellationToken)
    {
        var bytes = new byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<uint> ReadUInt32Async(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var bytes = new byte[sizeof(uint)];
        await ReadExactlyAsync(stream, bytes, cancellationToken).ConfigureAwait(false);
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
    }

    public static async ValueTask<long> ReadInt64Async(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var bytes = new byte[sizeof(long)];
        await ReadExactlyAsync(stream, bytes, cancellationToken).ConfigureAwait(false);
        return BinaryPrimitives.ReadInt64LittleEndian(bytes);
    }

    public static async ValueTask WriteStringAsync(
        Stream stream,
        string value,
        CancellationToken cancellationToken)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length is 0 or > MaximumNameBytes)
        {
            throw new NingRanException("文件名过长，无法安全处理。");
        }

        await WriteUInt32Async(stream, (uint)bytes.Length, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<string> ReadStringAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var length = await ReadUInt32Async(stream, cancellationToken).ConfigureAwait(false);
        if (length is 0 or > MaximumNameBytes)
        {
            throw new InvalidDataException("加密文件中的名称不正确。");
        }

        var bytes = new byte[(int)length];
        await ReadExactlyAsync(stream, bytes, cancellationToken).ConfigureAwait(false);
        return new UTF8Encoding(false, true).GetString(bytes);
    }

    public static int EncodedStringLength(string value) =>
        sizeof(uint) + Encoding.UTF8.GetByteCount(value);
}
