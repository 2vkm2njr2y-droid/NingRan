namespace NingRan.Core.Internal;

internal static class BoundedFileReader
{
    public static byte[] ReadAllBytes(string path, int maximumLength, string description)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumLength);
        using var handle = WindowsFileSystemSafety.OpenInputFile(path);
        using var stream = new FileStream(handle, FileAccess.Read);
        ValidateLength(stream.Length, maximumLength, description);
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    public static async Task<byte[]> ReadAllBytesAsync(
        string path,
        int maximumLength,
        string description,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumLength);
        using var handle = WindowsFileSystemSafety.OpenInputFile(path);
        await using var stream = new FileStream(handle, FileAccess.Read, 16 * 1024, isAsync: true);
        ValidateLength(stream.Length, maximumLength, description);
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    private static void ValidateLength(long length, int maximumLength, string description)
    {
        if (length is <= 0 || length > maximumLength)
        {
            throw new NingRanException($"{description}大小不正确或超过安全上限。");
        }
    }
}
