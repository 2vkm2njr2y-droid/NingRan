using System.Buffers;
using System.Security.Cryptography;

namespace NingRan.Core.Internal;

internal static class PayloadContainer
{
    private static ReadOnlySpan<byte> Magic => "NRPAY004"u8;
    private const int BufferSize = 1024 * 1024;
    internal const int SenderSignatureSize = 64;
    internal const int MaximumEntries = 20_000;
    internal const long MaximumTotalNameBytes = 8L * 1024 * 1024;
    private const long MaximumPadding = 10L * 1024 * 1024 * 1024;

    public static async Task WriteAsync(
        Stream output,
        PayloadManifest manifest,
        SigningIdentity? signingIdentity,
        Action<long, string>? reportProgress,
        CancellationToken cancellationToken)
    {
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var authenticatedOutput = new HashingWriteStream(output, hasher, leaveOpen: true);
        await authenticatedOutput.WriteAsync(Magic.ToArray(), cancellationToken).ConfigureAwait(false);
        await authenticatedOutput.WriteAsync(new[] { signingIdentity is null ? (byte)0 : (byte)1 }, cancellationToken)
            .ConfigureAwait(false);
        await authenticatedOutput.WriteAsync(new[] { manifest.IsDirectory ? (byte)1 : (byte)0 }, cancellationToken)
            .ConfigureAwait(false);
        await BinaryFormat.WriteStringAsync(authenticatedOutput, manifest.RootName, cancellationToken).ConfigureAwait(false);

        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        long completed = 0;
        try
        {
            foreach (var entry in manifest.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await authenticatedOutput.WriteAsync(new[] { (byte)entry.Kind }, cancellationToken).ConfigureAwait(false);
                await BinaryFormat.WriteStringAsync(authenticatedOutput, entry.RelativePath, cancellationToken).ConfigureAwait(false);

                if (entry.Kind == PayloadEntryKind.Directory)
                {
                    await BinaryFormat.WriteInt64Async(authenticatedOutput, entry.LastWriteUtcTicks, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                await BinaryFormat.WriteInt64Async(authenticatedOutput, entry.Length, cancellationToken).ConfigureAwait(false);
                await BinaryFormat.WriteInt64Async(authenticatedOutput, entry.LastWriteUtcTicks, cancellationToken)
                    .ConfigureAwait(false);

                await using var input = new FileStream(
                    entry.SourceHandle,
                    FileAccess.Read,
                    BufferSize,
                    isAsync: true);
                if (input.Length != entry.Length)
                {
                    throw new NingRanException($"文件在准备后发生了变化：{entry.FullPath}");
                }

                long remaining = entry.Length;
                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var wanted = (int)Math.Min(buffer.Length, remaining);
                    var read = await BinaryFormat.ReadAtMostAsync(
                        input,
                        buffer.AsMemory(0, wanted),
                        cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new NingRanException($"文件在加密过程中被缩短：{entry.FullPath}");
                    }

                    await authenticatedOutput.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    remaining -= read;
                    completed = checked(completed + read);
                    reportProgress?.Invoke(completed, $"正在加密：{entry.RelativePath}");
                }

                if (input.Length != entry.Length ||
                    File.GetLastWriteTimeUtc(input.SafeFileHandle).Ticks != entry.LastWriteUtcTicks)
                {
                    throw new NingRanException($"文件在加密过程中发生了变化：{entry.FullPath}");
                }
            }

            if (manifest.PaddingLength > 0)
            {
                await authenticatedOutput.WriteAsync(new[] { (byte)PayloadEntryKind.Padding }, cancellationToken)
                    .ConfigureAwait(false);
                await BinaryFormat.WriteInt64Async(authenticatedOutput, manifest.PaddingLength, cancellationToken)
                    .ConfigureAwait(false);
                var remaining = manifest.PaddingLength;
                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var count = (int)Math.Min(buffer.Length, remaining);
                    RandomNumberGenerator.Fill(buffer.AsSpan(0, count));
                    await authenticatedOutput.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(buffer.AsSpan(0, count));
                    remaining -= count;
                }
            }

            await authenticatedOutput.WriteAsync(new[] { (byte)PayloadEntryKind.End }, cancellationToken).ConfigureAwait(false);
            var hash = hasher.GetHashAndReset();
            byte[]? signature = null;
            try
            {
                if (signingIdentity is not null)
                {
                    signature = signingIdentity.Key.SignHash(
                        hash,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    if (signature.Length != SenderSignatureSize)
                    {
                        throw new NingRanException("发送者身份证明生成失败。");
                    }

                    await BinaryFormat.WriteStringAsync(output, signingIdentity.Fingerprint, cancellationToken)
                        .ConfigureAwait(false);
                    await output.WriteAsync(signature, cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
                if (signature is not null)
                {
                    CryptographicOperations.ZeroMemory(signature);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static async Task<PayloadReadResult> ReadAsync(
        Stream input,
        string? stagingDirectory,
        Action<long, string>? reportProgress,
        CancellationToken cancellationToken)
    {
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var authenticatedInput = new HashingReadStream(input, hasher, leaveOpen: true);
        var magic = new byte[Magic.Length];
        await BinaryFormat.ReadExactlyAsync(authenticatedInput, magic, cancellationToken).ConfigureAwait(false);
        if (!magic.AsSpan().SequenceEqual(Magic))
        {
            throw new NingRanException("加密内容的内部格式不正确或已损坏。");
        }

        var flags = new byte[1];
        await BinaryFormat.ReadExactlyAsync(authenticatedInput, flags, cancellationToken).ConfigureAwait(false);
        if ((flags[0] & ~1) != 0)
        {
            throw new NingRanException("加密内容含有当前版本不支持的身份标记。");
        }

        var kind = new byte[1];
        await BinaryFormat.ReadExactlyAsync(authenticatedInput, kind, cancellationToken).ConfigureAwait(false);
        var isDirectory = kind[0] switch
        {
            0 => false,
            1 => true,
            _ => throw new NingRanException("加密内容的类型不正确或已损坏。"),
        };
        var rootName = PathSafety.ValidateNameSegment(
            await BinaryFormat.ReadStringAsync(authenticatedInput, cancellationToken).ConfigureAwait(false));
        long totalNameBytes = System.Text.Encoding.UTF8.GetByteCount(rootName);

        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directoryTimes = new List<(string Path, long Ticks)>();
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        var rootSeen = false;
        var entryCount = 0;
        long completed = 0;

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var record = new byte[1];
                await BinaryFormat.ReadExactlyAsync(authenticatedInput, record, cancellationToken).ConfigureAwait(false);
                var entryKind = record[0] switch
                {
                    (byte)PayloadEntryKind.End => PayloadEntryKind.End,
                    (byte)PayloadEntryKind.Directory => PayloadEntryKind.Directory,
                    (byte)PayloadEntryKind.File => PayloadEntryKind.File,
                    (byte)PayloadEntryKind.Padding => PayloadEntryKind.Padding,
                    _ => throw new NingRanException("加密内容含有未知条目，文件可能已损坏。"),
                };

                if (entryKind == PayloadEntryKind.End)
                {
                    break;
                }

                if (entryKind == PayloadEntryKind.Padding)
                {
                    var paddingLength = await BinaryFormat.ReadInt64Async(authenticatedInput, cancellationToken).ConfigureAwait(false);
                    if (paddingLength is < 0 or > MaximumPadding)
                    {
                        throw new NingRanException("加密内容的大小隐藏数据异常。");
                    }

                    await DiscardAsync(authenticatedInput, paddingLength, buffer, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (++entryCount > MaximumEntries)
                {
                    throw new NingRanException("加密文件包含过多条目，已停止处理。");
                }

                var relativePath = PathSafety.NormalizeRelativePath(
                    await BinaryFormat.ReadStringAsync(authenticatedInput, cancellationToken).ConfigureAwait(false));
                totalNameBytes = checked(
                    totalNameBytes + System.Text.Encoding.UTF8.GetByteCount(relativePath));
                if (totalNameBytes > MaximumTotalNameBytes)
                {
                    throw new NingRanException("加密文件中的名称总长度超过安全上限，已停止处理。");
                }
                var firstSegment = relativePath.Split('/', 2)[0];
                if (!string.Equals(firstSegment, rootName, StringComparison.OrdinalIgnoreCase) ||
                    !seenPaths.Add(relativePath))
                {
                    throw new NingRanException("加密文件包含重复或越过根目录的不安全路径。");
                }

                var isRoot = string.Equals(relativePath, rootName, StringComparison.OrdinalIgnoreCase);
                if (isRoot)
                {
                    if (rootSeen || (isDirectory && entryKind != PayloadEntryKind.Directory) ||
                        (!isDirectory && entryKind != PayloadEntryKind.File))
                    {
                        throw new NingRanException("加密内容的根条目不正确或已损坏。");
                    }

                    rootSeen = true;
                }

                var destination = stagingDirectory is null
                    ? null
                    : PathSafety.GetSafeDestination(stagingDirectory, relativePath);

                if (entryKind == PayloadEntryKind.Directory)
                {
                    var ticks = await ReadAndValidateTicksAsync(authenticatedInput, cancellationToken).ConfigureAwait(false);
                    if (destination is not null)
                    {
                        Directory.CreateDirectory(destination);
                        directoryTimes.Add((destination, ticks));
                    }

                    continue;
                }

                var length = await BinaryFormat.ReadInt64Async(authenticatedInput, cancellationToken).ConfigureAwait(false);
                if (length < 0)
                {
                    throw new NingRanException("加密内容中的文件大小不正确。");
                }

                var lastWriteTicks = await ReadAndValidateTicksAsync(authenticatedInput, cancellationToken).ConfigureAwait(false);
                FileStream? output = null;
                try
                {
                    if (destination is not null)
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                        output = new FileStream(
                            destination,
                            FileMode.CreateNew,
                            FileAccess.Write,
                            FileShare.None,
                            BufferSize,
                            FileOptions.Asynchronous | FileOptions.SequentialScan);
                        WindowsFileSystemSafety.VerifyHandlePath(output.SafeFileHandle, destination);
                        var outputAttributes = File.GetAttributes(output.SafeFileHandle);
                        if ((outputAttributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                        {
                            throw new NingRanException("还原目标不是普通磁盘文件，已停止处理。");
                        }
                    }

                    long remaining = length;
                    while (remaining > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var wanted = (int)Math.Min(buffer.Length, remaining);
                        var read = await BinaryFormat.ReadAtMostAsync(
                            authenticatedInput,
                            buffer.AsMemory(0, wanted),
                            cancellationToken).ConfigureAwait(false);
                        if (read == 0)
                        {
                            throw new NingRanException("加密文件不完整，文件内容提前结束。");
                        }

                        if (output is not null)
                        {
                            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        }

                        remaining -= read;
                        completed = checked(completed + read);
                        reportProgress?.Invoke(completed, $"正在还原：{relativePath}");
                    }

                    if (output is not null)
                    {
                        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    }
                }
                finally
                {
                    if (output is not null)
                    {
                        await output.DisposeAsync().ConfigureAwait(false);
                    }
                }

                if (destination is not null)
                {
                    File.SetLastWriteTimeUtc(destination, new DateTime(lastWriteTicks, DateTimeKind.Utc));
                }
            }

            if (!rootSeen)
            {
                throw new NingRanException("加密内容缺少根文件或根文件夹。");
            }

            var hash = hasher.GetHashAndReset();
            string? signerFingerprint = null;
            byte[]? signature = null;
            if ((flags[0] & 1) != 0)
            {
                signerFingerprint = await BinaryFormat.ReadStringAsync(input, cancellationToken).ConfigureAwait(false);
                if (signerFingerprint.Length != 64 || signerFingerprint.Any(character => !Uri.IsHexDigit(character)))
                {
                    CryptographicOperations.ZeroMemory(hash);
                    throw new NingRanException("发送者身份证明不正确或已损坏。");
                }

                signature = new byte[SenderSignatureSize];
                await BinaryFormat.ReadExactlyAsync(input, signature, cancellationToken).ConfigureAwait(false);
            }

            var trailing = new byte[1];
            if (await input.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
            {
                CryptographicOperations.ZeroMemory(hash);
                if (signature is not null) CryptographicOperations.ZeroMemory(signature);
                throw new NingRanException("加密内容结束标记之后还有异常数据。");
            }

            if (stagingDirectory is not null)
            {
                foreach (var (path, ticks) in directoryTimes
                    .OrderByDescending(item => item.Path.Length))
                {
                    Directory.SetLastWriteTimeUtc(path, new DateTime(ticks, DateTimeKind.Utc));
                }
            }

            return new PayloadReadResult(rootName, isDirectory, signerFingerprint, hash, signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<long> ReadAndValidateTicksAsync(
        Stream input,
        CancellationToken cancellationToken)
    {
        var ticks = await BinaryFormat.ReadInt64Async(input, cancellationToken).ConfigureAwait(false);
        if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
        {
            throw new NingRanException("加密内容中的文件时间不正确。");
        }

        return ticks;
    }

    private static async Task DiscardAsync(
        Stream input,
        long length,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var remaining = length;
        while (remaining > 0)
        {
            var wanted = (int)Math.Min(buffer.Length, remaining);
            var read = await BinaryFormat.ReadAtMostAsync(
                input,
                buffer.AsMemory(0, wanted),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new NingRanException("加密文件不完整，大小隐藏数据提前结束。");
            }

            remaining -= read;
        }
    }
}

internal sealed class PayloadReadResult(
    string rootName,
    bool isDirectory,
    string? signerFingerprint,
    byte[] authenticatedHash,
    byte[]? signature) : IDisposable
{
    public string RootName { get; } = rootName;
    public bool IsDirectory { get; } = isDirectory;
    public string? SignerFingerprint { get; } = signerFingerprint;
    public byte[] AuthenticatedHash { get; } = authenticatedHash;
    public byte[]? Signature { get; } = signature;
    public bool HasSenderSignature => SignerFingerprint is not null && Signature is not null;

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(AuthenticatedHash);
        if (Signature is not null)
        {
            CryptographicOperations.ZeroMemory(Signature);
        }
    }
}
