using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NingRan.Core.Internal;

/// <summary>
/// 新版归档内容：目录索引和每个文件都按固定大小的认证分段保存。
/// 这样在通过解锁验证后可以直接读取某个媒体分段，不必把明文写入磁盘。
/// </summary>
internal static class IndexedPayloadContainer
{
    // 保持与 6.1.2 新建归档一致的认证分段大小，确保本次正在测试的媒体文件可继续打开。
    // 连续播放的流畅性由查看器的后台预读保证，不通过改变既有归档布局实现。
    internal const int BlockSize = 4 * 1024 * 1024;
    private const int TagSize = CryptoSizes.Tag;
    private const long RecordSize = BlockSize + TagSize;
    private const int PrefixSize = 32;
    private const int MaximumIndexBytes = 16 * 1024 * 1024;
    private const int MaximumIndexBlocks = MaximumIndexBytes / BlockSize;
    private const int MaximumEntries = 20_000;
    private const long MaximumTotalNameBytes = 8L * 1024 * 1024;
    private const int SenderSignatureSize = 64;
    private static ReadOnlySpan<byte> PrefixMagic => "NRIDX006"u8;
    private static ReadOnlySpan<byte> IndexMagic => "NRPAY006"u8;

    public static async Task<IndexedPayload> WriteAsync(
        Stream output,
        PayloadManifest manifest,
        ArchiveHeader header,
        byte[] dataKey,
        SigningIdentity signingIdentity,
        Action<long, string>? reportProgress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(dataKey);
        ArgumentNullException.ThrowIfNull(signingIdentity);

        var entries = manifest.Entries.Select(entry => new IndexedPayloadEntry(
            entry.Kind,
            entry.RelativePath,
            entry.Length,
            entry.LastWriteUtcTicks,
            0,
            entry.Kind == PayloadEntryKind.File ? GetBlockCount(entry.Length) : 0,
            NrMediaFiles.TryGetKind(entry.RelativePath))).ToArray();
        byte[]? preliminaryIndex = null;
        byte[]? indexBytes = null;
        byte[]? prefix = null;
        try
        {
            preliminaryIndex = BuildIndex(manifest.IsDirectory, manifest.RootName, entries, signingIdentity);
            var indexBlockCount = GetBlockCount(preliminaryIndex.Length);
            if (indexBlockCount is < 1 or > MaximumIndexBlocks)
            {
                throw new NingRanException("加密文件的目录信息过大，无法安全保存。");
            }

            long nextDataBlock = indexBlockCount;
            for (var index = 0; index < entries.Length; index++)
            {
                var entry = entries[index];
                entries[index] = entry with { DataBlockStart = entry.Kind == PayloadEntryKind.File ? nextDataBlock : 0 };
                nextDataBlock = checked(nextDataBlock + entry.DataBlockCount);
            }

            indexBytes = BuildIndex(manifest.IsDirectory, manifest.RootName, entries, signingIdentity);
            var finalIndexBlockCount = GetBlockCount(indexBytes.Length);
            if (finalIndexBlockCount != indexBlockCount)
            {
                // 数据起始编号本身是固定长度字段；若索引刚好跨过分段边界，重建一次即可稳定。
                indexBlockCount = finalIndexBlockCount;
                nextDataBlock = indexBlockCount;
                for (var index = 0; index < entries.Length; index++)
                {
                    var entry = entries[index];
                    entries[index] = entry with { DataBlockStart = entry.Kind == PayloadEntryKind.File ? nextDataBlock : 0 };
                    nextDataBlock = checked(nextDataBlock + entry.DataBlockCount);
                }

                CryptographicOperations.ZeroMemory(indexBytes);
                indexBytes = BuildIndex(manifest.IsDirectory, manifest.RootName, entries, signingIdentity);
                if (GetBlockCount(indexBytes.Length) != indexBlockCount)
                {
                    throw new NingRanException("加密文件目录的分段计算不正确。");
                }
            }

            var paddingBlocks = manifest.PaddingLength == 0 ? 0 : GetBlockCount(manifest.PaddingLength);
            var totalBlockCount = checked(nextDataBlock + paddingBlocks);
            prefix = BuildPrefix(indexBlockCount, indexBytes.Length, totalBlockCount);
            await output.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
            await WriteBlocksAsync(
                output,
                indexBytes,
                indexBlockCount,
                startBlock: 0,
                header,
                dataKey,
                prefix,
                "NRINDEX-V1",
                cancellationToken).ConfigureAwait(false);

            long completed = 0;
            for (var entryIndex = 0; entryIndex < manifest.Entries.Count; entryIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var sourceEntry = manifest.Entries[entryIndex];
                var indexedEntry = entries[entryIndex];
                if (sourceEntry.Kind != PayloadEntryKind.File)
                {
                    continue;
                }

                await WriteSourceFileAsync(
                    output,
                    sourceEntry,
                    indexedEntry,
                    header,
                    dataKey,
                    prefix,
                    (bytes, message) =>
                    {
                        completed = checked(completed + bytes);
                        reportProgress?.Invoke(completed, message);
                    },
                    cancellationToken).ConfigureAwait(false);
            }

            if (paddingBlocks > 0)
            {
                await WriteRandomBlocksAsync(
                    output,
                    nextDataBlock,
                    paddingBlocks,
                    header,
                    dataKey,
                    prefix,
                    cancellationToken).ConfigureAwait(false);
            }

            var parsed = ParseIndex(indexBytes);
            parsed.SetLayout(checked((int)indexBlockCount), indexBytes.Length, totalBlockCount);
            return parsed;
        }
        finally
        {
            if (preliminaryIndex is not null) CryptographicOperations.ZeroMemory(preliminaryIndex);
            if (indexBytes is not null) CryptographicOperations.ZeroMemory(indexBytes);
            if (prefix is not null) CryptographicOperations.ZeroMemory(prefix);
        }
    }

    public static async Task<IndexedPayload> OpenAsync(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var prefix = new byte[PrefixSize];
        byte[]? indexBytes = null;
        try
        {
            input.Position = header.Bytes.Length;
            await BinaryFormat.ReadExactlyAsync(input, prefix, cancellationToken).ConfigureAwait(false);
            var (indexBlockCount, indexLength, totalBlockCount) = ReadPrefix(prefix);
            ValidateLength(input.Length, header.Bytes.Length, totalBlockCount);
            indexBytes = await ReadBlocksAsync(
                input.SafeFileHandle,
                checked(header.Bytes.Length + PrefixSize),
                indexBlockCount,
                indexLength,
                startBlock: 0,
                header,
                dataKey,
                prefix,
                "NRINDEX-V1",
                cancellationToken).ConfigureAwait(false);
            var payload = ParseIndex(indexBytes);
            payload.SetLayout(indexBlockCount, indexLength, totalBlockCount);
            return payload;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
            if (indexBytes is not null) CryptographicOperations.ZeroMemory(indexBytes);
        }
    }

    public static async Task ValidateAllAsync(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayload payload,
        Action<long, string>? reportProgress,
        CancellationToken cancellationToken)
    {
        var prefix = BuildPrefix(payload.IndexBlockCount, payload.IndexLength, payload.TotalBlockCount);
        var ciphertext = new byte[BlockSize];
        var plaintext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            var payloadOffset = checked(input.Position = header.Bytes.Length + PrefixSize);
            for (long block = 0; block < payload.TotalBlockCount; block++)
            {
                await ReadAndDecryptBlockAsync(
                    input.SafeFileHandle,
                    payloadOffset,
                    header,
                    cipher,
                    checked((ulong)block),
                    ciphertext,
                    tag,
                    plaintext,
                    prefix,
                    block < payload.IndexBlockCount ? "NRINDEX-V1" : "NRDATA-V1",
                    cancellationToken).ConfigureAwait(false);
                reportProgress?.Invoke(block + 1, "正在验证加密内容，不创建文件…");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static async Task ReadEntryBlockAsync(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayload payload,
        long absoluteBlockIndex,
        byte[] ciphertext,
        byte[] tag,
        byte[] plaintext,
        ChaCha20Poly1305 cipher,
        CancellationToken cancellationToken)
    {
        if (absoluteBlockIndex < payload.IndexBlockCount || absoluteBlockIndex >= payload.TotalBlockCount)
        {
            throw new NingRanException("请求的媒体分段不在加密文件范围内。");
        }

        var prefix = BuildPrefix(payload.IndexBlockCount, payload.IndexLength, payload.TotalBlockCount);
        try
        {
            await ReadAndDecryptBlockAsync(
                input.SafeFileHandle,
                checked(header.Bytes.Length + PrefixSize),
                header,
                cipher,
                checked((ulong)absoluteBlockIndex),
                ciphertext,
                tag,
                plaintext,
                prefix,
                "NRDATA-V1",
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
        }
    }

    public static async Task CopyEntryToStreamAsync(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayload payload,
        IndexedPayloadEntry entry,
        Stream output,
        CancellationToken cancellationToken)
    {
        if (entry.Kind != PayloadEntryKind.File)
        {
            throw new NingRanException("只能导出加密文件中的普通文件。");
        }

        var ciphertext = new byte[BlockSize];
        var plaintext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            long completed = 0;
            for (long blockOffset = 0; blockOffset < entry.DataBlockCount; blockOffset++)
            {
                await ReadEntryBlockAsync(
                    input,
                    header,
                    dataKey,
                    payload,
                    checked(entry.DataBlockStart + blockOffset),
                    ciphertext,
                    tag,
                    plaintext,
                    cipher,
                    cancellationToken).ConfigureAwait(false);
                var count = (int)Math.Min(BlockSize, entry.Length - completed);
                await output.WriteAsync(plaintext.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                completed = checked(completed + count);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task WriteSourceFileAsync(
        Stream output,
        PayloadEntry sourceEntry,
        IndexedPayloadEntry indexedEntry,
        ArchiveHeader header,
        byte[] dataKey,
        byte[] prefix,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        await using var source = sourceEntry.ContentFactory is not null
            ? await sourceEntry.ContentFactory(cancellationToken).ConfigureAwait(false)
            : new FileStream(sourceEntry.SourceHandle ?? throw new NingRanException("缺少原始文件读取句柄。"), FileAccess.Read, BlockSize, isAsync: true);
        if (source.Length != sourceEntry.Length)
        {
            throw new NingRanException($"文件在准备后发生了变化：{sourceEntry.FullPath}");
        }

        var plaintext = new byte[BlockSize];
        var ciphertext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            long completed = 0;
            for (long blockOffset = 0; blockOffset < indexedEntry.DataBlockCount; blockOffset++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var wanted = (int)Math.Min(BlockSize, sourceEntry.Length - completed);
                await BinaryFormat.ReadExactlyAsync(source, plaintext.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
                if (wanted < BlockSize) plaintext.AsSpan(wanted).Clear();
                await EncryptAndWriteBlockAsync(
                    output,
                    header,
                    cipher,
                    checked((ulong)(indexedEntry.DataBlockStart + blockOffset)),
                    plaintext,
                    ciphertext,
                    tag,
                    prefix,
                    "NRDATA-V1",
                    cancellationToken).ConfigureAwait(false);
                completed = checked(completed + wanted);
                progress?.Invoke(wanted, $"正在加密：{sourceEntry.RelativePath}");
            }

            if (source.Length != sourceEntry.Length ||
                (sourceEntry.ContentFactory is null && File.GetLastWriteTimeUtc(sourceEntry.SourceHandle!).Ticks != sourceEntry.LastWriteUtcTicks))
            {
                throw new NingRanException($"文件在加密过程中发生了变化：{sourceEntry.FullPath}");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task WriteBlocksAsync(
        Stream output,
        byte[] content,
        long blockCount,
        long startBlock,
        ArchiveHeader header,
        byte[] dataKey,
        byte[] prefix,
        string purpose,
        CancellationToken cancellationToken)
    {
        var plaintext = new byte[BlockSize];
        var ciphertext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            for (long block = 0; block < blockCount; block++)
            {
                var contentOffset = checked((int)(block * BlockSize));
                var count = Math.Min(BlockSize, content.Length - contentOffset);
                if (count > 0) content.AsSpan(contentOffset, count).CopyTo(plaintext);
                if (count < BlockSize) plaintext.AsSpan(count).Clear();
                await EncryptAndWriteBlockAsync(
                    output,
                    header,
                    cipher,
                    checked((ulong)(startBlock + block)),
                    plaintext,
                    ciphertext,
                    tag,
                    prefix,
                    purpose,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task WriteRandomBlocksAsync(
        Stream output,
        long startBlock,
        long blockCount,
        ArchiveHeader header,
        byte[] dataKey,
        byte[] prefix,
        CancellationToken cancellationToken)
    {
        var plaintext = new byte[BlockSize];
        var ciphertext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            for (long block = 0; block < blockCount; block++)
            {
                RandomNumberGenerator.Fill(plaintext);
                await EncryptAndWriteBlockAsync(
                    output,
                    header,
                    cipher,
                    checked((ulong)(startBlock + block)),
                    plaintext,
                    ciphertext,
                    tag,
                    prefix,
                    "NRDATA-V1",
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task EncryptAndWriteBlockAsync(
        Stream output,
        ArchiveHeader header,
        ChaCha20Poly1305 cipher,
        ulong blockIndex,
        byte[] plaintext,
        byte[] ciphertext,
        byte[] tag,
        byte[] prefix,
        string purpose,
        CancellationToken cancellationToken)
    {
        var nonce = CreateNonce(header.PayloadNoncePrefix, blockIndex);
        var aad = CreateAssociatedData(header.HeaderHash, prefix, blockIndex, purpose);
        try
        {
            cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task<byte[]> ReadBlocksAsync(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        long payloadOffset,
        long blockCount,
        int contentLength,
        long startBlock,
        ArchiveHeader header,
        byte[] dataKey,
        byte[] prefix,
        string purpose,
        CancellationToken cancellationToken)
    {
        var result = new byte[contentLength];
        var ciphertext = new byte[BlockSize];
        var plaintext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            for (long block = 0; block < blockCount; block++)
            {
                await ReadAndDecryptBlockAsync(
                    handle,
                    payloadOffset,
                    header,
                    cipher,
                    checked((ulong)(startBlock + block)),
                    ciphertext,
                    tag,
                    plaintext,
                    prefix,
                    purpose,
                    cancellationToken).ConfigureAwait(false);
                var offset = checked((int)(block * BlockSize));
                var count = Math.Min(BlockSize, contentLength - offset);
                plaintext.AsSpan(0, count).CopyTo(result.AsSpan(offset));
            }

            return result;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(result);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task ReadAndDecryptBlockAsync(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        long payloadOffset,
        ArchiveHeader header,
        ChaCha20Poly1305 cipher,
        ulong blockIndex,
        byte[] ciphertext,
        byte[] tag,
        byte[] plaintext,
        byte[] prefix,
        string purpose,
        CancellationToken cancellationToken)
    {
        var recordOffset = checked(payloadOffset + checked((long)blockIndex * RecordSize));
        await ReadExactlyAtAsync(handle, ciphertext, recordOffset, cancellationToken).ConfigureAwait(false);
        await ReadExactlyAtAsync(handle, tag, checked(recordOffset + BlockSize), cancellationToken).ConfigureAwait(false);
        var nonce = CreateNonce(header.PayloadNoncePrefix, blockIndex);
        var aad = CreateAssociatedData(header.HeaderHash, prefix, blockIndex, purpose);
        try
        {
            cipher.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        catch (CryptographicException exception)
        {
            throw new NingRanException("加密内容未通过完整性检查，文件可能已被修改或损坏。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static async Task ReadExactlyAtAsync(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        Memory<byte> buffer,
        long offset,
        CancellationToken cancellationToken)
    {
        var completed = 0;
        while (completed < buffer.Length)
        {
            var read = await RandomAccess.ReadAsync(handle, buffer[completed..], checked(offset + completed), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0) throw new NingRanException("加密文件不完整。");
            completed += read;
        }
    }

    private static byte[] BuildIndex(
        bool isDirectory,
        string rootName,
        IReadOnlyList<IndexedPayloadEntry> entries,
        SigningIdentity signingIdentity)
    {
        using var content = new MemoryStream();
        using (var writer = new BinaryWriter(content, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(IndexMagic);
            writer.Write(isDirectory);
            WriteString(writer, rootName);
            writer.Write(entries.Count);
            foreach (var entry in entries)
            {
                writer.Write((byte)entry.Kind);
                WriteString(writer, entry.RelativePath);
                writer.Write(entry.Length);
                writer.Write(entry.LastWriteUtcTicks);
                writer.Write(entry.DataBlockStart);
                writer.Write(entry.DataBlockCount);
                writer.Write(entry.MediaKind is null ? (byte)255 : (byte)entry.MediaKind.Value);
            }
        }

        var authenticated = content.ToArray();
        byte[]? hash = null;
        byte[]? signature = null;
        try
        {
            hash = SHA256.HashData(authenticated);
            signature = signingIdentity.Key.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (signature.Length != SenderSignatureSize)
            {
                throw new NingRanException("发送者身份证明生成失败。");
            }

            using var result = new MemoryStream();
            result.Write(authenticated);
            using (var writer = new BinaryWriter(result, Encoding.UTF8, leaveOpen: true))
            {
                WriteString(writer, signingIdentity.Fingerprint);
                writer.Write(signature);
            }

            return result.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authenticated);
            if (hash is not null) CryptographicOperations.ZeroMemory(hash);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static IndexedPayload ParseIndex(ReadOnlySpan<byte> bytes)
    {
        var reader = new IndexReader(bytes);
        if (!reader.ReadBytes(IndexMagic.Length).SequenceEqual(IndexMagic))
        {
            throw new NingRanException("加密内容的内部目录格式不正确或已损坏。");
        }

        var isDirectory = reader.ReadBoolean();
        var rootName = PathSafety.ValidateNameSegment(reader.ReadString(32 * 1024));
        var entryCount = reader.ReadInt32();
        if (entryCount is < 1 or > MaximumEntries)
        {
            throw new NingRanException("加密文件包含过多条目，已停止读取。");
        }

        var entries = new List<IndexedPayloadEntry>(entryCount);
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalNameBytes = Encoding.UTF8.GetByteCount(rootName);
        long lastBlock = 0;
        var rootSeen = false;
        for (var index = 0; index < entryCount; index++)
        {
            var kind = reader.ReadByte() switch
            {
                (byte)PayloadEntryKind.Directory => PayloadEntryKind.Directory,
                (byte)PayloadEntryKind.File => PayloadEntryKind.File,
                _ => throw new NingRanException("加密内容包含未知条目。"),
            };
            var relativePath = PathSafety.NormalizeRelativePath(reader.ReadString(32 * 1024));
            totalNameBytes = checked(totalNameBytes + Encoding.UTF8.GetByteCount(relativePath));
            if (totalNameBytes > MaximumTotalNameBytes || !seenPaths.Add(relativePath))
            {
                throw new NingRanException("加密文件的文件名信息不正确或过大。");
            }

            var length = reader.ReadInt64();
            var ticks = reader.ReadInt64();
            var blockStart = reader.ReadInt64();
            var blockCount = reader.ReadInt64();
            var mediaValue = reader.ReadByte();
            SecureMediaKind? mediaKind = mediaValue == 255 ? null : mediaValue switch
            {
                (byte)SecureMediaKind.Text => SecureMediaKind.Text,
                (byte)SecureMediaKind.Image => SecureMediaKind.Image,
                (byte)SecureMediaKind.Audio => SecureMediaKind.Audio,
                (byte)SecureMediaKind.Video => SecureMediaKind.Video,
                _ => throw new NingRanException("加密内容包含不支持的媒体类型。"),
            };
            if (length < 0 || (kind == PayloadEntryKind.Directory && (length != 0 || blockStart != 0 || blockCount != 0)) ||
                (kind == PayloadEntryKind.File && (blockCount != GetBlockCount(length) || blockStart < 1)))
            {
                throw new NingRanException("加密内容的文件信息不正确。");
            }

            var isRoot = string.Equals(relativePath, rootName, StringComparison.OrdinalIgnoreCase);
            if (isRoot)
            {
                if (rootSeen || (isDirectory && kind != PayloadEntryKind.Directory) || (!isDirectory && kind != PayloadEntryKind.File))
                {
                    throw new NingRanException("加密内容的根条目不正确。");
                }

                rootSeen = true;
            }

            if (kind == PayloadEntryKind.File)
            {
                if (blockStart < lastBlock) throw new NingRanException("加密内容的分段顺序不正确。");
                lastBlock = checked(blockStart + blockCount);
            }

            entries.Add(new IndexedPayloadEntry(kind, relativePath, length, ticks, blockStart, blockCount, mediaKind));
        }

        if (!rootSeen)
        {
            throw new NingRanException("加密内容缺少根条目。");
        }

        var authenticatedLength = reader.Position;
        var authenticatedHash = SHA256.HashData(bytes[..authenticatedLength]);
        try
        {
            var fingerprint = reader.ReadString(128);
            var signature = reader.ReadBytes(SenderSignatureSize).ToArray();
            if (!IsFingerprint(fingerprint) || reader.Remaining != 0)
            {
                CryptographicOperations.ZeroMemory(signature);
                throw new NingRanException("加密内容的发送者身份证明不正确。");
            }

            // 前缀中的数量会由 OpenAsync 填入；这里先用占位值，随后覆写。
            return new IndexedPayload(isDirectory, rootName, entries, fingerprint, signature, authenticatedHash);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(authenticatedHash);
            throw;
        }
    }

    private static byte[] BuildPrefix(long indexBlockCount, int indexLength, long totalBlockCount)
    {
        var prefix = new byte[PrefixSize];
        PrefixMagic.CopyTo(prefix);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(8), checked((int)indexBlockCount));
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(12), indexLength);
        BinaryPrimitives.WriteInt64LittleEndian(prefix.AsSpan(16), totalBlockCount);
        // 24..31 保留为零，避免未来格式把随机数据误当作有效字段。
        return prefix;
    }

    private static (int IndexBlockCount, int IndexLength, long TotalBlockCount) ReadPrefix(byte[] prefix)
    {
        if (!prefix.AsSpan(0, PrefixMagic.Length).SequenceEqual(PrefixMagic) || prefix.AsSpan(24, 8).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new NingRanException("此文件不是支持直接浏览的新凝然加密格式。");
        }

        var indexBlockCount = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(8));
        var indexLength = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(12));
        var totalBlockCount = BinaryPrimitives.ReadInt64LittleEndian(prefix.AsSpan(16));
        if (indexBlockCount is < 1 or > MaximumIndexBlocks || indexLength is < 1 or > MaximumIndexBytes ||
            GetBlockCount(indexLength) != indexBlockCount || totalBlockCount < indexBlockCount)
        {
            throw new NingRanException("加密文件的目录分段信息不正确。");
        }

        return (indexBlockCount, indexLength, totalBlockCount);
    }

    private static void ValidateLength(long fileLength, int headerLength, long totalBlockCount)
    {
        var expected = checked(headerLength + PrefixSize + checked(totalBlockCount * RecordSize));
        if (fileLength != expected)
        {
            throw new NingRanException("加密文件的长度不正确或文件已损坏。");
        }
    }

    private static long GetBlockCount(long length) => length == 0 ? 0 : checked(((length - 1) / BlockSize) + 1);

    private static byte[] CreateNonce(ReadOnlySpan<byte> prefix, ulong index)
    {
        var nonce = new byte[CryptoSizes.Nonce];
        prefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(4), index);
        return nonce;
    }

    private static byte[] CreateAssociatedData(ReadOnlySpan<byte> headerHash, byte[] prefix, ulong index, string purpose)
    {
        var purposeBytes = Encoding.ASCII.GetBytes(purpose);
        var result = new byte[checked(headerHash.Length + prefix.Length + sizeof(ulong) + purposeBytes.Length)];
        headerHash.CopyTo(result);
        prefix.CopyTo(result.AsSpan(headerHash.Length));
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(headerHash.Length + prefix.Length), index);
        purposeBytes.CopyTo(result.AsSpan(headerHash.Length + prefix.Length + sizeof(ulong)));
        CryptographicOperations.ZeroMemory(purposeBytes);
        return result;
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool IsFingerprint(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    internal sealed class IndexedPayload : IDisposable
    {
        public IndexedPayload(
            bool isDirectory,
            string rootName,
            IReadOnlyList<IndexedPayloadEntry> entries,
            string signerFingerprint,
            byte[] signature,
            byte[] authenticatedHash)
        {
            IsDirectory = isDirectory;
            RootName = rootName;
            Entries = entries;
            SignerFingerprint = signerFingerprint;
            Signature = signature;
            AuthenticatedHash = authenticatedHash;
        }

        public bool IsDirectory { get; }
        public string RootName { get; }
        public IReadOnlyList<IndexedPayloadEntry> Entries { get; }
        public string SignerFingerprint { get; }
        public byte[] Signature { get; }
        public byte[] AuthenticatedHash { get; }
        public int IndexBlockCount { get; private set; }
        public int IndexLength { get; private set; }
        public long TotalBlockCount { get; private set; }
        public bool HasSenderSignature => true;

        public void SetLayout(int indexBlockCount, int indexLength, long totalBlockCount)
        {
            IndexBlockCount = indexBlockCount;
            IndexLength = indexLength;
            TotalBlockCount = totalBlockCount;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Signature);
            CryptographicOperations.ZeroMemory(AuthenticatedHash);
        }
    }

    internal sealed record IndexedPayloadEntry(
        PayloadEntryKind Kind,
        string RelativePath,
        long Length,
        long LastWriteUtcTicks,
        long DataBlockStart,
        long DataBlockCount,
        SecureMediaKind? MediaKind);

    private ref struct IndexReader
    {
        private readonly ReadOnlySpan<byte> _bytes;
        public IndexReader(ReadOnlySpan<byte> bytes) => _bytes = bytes;
        public int Position { get; private set; }
        public int Remaining => _bytes.Length - Position;
        public byte ReadByte()
        {
            if (Remaining < 1) throw new NingRanException("加密文件的目录信息不完整。");
            return _bytes[Position++];
        }

        public bool ReadBoolean()
        {
            var value = ReadByte();
            return value switch
            {
                0 => false,
                1 => true,
                _ => throw new NingRanException("加密文件的目录标记不正确。"),
            };
        }

        public int ReadInt32()
        {
            if (Remaining < sizeof(int)) throw new NingRanException("加密文件的目录信息不完整。");
            var value = BinaryPrimitives.ReadInt32LittleEndian(_bytes[Position..]);
            Position += sizeof(int);
            return value;
        }

        public long ReadInt64()
        {
            if (Remaining < sizeof(long)) throw new NingRanException("加密文件的目录信息不完整。");
            var value = BinaryPrimitives.ReadInt64LittleEndian(_bytes[Position..]);
            Position += sizeof(long);
            return value;
        }

        public ReadOnlySpan<byte> ReadBytes(int length)
        {
            if (length < 0 || Remaining < length) throw new NingRanException("加密文件的目录信息不完整。");
            var value = _bytes.Slice(Position, length);
            Position += length;
            return value;
        }

        public string ReadString(int maximumBytes)
        {
            var length = ReadInt32();
            if (length < 0 || length > maximumBytes) throw new NingRanException("加密文件的名称信息过长。");
            try
            {
                return new UTF8Encoding(false, true).GetString(ReadBytes(length));
            }
            catch (DecoderFallbackException exception)
            {
                throw new NingRanException("加密文件的名称编码不正确。", exception);
            }
        }
    }
}
