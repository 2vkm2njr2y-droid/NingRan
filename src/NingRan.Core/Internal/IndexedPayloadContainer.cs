using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ZstdSharp;

namespace NingRan.Core.Internal;

/// <summary>按 4MB 原始分段进行 Zstandard 无损压缩后独立认证加密。</summary>
internal static class IndexedPayloadContainer
{
    internal const int BlockSize = 4 * 1024 * 1024;
    private const int TagSize = CryptoSizes.Tag;
    private const long FixedRecordSize = BlockSize + TagSize;
    private const int PrefixSize = 32;
    private const int MaximumIndexBytes = 16 * 1024 * 1024;
    private const int MaximumIndexBlocks = MaximumIndexBytes / BlockSize;
    private const int MaximumEntries = 20_000;
    private const long MaximumTotalNameBytes = 8L * 1024 * 1024;
    private const int SenderSignatureSize = 64;
    private static ReadOnlySpan<byte> PrefixMagic => "NRIDX007"u8;
    private static ReadOnlySpan<byte> IndexMagic => "NRPAY007"u8;

    public static async Task<IndexedPayload> WriteAsync(
        Stream output, PayloadManifest manifest, ArchiveHeader header, byte[] dataKey,
        SigningIdentity signingIdentity, ArchiveCompressionLevel compression,
        Action<long, string>? reportProgress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(dataKey);
        ArgumentNullException.ThrowIfNull(signingIdentity);

        var entries = new List<IndexedPayloadEntry>(manifest.Entries.Count);
        long dataOffset = 0;
        foreach (var sourceEntry in manifest.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (sourceEntry.Kind != PayloadEntryKind.File)
            {
                entries.Add(new IndexedPayloadEntry(sourceEntry.Kind, sourceEntry.RelativePath, sourceEntry.Length,
                    sourceEntry.LastWriteUtcTicks, 0, 0, NrMediaFiles.TryGetKind(sourceEntry.RelativePath), []));
                continue;
            }

            var planned = await PlanSourceFileAsync(sourceEntry, compression, cancellationToken).ConfigureAwait(false);
            var blocks = new IndexedPayloadBlock[planned.Count];
            for (var index = 0; index < planned.Count; index++)
                blocks[index] = planned[index] with { DataOffset = checked(dataOffset + planned[index].DataOffset) };
            dataOffset = checked(dataOffset + planned.Sum(block => (long)block.StoredLength + TagSize));
            entries.Add(new IndexedPayloadEntry(sourceEntry.Kind, sourceEntry.RelativePath, sourceEntry.Length,
                sourceEntry.LastWriteUtcTicks, 0, blocks.Length, NrMediaFiles.TryGetKind(sourceEntry.RelativePath), blocks));
        }

        byte[]? preliminaryIndex = null;
        byte[]? indexBytes = null;
        byte[]? prefix = null;
        try
        {
            preliminaryIndex = BuildIndex(manifest.IsDirectory, manifest.RootName, entries, compression, signingIdentity);
            var indexBlockCount = GetBlockCount(preliminaryIndex.Length);
            if (indexBlockCount is < 1 or > MaximumIndexBlocks)
                throw new NingRanException("加密文件的目录信息过大，无法安全保存。");

            long nextRecord = indexBlockCount;
            for (var index = 0; index < entries.Count; index++)
            {
                var entry = entries[index];
                entries[index] = entry with { DataBlockStart = entry.Kind == PayloadEntryKind.File ? nextRecord : 0 };
                nextRecord = checked(nextRecord + entry.DataBlockCount);
            }

            indexBytes = BuildIndex(manifest.IsDirectory, manifest.RootName, entries, compression, signingIdentity);
            var finalIndexBlockCount = GetBlockCount(indexBytes.Length);
            if (finalIndexBlockCount != indexBlockCount)
            {
                indexBlockCount = finalIndexBlockCount;
                nextRecord = indexBlockCount;
                for (var index = 0; index < entries.Count; index++)
                {
                    var entry = entries[index];
                    entries[index] = entry with { DataBlockStart = entry.Kind == PayloadEntryKind.File ? nextRecord : 0 };
                    nextRecord = checked(nextRecord + entry.DataBlockCount);
                }
                CryptographicOperations.ZeroMemory(indexBytes);
                indexBytes = BuildIndex(manifest.IsDirectory, manifest.RootName, entries, compression, signingIdentity);
                if (GetBlockCount(indexBytes.Length) != indexBlockCount)
                    throw new NingRanException("加密文件目录的分段计算不正确。");
            }

            var paddingRecords = manifest.PaddingLength == 0 ? 0 : GetBlockCount(manifest.PaddingLength);
            var totalRecordCount = checked(nextRecord + paddingRecords);
            prefix = BuildPrefix(indexBlockCount, indexBytes.Length, totalRecordCount, paddingRecords);
            await output.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
            await WriteFixedBlocksAsync(output, indexBytes, indexBlockCount, 0, header, dataKey, prefix,
                "NRINDEX-V2", cancellationToken).ConfigureAwait(false);

            long completed = 0;
            for (var entryIndex = 0; entryIndex < manifest.Entries.Count; entryIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var sourceEntry = manifest.Entries[entryIndex];
                if (sourceEntry.Kind != PayloadEntryKind.File) continue;
                await WriteSourceFileAsync(output, sourceEntry, entries[entryIndex], compression, header, dataKey, prefix,
                    (bytes, message) => { completed = checked(completed + bytes); reportProgress?.Invoke(completed, message); },
                    cancellationToken).ConfigureAwait(false);
            }
            if (paddingRecords > 0)
                await WriteRandomBlocksAsync(output, nextRecord, paddingRecords, header, dataKey, prefix, cancellationToken)
                    .ConfigureAwait(false);

            var parsed = ParseIndex(indexBytes);
            parsed.SetLayout(checked((int)indexBlockCount), indexBytes.Length, totalRecordCount, paddingRecords);
            return parsed;
        }
        finally
        {
            if (preliminaryIndex is not null) CryptographicOperations.ZeroMemory(preliminaryIndex);
            if (indexBytes is not null) CryptographicOperations.ZeroMemory(indexBytes);
            if (prefix is not null) CryptographicOperations.ZeroMemory(prefix);
        }
    }

    public static async Task<IndexedPayload> OpenAsync(FileStream input, ArchiveHeader header, byte[] dataKey,
        CancellationToken cancellationToken)
    {
        var prefix = new byte[PrefixSize];
        byte[]? indexBytes = null;
        try
        {
            input.Position = header.Bytes.Length;
            await BinaryFormat.ReadExactlyAsync(input, prefix, cancellationToken).ConfigureAwait(false);
            var (indexBlockCount, indexLength, totalRecordCount, paddingRecords) = ReadPrefix(prefix);
            indexBytes = await ReadFixedBlocksAsync(input.SafeFileHandle, checked(header.Bytes.Length + PrefixSize),
                indexBlockCount, indexLength, header, dataKey, prefix, "NRINDEX-V2", cancellationToken).ConfigureAwait(false);
            var payload = ParseIndex(indexBytes);
            payload.SetLayout(indexBlockCount, indexLength, totalRecordCount, paddingRecords);
            ValidateFileLength(input.Length, header.Bytes.Length, payload);
            return payload;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
            if (indexBytes is not null) CryptographicOperations.ZeroMemory(indexBytes);
        }
    }

    public static async Task ValidateAllAsync(FileStream input, ArchiveHeader header, byte[] dataKey,
        IndexedPayload payload, Action<long, string>? reportProgress, CancellationToken cancellationToken)
    {
        var prefix = BuildPrefix(payload.IndexBlockCount, payload.IndexLength, payload.TotalBlockCount, payload.PaddingRecordCount);
        var ciphertext = new byte[BlockSize];
        var plaintext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            long completed = 0;
            for (long block = 0; block < payload.IndexBlockCount; block++)
            {
                await ReadAndDecryptFixedBlockAsync(input.SafeFileHandle, checked(header.Bytes.Length + PrefixSize), header,
                    cipher, checked((ulong)block), ciphertext, tag, plaintext, prefix, "NRINDEX-V2", cancellationToken)
                    .ConfigureAwait(false);
                reportProgress?.Invoke(++completed, "正在验证加密目录…");
            }
            foreach (var entry in payload.Entries)
            {
                if (entry.Kind != PayloadEntryKind.File) continue;
                for (var block = 0; block < entry.Blocks.Count; block++)
                {
                    await ReadEntryBlockAsync(input, header, dataKey, payload, entry, block, ciphertext, tag, plaintext,
                        cipher, cancellationToken).ConfigureAwait(false);
                    reportProgress?.Invoke(++completed, "正在验证加密内容，不创建文件…");
                }
            }
            for (long block = 0; block < payload.PaddingRecordCount; block++)
            {
                var absolute = checked(payload.TotalBlockCount - payload.PaddingRecordCount + block);
                await ReadAndDecryptFixedBlockAsync(input.SafeFileHandle, DataStart(header, payload), header, cipher,
                    checked((ulong)absolute), ciphertext, tag, plaintext, prefix, "NRDATA-V2", cancellationToken)
                    .ConfigureAwait(false);
                reportProgress?.Invoke(++completed, "正在验证隐藏大小填充…");
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

    public static async Task ReadEntryBlockAsync(FileStream input, ArchiveHeader header, byte[] dataKey,
        IndexedPayload payload, IndexedPayloadEntry entry, long blockOffset, byte[] ciphertext, byte[] tag,
        byte[] plaintext, ChaCha20Poly1305 cipher, CancellationToken cancellationToken)
    {
        if (entry.Kind != PayloadEntryKind.File || blockOffset < 0 || blockOffset >= entry.Blocks.Count)
            throw new NingRanException("请求的媒体分段不在加密文件范围内。");
        var block = entry.Blocks[(int)blockOffset];
        if (block.StoredLength > ciphertext.Length || block.PlainLength > plaintext.Length)
            throw new NingRanException("加密内容的分段长度超出安全上限。");

        var prefix = BuildPrefix(payload.IndexBlockCount, payload.IndexLength, payload.TotalBlockCount, payload.PaddingRecordCount);
        var stored = ciphertext.AsMemory(0, block.StoredLength);
        try
        {
            var recordOffset = checked(DataStart(header, payload) + block.DataOffset);
            await ReadExactlyAtAsync(input.SafeFileHandle, stored, recordOffset, cancellationToken).ConfigureAwait(false);
            await ReadExactlyAtAsync(input.SafeFileHandle, tag.AsMemory(0, TagSize),
                checked(recordOffset + block.StoredLength), cancellationToken).ConfigureAwait(false);
            DecryptRecord(cipher, header, entry, blockOffset, stored.Span, tag, plaintext, block, prefix);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(ciphertext.AsSpan(0, block.StoredLength));
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static async Task CopyEntryToStreamAsync(FileStream input, ArchiveHeader header, byte[] dataKey,
        IndexedPayload payload, IndexedPayloadEntry entry, Stream output, CancellationToken cancellationToken)
    {
        if (entry.Kind != PayloadEntryKind.File) throw new NingRanException("只能导出加密文件中的普通文件。");
        var ciphertext = new byte[BlockSize];
        var plaintext = new byte[BlockSize];
        var tag = new byte[TagSize];
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            long completed = 0;
            for (var block = 0; block < entry.Blocks.Count; block++)
            {
                await ReadEntryBlockAsync(input, header, dataKey, payload, entry, block, ciphertext, tag, plaintext,
                    cipher, cancellationToken).ConfigureAwait(false);
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

    private static async Task<IReadOnlyList<IndexedPayloadBlock>> PlanSourceFileAsync(PayloadEntry sourceEntry,
        ArchiveCompressionLevel compression, CancellationToken cancellationToken)
    {
        await using var source = await OpenSourceAsync(sourceEntry, cancellationToken).ConfigureAwait(false);
        if (source.Length != sourceEntry.Length) throw new NingRanException($"文件在准备后发生了变化：{sourceEntry.FullPath}");
        using var compressor = compression == ArchiveCompressionLevel.Store ? null : new Compressor(GetZstdLevel(compression));
        var plaintext = new byte[BlockSize];
        var blocks = new List<IndexedPayloadBlock>();
        long completed = 0;
        try
        {
            while (completed < sourceEntry.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var wanted = checked((int)Math.Min(BlockSize, sourceEntry.Length - completed));
                await BinaryFormat.ReadExactlyAsync(source, plaintext.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
                var compressed = compression == ArchiveCompressionLevel.Store ? null : compressor!.Wrap(plaintext.AsSpan(0, wanted)).ToArray();
                var useCompressed = compressed is not null && compressed.Length < wanted;
                var storedLength = useCompressed ? compressed!.Length : wanted;
                if (compressed is not null) CryptographicOperations.ZeroMemory(compressed);
                blocks.Add(new IndexedPayloadBlock(blocks.Sum(block => (long)block.StoredLength + TagSize),
                    storedLength, wanted, useCompressed));
                completed = checked(completed + wanted);
            }
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        if (source.Length != sourceEntry.Length ||
            (sourceEntry.ContentFactory is null && File.GetLastWriteTimeUtc(sourceEntry.SourceHandle!).Ticks != sourceEntry.LastWriteUtcTicks))
            throw new NingRanException($"文件在准备后发生了变化：{sourceEntry.FullPath}");
        return blocks;
    }

    private static async Task WriteSourceFileAsync(Stream output, PayloadEntry sourceEntry,
        IndexedPayloadEntry indexedEntry, ArchiveCompressionLevel compression, ArchiveHeader header, byte[] dataKey,
        byte[] prefix, Action<long, string>? progress, CancellationToken cancellationToken)
    {
        await using var source = await OpenSourceAsync(sourceEntry, cancellationToken).ConfigureAwait(false);
        if (source.Length != sourceEntry.Length) throw new NingRanException($"文件在准备后发生了变化：{sourceEntry.FullPath}");
        using var compressor = compression == ArchiveCompressionLevel.Store ? null : new Compressor(GetZstdLevel(compression));
        var plaintext = new byte[BlockSize];
        try
        {
            long completed = 0;
            for (var blockOffset = 0; blockOffset < indexedEntry.Blocks.Count; blockOffset++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var plan = indexedEntry.Blocks[blockOffset];
                var wanted = checked((int)Math.Min(BlockSize, sourceEntry.Length - completed));
                await BinaryFormat.ReadExactlyAsync(source, plaintext.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
                var compressed = compression == ArchiveCompressionLevel.Store ? null : compressor!.Wrap(plaintext.AsSpan(0, wanted)).ToArray();
                var useCompressed = compressed is not null && compressed.Length < wanted;
                var stored = useCompressed ? compressed! : plaintext.AsSpan(0, wanted).ToArray();
                if (useCompressed != plan.IsCompressed || stored.Length != plan.StoredLength || wanted != plan.PlainLength)
                {
                    if (compressed is not null) CryptographicOperations.ZeroMemory(compressed);
                    CryptographicOperations.ZeroMemory(stored);
                    throw new NingRanException($"文件在加密过程中发生了变化：{sourceEntry.FullPath}");
                }
                await EncryptRecordAsync(output, checked((ulong)(indexedEntry.DataBlockStart + blockOffset)), stored,
                    header, dataKey, prefix, "NRDATA-V2", cancellationToken).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(stored);
                if (compressed is not null) CryptographicOperations.ZeroMemory(compressed);
                completed = checked(completed + wanted);
                progress?.Invoke(wanted, $"正在加密：{sourceEntry.RelativePath}");
            }
            if (source.Length != sourceEntry.Length ||
                (sourceEntry.ContentFactory is null && File.GetLastWriteTimeUtc(sourceEntry.SourceHandle!).Ticks != sourceEntry.LastWriteUtcTicks))
                throw new NingRanException($"文件在加密过程中发生了变化：{sourceEntry.FullPath}");
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static async Task<Stream> OpenSourceAsync(PayloadEntry entry, CancellationToken cancellationToken)
    {
        if (entry.ContentFactory is not null)
        {
            return await entry.ContentFactory(cancellationToken).ConfigureAwait(false);
        }

        // 每次读取都打开独立的 Windows 文件对象，避免 FileStream.Dispose 关闭清单中的锁定句柄。
        var handle = WindowsFileSystemSafety.OpenInputFile(entry.FullPath);
        try
        {
            WindowsFileSystemSafety.VerifyIdentity(handle, entry.Identity);
            return new FileStream(handle, FileAccess.Read, BlockSize, isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static async Task WriteFixedBlocksAsync(Stream output, byte[] content, long blockCount, long startBlock,
        ArchiveHeader header, byte[] dataKey, byte[] prefix, string purpose, CancellationToken cancellationToken)
    {
        var plaintext = new byte[BlockSize];
        try
        {
            for (long block = 0; block < blockCount; block++)
            {
                var offset = checked((int)(block * BlockSize));
                var count = Math.Min(BlockSize, content.Length - offset);
                if (count > 0) content.AsSpan(offset, count).CopyTo(plaintext);
                if (count < BlockSize) plaintext.AsSpan(count).Clear();
                await EncryptRecordAsync(output, checked((ulong)(startBlock + block)), plaintext, header, dataKey, prefix,
                    purpose, cancellationToken).ConfigureAwait(false);
            }
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static async Task WriteRandomBlocksAsync(Stream output, long startBlock, long blockCount,
        ArchiveHeader header, byte[] dataKey, byte[] prefix, CancellationToken cancellationToken)
    {
        var plaintext = new byte[BlockSize];
        try
        {
            for (long block = 0; block < blockCount; block++)
            {
                RandomNumberGenerator.Fill(plaintext);
                await EncryptRecordAsync(output, checked((ulong)(startBlock + block)), plaintext, header, dataKey, prefix,
                    "NRDATA-V2", cancellationToken).ConfigureAwait(false);
            }
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static async Task EncryptRecordAsync(Stream output, ulong blockIndex, ReadOnlyMemory<byte> content,
        ArchiveHeader header, byte[] dataKey, byte[] prefix, string purpose, CancellationToken cancellationToken)
    {
        var ciphertext = new byte[content.Length];
        var tag = new byte[TagSize];
        var nonce = CreateNonce(header.PayloadNoncePrefix, blockIndex);
        var aad = CreateAssociatedData(header.HeaderHash, prefix, blockIndex, purpose);
        try
        {
            using var cipher = new ChaCha20Poly1305(dataKey);
            cipher.Encrypt(nonce, content.Span, ciphertext, tag, aad);
            await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static async Task<byte[]> ReadFixedBlocksAsync(Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        long payloadOffset, long blockCount, int contentLength, ArchiveHeader header, byte[] dataKey, byte[] prefix,
        string purpose, CancellationToken cancellationToken)
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
                await ReadAndDecryptFixedBlockAsync(handle, payloadOffset, header, cipher, checked((ulong)block), ciphertext,
                    tag, plaintext, prefix, purpose, cancellationToken).ConfigureAwait(false);
                var offset = checked((int)(block * BlockSize));
                var count = Math.Min(BlockSize, contentLength - offset);
                plaintext.AsSpan(0, count).CopyTo(result.AsSpan(offset));
            }
            return result;
        }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task ReadAndDecryptFixedBlockAsync(Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        long payloadOffset, ArchiveHeader header, ChaCha20Poly1305 cipher, ulong blockIndex, byte[] ciphertext, byte[] tag,
        byte[] plaintext, byte[] prefix, string purpose, CancellationToken cancellationToken)
    {
        var recordOffset = checked(payloadOffset + checked((long)blockIndex * FixedRecordSize));
        await ReadExactlyAtAsync(handle, ciphertext, recordOffset, cancellationToken).ConfigureAwait(false);
        await ReadExactlyAtAsync(handle, tag, checked(recordOffset + BlockSize), cancellationToken).ConfigureAwait(false);
        var nonce = CreateNonce(header.PayloadNoncePrefix, blockIndex);
        var aad = CreateAssociatedData(header.HeaderHash, prefix, blockIndex, purpose);
        try { cipher.Decrypt(nonce, ciphertext, tag, plaintext, aad); }
        catch (CryptographicException exception) { throw new NingRanException("加密内容未通过完整性检查，文件可能已被修改或损坏。", exception); }
        finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(aad); }
    }

    private static void DecryptRecord(ChaCha20Poly1305 cipher, ArchiveHeader header, IndexedPayloadEntry entry,
        long blockOffset, ReadOnlySpan<byte> stored, ReadOnlySpan<byte> tag, byte[] plaintext,
        IndexedPayloadBlock block, byte[] prefix)
    {
        var index = checked((ulong)(entry.DataBlockStart + blockOffset));
        var nonce = CreateNonce(header.PayloadNoncePrefix, index);
        var aad = CreateAssociatedData(header.HeaderHash, prefix, index, "NRDATA-V2");
        var decoded = new byte[block.StoredLength];
        try
        {
            cipher.Decrypt(nonce, stored, tag[..TagSize], decoded, aad);
            if (block.IsCompressed)
            {
                using var decompressor = new Decompressor();
                var result = decompressor.Unwrap(decoded, block.PlainLength);
                if (result.Length != block.PlainLength) throw new NingRanException("解压后的分段长度不正确。");
                result.CopyTo(plaintext.AsSpan(0, block.PlainLength));
            }
            else
            {
                if (block.StoredLength != block.PlainLength) throw new NingRanException("加密内容的原始分段长度不正确。");
                decoded.AsSpan().CopyTo(plaintext.AsSpan(0, block.PlainLength));
            }
            plaintext.AsSpan(block.PlainLength).Clear();
        }
        catch (CryptographicException exception) { throw new NingRanException("加密内容未通过完整性检查，文件可能已被修改或损坏。", exception); }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] BuildIndex(bool isDirectory, string rootName, IReadOnlyList<IndexedPayloadEntry> entries,
        ArchiveCompressionLevel compression, SigningIdentity signingIdentity)
    {
        using var content = new MemoryStream();
        using (var writer = new BinaryWriter(content, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(IndexMagic);
            writer.Write((byte)compression);
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
                foreach (var block in entry.Blocks)
                {
                    writer.Write(block.DataOffset);
                    writer.Write(block.StoredLength);
                    writer.Write(block.PlainLength);
                    writer.Write(block.IsCompressed);
                }
            }
        }
        var authenticated = content.ToArray();
        byte[]? hash = null;
        byte[]? signature = null;
        try
        {
            hash = SHA256.HashData(authenticated);
            signature = signingIdentity.Key.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (signature.Length != SenderSignatureSize) throw new NingRanException("发送者身份证明生成失败。");
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
            throw new NingRanException("加密内容的内部目录格式不正确或已损坏。");
        var compression = reader.ReadByte() switch
        {
            (byte)ArchiveCompressionLevel.Store => ArchiveCompressionLevel.Store,
            (byte)ArchiveCompressionLevel.Fastest => ArchiveCompressionLevel.Fastest,
            (byte)ArchiveCompressionLevel.Standard => ArchiveCompressionLevel.Standard,
            (byte)ArchiveCompressionLevel.Maximum => ArchiveCompressionLevel.Maximum,
            _ => throw new NingRanException("加密内容的压缩等级不正确。"),
        };
        var isDirectory = reader.ReadBoolean();
        var rootName = PathSafety.ValidateNameSegment(reader.ReadString(32 * 1024));
        var entryCount = reader.ReadInt32();
        if (entryCount is < 1 or > MaximumEntries) throw new NingRanException("加密文件包含过多条目，已停止读取。");
        var entries = new List<IndexedPayloadEntry>(entryCount);
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalNameBytes = Encoding.UTF8.GetByteCount(rootName);
        long lastRecord = 0;
        long lastDataOffset = 0;
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
                throw new NingRanException("加密文件的文件名信息不正确或过大。");
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
                (byte)SecureMediaKind.Pdf => SecureMediaKind.Pdf,
                _ => throw new NingRanException("加密内容包含不支持的媒体类型。"),
            };
            if (length < 0 || blockCount < 0 ||
                (kind == PayloadEntryKind.Directory && (length != 0 || blockStart != 0 || blockCount != 0)) ||
                (kind == PayloadEntryKind.File && (blockCount != GetBlockCount(length) || blockStart < 1)))
                throw new NingRanException("加密内容的文件信息不正确。");
            var blocks = new List<IndexedPayloadBlock>(checked((int)Math.Min(blockCount, int.MaxValue)));
            for (long block = 0; block < blockCount; block++)
            {
                var dataOffset = reader.ReadInt64();
                var storedLength = reader.ReadInt32();
                var plainLength = reader.ReadInt32();
                var isCompressed = reader.ReadBoolean();
                if (dataOffset < lastDataOffset || storedLength is <= 0 or > BlockSize || plainLength is <= 0 or > BlockSize ||
                    (isCompressed && storedLength >= plainLength) || (!isCompressed && storedLength != plainLength))
                    throw new NingRanException("加密内容的压缩分段信息不正确。");
                blocks.Add(new IndexedPayloadBlock(dataOffset, storedLength, plainLength, isCompressed));
                lastDataOffset = checked(dataOffset + storedLength + TagSize);
            }
            var isRoot = string.Equals(relativePath, rootName, StringComparison.OrdinalIgnoreCase);
            if (isRoot)
            {
                if (rootSeen || (isDirectory && kind != PayloadEntryKind.Directory) || (!isDirectory && kind != PayloadEntryKind.File))
                    throw new NingRanException("加密内容的根条目不正确。");
                rootSeen = true;
            }
            if (kind == PayloadEntryKind.File)
            {
                if (blockStart < lastRecord) throw new NingRanException("加密内容的分段顺序不正确。");
                lastRecord = checked(blockStart + blockCount);
            }
            entries.Add(new IndexedPayloadEntry(kind, relativePath, length, ticks, blockStart, blockCount, mediaKind, blocks));
        }
        if (!rootSeen) throw new NingRanException("加密内容缺少根条目。");
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
            return new IndexedPayload(isDirectory, rootName, entries, compression, fingerprint, signature, authenticatedHash);
        }
        catch { CryptographicOperations.ZeroMemory(authenticatedHash); throw; }
    }

    private static long DataStart(ArchiveHeader header, IndexedPayload payload) =>
        checked(header.Bytes.Length + PrefixSize + payload.IndexBlockCount * FixedRecordSize);

    private static void ValidateFileLength(long fileLength, int headerLength, IndexedPayload payload)
    {
        var dataLength = payload.Entries.SelectMany(entry => entry.Blocks)
            .Sum(block => (long)block.StoredLength + TagSize);
        var expected = checked(headerLength + PrefixSize + payload.IndexBlockCount * FixedRecordSize + dataLength +
            payload.PaddingRecordCount * FixedRecordSize);
        if (fileLength != expected) throw new NingRanException("加密文件的长度不正确或文件已损坏。");
    }

    private static byte[] BuildPrefix(long indexBlockCount, int indexLength, long totalRecordCount, long paddingRecords)
    {
        var prefix = new byte[PrefixSize];
        PrefixMagic.CopyTo(prefix);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(8), checked((int)indexBlockCount));
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(12), indexLength);
        BinaryPrimitives.WriteInt64LittleEndian(prefix.AsSpan(16), totalRecordCount);
        BinaryPrimitives.WriteInt64LittleEndian(prefix.AsSpan(24), paddingRecords);
        return prefix;
    }

    private static (int IndexBlockCount, int IndexLength, long TotalRecordCount, long PaddingRecords) ReadPrefix(byte[] prefix)
    {
        if (!prefix.AsSpan(0, PrefixMagic.Length).SequenceEqual(PrefixMagic))
            throw new NingRanException("此文件不是支持直接浏览的新凝然加密格式。");
        var indexBlockCount = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(8));
        var indexLength = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(12));
        var totalRecordCount = BinaryPrimitives.ReadInt64LittleEndian(prefix.AsSpan(16));
        var paddingRecords = BinaryPrimitives.ReadInt64LittleEndian(prefix.AsSpan(24));
        if (indexBlockCount is < 1 or > MaximumIndexBlocks || indexLength is < 1 or > MaximumIndexBytes ||
            GetBlockCount(indexLength) != indexBlockCount || totalRecordCount < indexBlockCount ||
            paddingRecords < 0 || paddingRecords > totalRecordCount - indexBlockCount)
            throw new NingRanException("加密文件的目录分段信息不正确。");
        return (indexBlockCount, indexLength, totalRecordCount, paddingRecords);
    }

    private static int GetZstdLevel(ArchiveCompressionLevel compression) => compression switch
    {
        ArchiveCompressionLevel.Fastest => 1,
        ArchiveCompressionLevel.Standard => 5,
        ArchiveCompressionLevel.Maximum => 15,
        _ => 1,
    };

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

    private static async Task ReadExactlyAtAsync(Microsoft.Win32.SafeHandles.SafeFileHandle handle, Memory<byte> buffer,
        long offset, CancellationToken cancellationToken)
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

    private static void WriteString(BinaryWriter writer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try { writer.Write(bytes.Length); writer.Write(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static bool IsFingerprint(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    internal sealed class IndexedPayload : IDisposable
    {
        public IndexedPayload(bool isDirectory, string rootName, IReadOnlyList<IndexedPayloadEntry> entries,
            ArchiveCompressionLevel compression, string signerFingerprint, byte[] signature, byte[] authenticatedHash)
        {
            IsDirectory = isDirectory; RootName = rootName; Entries = entries; Compression = compression;
            SignerFingerprint = signerFingerprint; Signature = signature; AuthenticatedHash = authenticatedHash;
        }
        public bool IsDirectory { get; }
        public string RootName { get; }
        public IReadOnlyList<IndexedPayloadEntry> Entries { get; }
        public ArchiveCompressionLevel Compression { get; }
        public string SignerFingerprint { get; }
        public byte[] Signature { get; }
        public byte[] AuthenticatedHash { get; }
        public int IndexBlockCount { get; private set; }
        public int IndexLength { get; private set; }
        public long TotalBlockCount { get; private set; }
        public long PaddingRecordCount { get; private set; }
        public bool HasSenderSignature => true;
        public void SetLayout(int indexBlockCount, int indexLength, long totalBlockCount, long paddingRecordCount)
        {
            IndexBlockCount = indexBlockCount; IndexLength = indexLength; TotalBlockCount = totalBlockCount;
            PaddingRecordCount = paddingRecordCount;
        }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Signature);
            CryptographicOperations.ZeroMemory(AuthenticatedHash);
        }
    }

    internal sealed record IndexedPayloadEntry(PayloadEntryKind Kind, string RelativePath, long Length,
        long LastWriteUtcTicks, long DataBlockStart, long DataBlockCount, SecureMediaKind? MediaKind,
        IReadOnlyList<IndexedPayloadBlock> Blocks);

    internal sealed record IndexedPayloadBlock(long DataOffset, int StoredLength, int PlainLength, bool IsCompressed);

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
        public bool ReadBoolean() => ReadByte() switch
        {
            0 => false, 1 => true, _ => throw new NingRanException("加密文件的目录标记不正确。"),
        };
        public int ReadInt32()
        {
            if (Remaining < sizeof(int)) throw new NingRanException("加密文件的目录信息不完整。");
            var value = BinaryPrimitives.ReadInt32LittleEndian(_bytes[Position..]); Position += sizeof(int); return value;
        }
        public long ReadInt64()
        {
            if (Remaining < sizeof(long)) throw new NingRanException("加密文件的目录信息不完整。");
            var value = BinaryPrimitives.ReadInt64LittleEndian(_bytes[Position..]); Position += sizeof(long); return value;
        }
        public ReadOnlySpan<byte> ReadBytes(int length)
        {
            if (length < 0 || Remaining < length) throw new NingRanException("加密文件的目录信息不完整。");
            var value = _bytes.Slice(Position, length); Position += length; return value;
        }
        public string ReadString(int maximumBytes)
        {
            var length = ReadInt32();
            if (length < 0 || length > maximumBytes) throw new NingRanException("加密文件的名称信息过长。");
            try { return new UTF8Encoding(false, true).GetString(ReadBytes(length)); }
            catch (DecoderFallbackException exception) { throw new NingRanException("加密文件的名称编码不正确。", exception); }
        }
    }
}
