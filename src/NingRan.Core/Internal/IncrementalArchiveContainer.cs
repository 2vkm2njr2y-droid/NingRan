using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NingRan.Core.Internal;

/// <summary>
/// .nrenc 的增量修改层。旧内容仍然保留，新增内容和最新目录作为一个已提交的尾部段追加。
/// </summary>
internal static class IncrementalArchiveContainer
{
    private static ReadOnlySpan<byte> SegmentMagic => "NRUPD001"u8;
    // A staged segment is copied with this marker first. The committed marker
    // is written only after every byte of the segment has been flushed. If the
    // process stops in between, the original catalog remains authoritative.
    private static ReadOnlySpan<byte> ProvisionalSegmentMagic => "NRUPD000"u8;
    private static ReadOnlySpan<byte> FooterMagic => "NRUPDF01"u8;
    private const int Version = 1;
    internal const int SegmentHeaderSize = 116;
    internal const int FooterSize = 68;
    private const int TagSize = CryptoSizes.Tag;
    private const long FixedRecordSize = IndexedPayloadContainer.BlockSize + TagSize;
    private const int MaximumSegments = 1_000;

    internal sealed record OpenResult(
        IndexedPayloadContainer.IndexedPayload Payload,
        long BaseLength,
        long EffectiveLength,
        long NextBlockIndex,
        long Generation,
        long LastSegmentStart);

    internal sealed record StagedSegment(
        string Path,
        long SegmentStart,
        long SegmentLength,
        long Generation,
        long DataBlockStart,
        long DataBlockCount,
        long CatalogBlockStart,
        int CatalogBlockCount,
        int CatalogLength,
        byte[] CatalogHash);

    internal static byte[] GetCommittedSegmentMagic() => SegmentMagic.ToArray();

    internal sealed record PlannedAddition(
        PayloadEntry SourceEntry,
        IndexedPayloadContainer.IndexedPayloadEntry IndexedEntry);

    internal static long GetBaseLength(
        ArchiveHeader header,
        IndexedPayloadContainer.IndexedPayload payload)
    {
        var dataLength = payload.Entries.SelectMany(entry => entry.Blocks)
            .Sum(block => (long)block.StoredLength + TagSize);
        return checked(IndexedPayloadContainer.DataStart(header, payload) + dataLength +
            payload.PaddingRecordCount * FixedRecordSize);
    }

    internal static async Task<OpenResult> OpenAsync(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayloadContainer.IndexedPayload basePayload,
        long archiveLength,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(dataKey);
        ArgumentNullException.ThrowIfNull(basePayload);

        var baseLength = GetBaseLength(header, basePayload);
        if (archiveLength <= baseLength)
        {
            return new OpenResult(basePayload, baseLength, baseLength, basePayload.TotalBlockCount, 0,
                -1);
        }

        var baseDataStart = IndexedPayloadContainer.DataStart(header, basePayload);
        var baseDataEnd = baseLength - (basePayload.PaddingRecordCount * FixedRecordSize);
        var prefix = basePayload.CreatePrefix();
        var current = basePayload;
        var currentHash = basePayload.AuthenticatedHash.ToArray();
        var position = baseLength;
        var generation = 0L;
        var nextBlockIndex = basePayload.TotalBlockCount;
        var lastSegmentStart = -1L;
        var dataRanges = new List<(long Start, long End)>
        {
            (baseDataStart, baseDataEnd),
        };
        try
        {
            var segmentCount = 0;
            while (position < archiveLength)
            {
                if (archiveLength - position < sizeof(ulong))
                    break;

                var marker = await ReadSegmentMarkerAsync(input, position, cancellationToken)
                    .ConfigureAwait(false);
                if (marker.SequenceEqual(ProvisionalSegmentMagic))
                {
                    CryptographicOperations.ZeroMemory(marker);
                    break;
                }

                if (segmentCount >= MaximumSegments)
                {
                    CryptographicOperations.ZeroMemory(marker);
                    throw new NingRanException("加密文件包含过多增量修改记录，已停止读取。");
                }

                if (!marker.SequenceEqual(SegmentMagic))
                {
                    CryptographicOperations.ZeroMemory(marker);
                    throw new NingRanException("加密文件包含无法识别的增量修改记录。");
                }
                CryptographicOperations.ZeroMemory(marker);

                if (archiveLength - position < SegmentHeaderSize)
                    throw new NingRanException("增量修改记录不完整，文件可能已被截断。");

                ParsedSegment? parsed = null;
                try
                {
                    parsed = await ReadSegmentAsync(input, position, header, dataKey, prefix, cancellationToken)
                        .ConfigureAwait(false);
                    ValidateSegmentChain(parsed, position, baseLength, generation, lastSegmentStart, currentHash,
                        archiveLength, dataRanges);
                }
                catch
                {
                    parsed?.Payload.Dispose();
                    throw;
                }

                parsed.Payload.SetLayout(basePayload.IndexBlockCount, basePayload.IndexLength,
                    basePayload.TotalBlockCount, basePayload.PaddingRecordCount);
                parsed.Payload.SetPrefixOverride(prefix);
                var previous = current;
                current = parsed.Payload;
                if (!ReferenceEquals(previous, basePayload)) previous.Dispose();
                CryptographicOperations.ZeroMemory(currentHash);
                currentHash = parsed.CatalogHash.ToArray();
                generation = parsed.Info.Generation;
                nextBlockIndex = checked(parsed.Info.CatalogBlockStart + parsed.Info.CatalogBlockCount);
                lastSegmentStart = position;
                dataRanges.Add((
                    checked(position + SegmentHeaderSize),
                    parsed.CatalogPhysicalOffset));
                position = checked(position + parsed.Info.SegmentLength);
                segmentCount++;
            }

            if (!ReferenceEquals(current, basePayload))
            {
                basePayload.Dispose();
            }
            var result = new OpenResult(current, baseLength, position, nextBlockIndex, generation,
                lastSegmentStart);
            CryptographicOperations.ZeroMemory(currentHash);
            return result;
        }
        catch
        {
            if (!ReferenceEquals(current, basePayload)) current.Dispose();
            basePayload.Dispose();
            CryptographicOperations.ZeroMemory(currentHash);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prefix);
        }
    }

    internal static async Task<StagedSegment> WriteStagedAsync(
        string path,
        long segmentStart,
        long baseArchiveLength,
        long generation,
        long previousSegmentStart,
        byte[] previousCatalogHash,
        long dataBlockStart,
        ArchiveHeader header,
        byte[] dataKey,
        byte[] prefix,
        IReadOnlyList<PlannedAddition> additions,
        IReadOnlyList<IndexedPayloadContainer.IndexedPayloadEntry> entries,
        bool isDirectory,
        string rootName,
        ArchiveCompressionLevel compression,
        SigningIdentity signingIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (previousCatalogHash.Length != SHA256.HashSizeInBytes)
            throw new ArgumentException("上一次目录指纹长度不正确。", nameof(previousCatalogHash));
        if (additions.Count == 0 && entries.Count == 0)
            throw new NingRanException("增量修改没有产生任何内容。");

        var dataBlockCount = additions.Sum(item => item.IndexedEntry.DataBlockCount);
        var dataBytes = additions.SelectMany(item => item.IndexedEntry.Blocks)
            .Sum(block => (long)block.StoredLength + TagSize);
        var catalogBlockStart = checked(dataBlockStart + dataBlockCount);

        var catalogBlockCount = 1L;
        byte[]? indexBytes = null;
        byte[]? prefixBytes = null;
        byte[]? catalogHash = null;
        try
        {
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var segmentLength = checked(SegmentHeaderSize + dataBytes + catalogBlockCount * FixedRecordSize + FooterSize);
                var info = new IncrementalUpdateInfo(
                    generation,
                    segmentStart,
                    segmentLength,
                    baseArchiveLength,
                    previousSegmentStart,
                    previousCatalogHash.ToArray(),
                    dataBlockStart,
                    dataBlockCount,
                    catalogBlockStart,
                    checked((int)catalogBlockCount),
                    indexBytes?.Length ?? 1);
                var built = IndexedPayloadContainer.BuildIndex(isDirectory, rootName, entries, compression,
                    signingIdentity, null, info);
                if (indexBytes is not null) CryptographicOperations.ZeroMemory(indexBytes);
                indexBytes = built;
                var required = checked((indexBytes.Length + IndexedPayloadContainer.BlockSize - 1L) /
                    IndexedPayloadContainer.BlockSize);
                if (required == catalogBlockCount)
                {
                    var finalInfo = info with { CatalogLength = indexBytes.Length };
                    var finalBytes = IndexedPayloadContainer.BuildIndex(isDirectory, rootName, entries, compression,
                        signingIdentity, null, finalInfo);
                    CryptographicOperations.ZeroMemory(indexBytes);
                    indexBytes = finalBytes;
                    catalogBlockCount = required;
                    break;
                }

                catalogBlockCount = required;
                if (attempt == 2) throw new NingRanException("增量目录分段计算不正确。");
            }

            if (indexBytes is null) throw new NingRanException("未能生成增量目录。");
            var finalLength = checked(SegmentHeaderSize + dataBytes + catalogBlockCount * FixedRecordSize + FooterSize);
            var finalInfoForHash = new IncrementalUpdateInfo(
                generation,
                segmentStart,
                finalLength,
                baseArchiveLength,
                previousSegmentStart,
                previousCatalogHash.ToArray(),
                dataBlockStart,
                dataBlockCount,
                catalogBlockStart,
                checked((int)catalogBlockCount),
                indexBytes.Length);
            var finalIndex = IndexedPayloadContainer.BuildIndex(isDirectory, rootName, entries, compression,
                signingIdentity, null, finalInfoForHash);
            CryptographicOperations.ZeroMemory(indexBytes);
            indexBytes = finalIndex;
            if (checked((indexBytes.Length + IndexedPayloadContainer.BlockSize - 1L) /
                IndexedPayloadContainer.BlockSize) != catalogBlockCount)
            {
                throw new NingRanException("增量目录分段计算不正确。");
            }

            using (var parsed = IndexedPayloadContainer.ParseIndex(indexBytes))
            {
                catalogHash = parsed.AuthenticatedHash.ToArray();
            }

            var segmentHeader = BuildSegmentHeader(finalInfoForHash, committed: false);
            prefixBytes = prefix.ToArray();
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             1024 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(segmentHeader, cancellationToken).ConfigureAwait(false);
                foreach (var addition in additions)
                {
                    await IndexedPayloadContainer.WriteSourceFileAsync(
                        output,
                        addition.SourceEntry,
                        addition.IndexedEntry,
                        compression,
                        header,
                        dataKey,
                        prefixBytes,
                        (_, _) => { },
                        cancellationToken).ConfigureAwait(false);
                }

                await IndexedPayloadContainer.WriteFixedBlocksAsync(
                    output,
                    indexBytes,
                    catalogBlockCount,
                    catalogBlockStart,
                    header,
                    dataKey,
                    prefixBytes,
                    "NRINDEX-V2",
                    cancellationToken).ConfigureAwait(false);

                var footer = BuildFooter(finalInfoForHash, catalogHash);
                await output.WriteAsync(footer, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }

            return new StagedSegment(path, segmentStart, finalLength, generation, dataBlockStart,
                dataBlockCount, catalogBlockStart, checked((int)catalogBlockCount), indexBytes.Length,
                catalogHash.ToArray());
        }
        finally
        {
            if (indexBytes is not null) CryptographicOperations.ZeroMemory(indexBytes);
            if (prefixBytes is not null) CryptographicOperations.ZeroMemory(prefixBytes);
            if (catalogHash is not null) CryptographicOperations.ZeroMemory(catalogHash);
        }
    }

    internal static async Task ValidateStagedAsync(
        string path,
        StagedSegment staged,
        ArchiveHeader header,
        byte[] dataKey,
        byte[] prefix,
        long baseDataStart,
        SigningIdentity signingIdentity,
        IReadOnlyList<PlannedAddition> additions,
        CancellationToken cancellationToken)
    {
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess);
        if (input.Length != staged.SegmentLength)
            throw new NingRanException("增量临时文件大小不正确。");

        var parsed = await ReadSegmentAsync(input, 0, header, dataKey, prefix, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (parsed.Info.SegmentStart != staged.SegmentStart ||
                parsed.Info.SegmentLength != staged.SegmentLength ||
                parsed.Info.Generation != staged.Generation ||
                parsed.Info.DataBlockStart != staged.DataBlockStart ||
                parsed.Info.DataBlockCount != staged.DataBlockCount ||
                parsed.Info.CatalogBlockStart != staged.CatalogBlockStart ||
                parsed.Info.CatalogBlockCount != staged.CatalogBlockCount ||
                parsed.Info.CatalogLength != staged.CatalogLength ||
                !CryptographicOperations.FixedTimeEquals(parsed.CatalogHash, staged.CatalogHash))
            {
                throw new NingRanException("增量临时文件的提交信息不一致。");
            }

            using var publicIdentity = signingIdentity.CreatePublicIdentity();
            if (!string.Equals(parsed.Payload.SignerFingerprint, publicIdentity.Fingerprint, StringComparison.Ordinal) ||
                !publicIdentity.Key.VerifyHash(parsed.Payload.AuthenticatedHash, parsed.Payload.Signature,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new NingRanException("增量目录的发送者身份证明复验失败。");
            }

            var ciphertext = new byte[IndexedPayloadContainer.BlockSize];
            var plaintext = new byte[IndexedPayloadContainer.BlockSize];
            var tag = new byte[TagSize];
            try
            {
                foreach (var addition in additions)
                {
                    var entry = parsed.Payload.Entries.FirstOrDefault(candidate =>
                        string.Equals(candidate.RelativePath, addition.IndexedEntry.RelativePath,
                            StringComparison.OrdinalIgnoreCase));
                    if (entry is null || entry.Blocks.Count != addition.IndexedEntry.Blocks.Count)
                        throw new NingRanException("增量目录缺少刚追加的文件。");

                    for (var blockIndex = 0; blockIndex < entry.Blocks.Count; blockIndex++)
                    {
                        var block = entry.Blocks[blockIndex];
                        // DataOffset is relative to the original archive data start. Convert it to the staged file.
                        var recordOffset = checked(baseDataStart + block.DataOffset - staged.SegmentStart);
                        await IndexedPayloadContainer.ReadExactlyAtAsync(input.SafeFileHandle,
                            ciphertext.AsMemory(0, block.StoredLength), recordOffset, cancellationToken)
                            .ConfigureAwait(false);
                        await IndexedPayloadContainer.ReadExactlyAtAsync(input.SafeFileHandle,
                            tag, checked(recordOffset + block.StoredLength), cancellationToken).ConfigureAwait(false);
                        using var cipher = new ChaCha20Poly1305(dataKey);
                        var nonce = IndexedPayloadContainer.CreateNonce(header.PayloadNoncePrefix,
                            checked((ulong)(entry.DataBlockStart + blockIndex)));
                        var associated = IndexedPayloadContainer.CreateAssociatedData(header.HeaderHash, prefix,
                            checked((ulong)(entry.DataBlockStart + blockIndex)), "NRDATA-V2");
                        try
                        {
                            var decoded = new byte[block.StoredLength];
                            try
                            {
                                cipher.Decrypt(nonce, ciphertext.AsSpan(0, block.StoredLength), tag, decoded, associated);
                                if (block.IsCompressed)
                                {
                                    using var decompressor = new ZstdSharp.Decompressor();
                                    var result = decompressor.Unwrap(decoded, block.PlainLength);
                                    if (result.Length != block.PlainLength) throw new NingRanException("增量文件分段解压失败。");
                                    result.CopyTo(plaintext.AsSpan(0, block.PlainLength));
                                }
                                else
                                {
                                    if (block.StoredLength != block.PlainLength) throw new NingRanException("增量文件分段长度不正确。");
                                    decoded.CopyTo(plaintext, 0);
                                }
                            }
                            catch (CryptographicException exception)
                            {
                                throw new NingRanException("增量文件内容未通过完整性检查。", exception);
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(decoded);
                            }
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(nonce);
                            CryptographicOperations.ZeroMemory(associated);
                        }
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(tag);
            }
        }
        finally
        {
            parsed.Payload.Dispose();
        }
    }

    private static async Task<ParsedSegment> ReadSegmentAsync(
        FileStream input,
        long physicalStart,
        ArchiveHeader header,
        byte[] dataKey,
        byte[] prefix,
        CancellationToken cancellationToken)
    {
        var headerBytes = new byte[SegmentHeaderSize];
        try
        {
            await IndexedPayloadContainer.ReadExactlyAtAsync(input.SafeFileHandle, headerBytes, physicalStart,
                cancellationToken).ConfigureAwait(false);
            var info = ParseSegmentHeader(headerBytes);
            if (info.SegmentLength < SegmentHeaderSize + FooterSize + FixedRecordSize ||
                info.SegmentStart < 0 || info.BaseArchiveLength <= 0 || info.Generation < 1 ||
                info.DataBlockStart < 0 || info.DataBlockCount < 0 || info.CatalogBlockStart < 0 ||
                info.CatalogBlockCount < 1 || info.CatalogLength < 1)
            {
                throw new NingRanException("增量段头信息不正确。");
            }

            var catalogOffset = checked(info.SegmentLength - FooterSize - info.CatalogBlockCount * FixedRecordSize);
            if (catalogOffset < SegmentHeaderSize || checked(physicalStart + info.SegmentLength) > input.Length)
                throw new NingRanException("增量段长度不正确。");

            var footerBytes = new byte[FooterSize];
            try
            {
                await IndexedPayloadContainer.ReadExactlyAtAsync(input.SafeFileHandle, footerBytes,
                    checked(physicalStart + info.SegmentLength - FooterSize), cancellationToken).ConfigureAwait(false);
                var (footerLength, footerStart, footerGeneration, footerHash) = ParseFooter(footerBytes);
                if (footerLength != info.SegmentLength || footerStart != info.SegmentStart ||
                    footerGeneration != info.Generation)
                {
                    CryptographicOperations.ZeroMemory(footerHash);
                    throw new NingRanException("增量段没有完整提交标记。");
                }

                var catalogOffsetInFile = checked(physicalStart + catalogOffset);
                var indexBytes = await IndexedPayloadContainer.ReadFixedBlocksAtAsync(
                    input.SafeFileHandle,
                    catalogOffsetInFile,
                    info.CatalogBlockCount,
                    info.CatalogLength,
                    info.CatalogBlockStart,
                    header,
                    dataKey,
                    prefix,
                    "NRINDEX-V2",
                    cancellationToken).ConfigureAwait(false);
                try
                {
                    var payload = IndexedPayloadContainer.ParseIndex(indexBytes);
                    if (payload.IncrementalInfo is null ||
                        !IncrementalInfoEquals(payload.IncrementalInfo, info))
                    {
                        payload.Dispose();
                        CryptographicOperations.ZeroMemory(footerHash);
                        throw new NingRanException("增量目录与段头不一致。");
                    }

                    if (!CryptographicOperations.FixedTimeEquals(payload.AuthenticatedHash, footerHash))
                    {
                        payload.Dispose();
                        CryptographicOperations.ZeroMemory(footerHash);
                        throw new NingRanException("增量目录校验失败。");
                    }

                    return new ParsedSegment(info, payload, footerHash,
                        checked(physicalStart + catalogOffset));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(indexBytes);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(footerBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headerBytes);
        }
    }

    private static void ValidateSegmentChain(
        ParsedSegment parsed,
        long physicalStart,
        long baseLength,
        long previousGeneration,
        long previousSegmentStart,
        byte[] previousCatalogHash,
        long archiveLength,
        IReadOnlyList<(long Start, long End)> dataRanges)
    {
        var info = parsed.Info;
        if (info.SegmentStart != physicalStart || info.BaseArchiveLength != baseLength ||
            info.Generation != previousGeneration + 1 || info.PreviousSegmentStart != previousSegmentStart ||
            !CryptographicOperations.FixedTimeEquals(info.PreviousCatalogHash, previousCatalogHash) ||
            checked(physicalStart + info.SegmentLength) > archiveLength)
        {
            throw new NingRanException("增量段的顺序或来源不正确。");
        }

        foreach (var entry in parsed.Payload.Entries)
        {
            foreach (var block in entry.Blocks)
            {
                var absolute = checked(dataRanges[0].Start + block.DataOffset);
                var end = checked(absolute + block.StoredLength + TagSize);
                var currentRange = (
                    Start: checked(physicalStart + SegmentHeaderSize),
                    End: parsed.CatalogPhysicalOffset);
                var inKnownRange = dataRanges.Any(range => absolute >= range.Start && end <= range.End) ||
                                   (absolute >= currentRange.Start && end <= currentRange.End);
                if (!inKnownRange)
                    throw new NingRanException("增量目录引用了不存在的加密分段。");
            }
        }
    }

    private static bool IncrementalInfoEquals(IncrementalUpdateInfo left, IncrementalUpdateInfo right) =>
        left.Generation == right.Generation && left.SegmentStart == right.SegmentStart &&
        left.SegmentLength == right.SegmentLength && left.BaseArchiveLength == right.BaseArchiveLength &&
        left.PreviousSegmentStart == right.PreviousSegmentStart &&
        CryptographicOperations.FixedTimeEquals(left.PreviousCatalogHash, right.PreviousCatalogHash) &&
        left.DataBlockStart == right.DataBlockStart && left.DataBlockCount == right.DataBlockCount &&
        left.CatalogBlockStart == right.CatalogBlockStart && left.CatalogBlockCount == right.CatalogBlockCount &&
        left.CatalogLength == right.CatalogLength;

    private static async Task<byte[]> ReadSegmentMarkerAsync(
        FileStream input,
        long physicalStart,
        CancellationToken cancellationToken)
    {
        var marker = new byte[SegmentMagic.Length];
        await IndexedPayloadContainer.ReadExactlyAtAsync(
                input.SafeFileHandle,
                marker,
                physicalStart,
                cancellationToken)
            .ConfigureAwait(false);
        return marker;
    }

    private static byte[] BuildSegmentHeader(IncrementalUpdateInfo info, bool committed)
    {
        var bytes = new byte[SegmentHeaderSize];
        (committed ? SegmentMagic : ProvisionalSegmentMagic).CopyTo(bytes);
        var offset = 8;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset, 4), Version); offset += 4;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.SegmentLength); offset += 8;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.Generation); offset += 8;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.SegmentStart); offset += 8;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.BaseArchiveLength); offset += 8;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.PreviousSegmentStart); offset += 8;
        info.PreviousCatalogHash.CopyTo(bytes.AsSpan(offset, SHA256.HashSizeInBytes)); offset += SHA256.HashSizeInBytes;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.DataBlockStart); offset += 8;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.DataBlockCount); offset += 8;
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), info.CatalogBlockStart); offset += 8;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset, 4), info.CatalogBlockCount); offset += 4;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset, 4), info.CatalogLength);
        return bytes;
    }

    private static IncrementalUpdateInfo ParseSegmentHeader(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != SegmentHeaderSize ||
            (!bytes[..8].SequenceEqual(SegmentMagic) && !bytes[..8].SequenceEqual(ProvisionalSegmentMagic)) ||
            BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(8, 4)) != Version)
            throw new NingRanException("增量段头格式不正确。");

        var offset = 12;
        var segmentLength = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var generation = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var segmentStart = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var baseLength = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var previousStart = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var previousHash = bytes.Slice(offset, SHA256.HashSizeInBytes).ToArray(); offset += SHA256.HashSizeInBytes;
        var dataStart = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var dataCount = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var catalogStart = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(offset, 8)); offset += 8;
        var catalogCount = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(offset, 4)); offset += 4;
        var catalogLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(offset, 4));
        return new IncrementalUpdateInfo(generation, segmentStart, segmentLength, baseLength, previousStart,
            previousHash, dataStart, dataCount, catalogStart, catalogCount, catalogLength);
    }

    private static byte[] BuildFooter(IncrementalUpdateInfo info, byte[] catalogHash)
    {
        if (catalogHash.Length != SHA256.HashSizeInBytes) throw new ArgumentException("目录指纹长度不正确。", nameof(catalogHash));
        var bytes = new byte[FooterSize];
        FooterMagic.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), Version);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(12, 8), info.SegmentLength);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(20, 8), info.SegmentStart);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(28, 8), info.Generation);
        catalogHash.CopyTo(bytes.AsSpan(36, SHA256.HashSizeInBytes));
        return bytes;
    }

    private static (long SegmentLength, long SegmentStart, long Generation, byte[] CatalogHash) ParseFooter(
        ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != FooterSize || !bytes[..8].SequenceEqual(FooterMagic) ||
            BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(8, 4)) != Version)
            throw new NingRanException("增量段提交标记不正确。");
        return (
            BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(12, 8)),
            BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(20, 8)),
            BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(28, 8)),
            bytes.Slice(36, SHA256.HashSizeInBytes).ToArray());
    }

    private sealed record ParsedSegment(
        IncrementalUpdateInfo Info,
        IndexedPayloadContainer.IndexedPayload Payload,
        byte[] CatalogHash,
        long CatalogPhysicalOffset);
}
