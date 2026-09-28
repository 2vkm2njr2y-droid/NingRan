using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace NingRan.Core.Internal;

/// <summary>
/// Version 3 fixed-capacity storage. Every version 3 file has two key-envelope positions and
/// two catalog generations per position, whether one or two workspaces are actually used.
/// The public header therefore does not state whether a second workspace exists.
/// </summary>
internal static class WorkspaceVaultContainer
{
    private static ReadOnlySpan<byte> HeaderMagic => "NRVBLK02"u8;
    private static ReadOnlySpan<byte> CatalogMagic => "NRWCAT03"u8;
    private static ReadOnlySpan<byte> CatalogAadMagic => "NRWCAD03"u8;
    private static ReadOnlySpan<byte> BlockMagic => "NRWDAT03"u8;
    private static ReadOnlySpan<byte> BlockAadMagic => "NRWDAA03"u8;

    public const int FormatVersion = 3;
    public const int WorkspaceCount = 2;
    public const int HeaderSize = 4096;
    public const int KeyAreaSize = 256 * 1024;
    public const int CatalogSlotSize = 16 * 1024 * 1024;
    public const int CatalogPlainSize = CatalogSlotSize - CryptoSizes.Nonce - CryptoSizes.Tag;
    public const int BlockPlainHeaderSize = 8 + 16 + 16 + 16 + sizeof(int) + sizeof(int);
    public const int DataSlotSize = CryptoSizes.Nonce + BlockPlainHeaderSize + VaultFormat.ChunkSize + CryptoSizes.Tag;
    public const long MinimumCapacityBytes = 128L * 1024 * 1024;
    private const int CompatibilityTailSize = 64 * 1024;

    private const long KeyBaseOffset = HeaderSize;
    private const long CatalogBaseOffset = KeyBaseOffset + WorkspaceCount * KeyAreaSize;
    private const long DataOffset = CatalogBaseOffset + WorkspaceCount * 2L * CatalogSlotSize;
    private const int HeaderHashOffset = 128;
    private const int HeaderHashLength = 32;

    public static bool IsFormat(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            Span<byte> prefix = stackalloc byte[12];
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return input.Read(prefix) == prefix.Length &&
                   prefix[..8].SequenceEqual(HeaderMagic) &&
                   BinaryPrimitives.ReadInt32LittleEndian(prefix[8..]) == FormatVersion;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { return false; }
    }

    public static int GetDataSlotCount(long capacityBytes)
    {
        ValidateCapacity(capacityBytes);
        return CalculateDataSlotCount(capacityBytes);
    }

    public static long CalculateRecommendedCapacity(long totalContentBytes)
    {
        if (totalContentBytes < 0) throw new ArgumentOutOfRangeException(nameof(totalContentBytes));
        var chunks = totalContentBytes == 0
            ? 16
            : checked((totalContentBytes + VaultFormat.ChunkSize - 1) / VaultFormat.ChunkSize);
        var required = checked(DataOffset + Math.Max(16, chunks + Math.Max(8, chunks / 4)) * (long)DataSlotSize);
        var gib = 1024L * 1024 * 1024;
        return Math.Max(gib, checked(((required + gib - 1) / gib) * gib));
    }

    public static long GetRegionCapacityBytes(int slotCount) => checked((long)slotCount * VaultFormat.ChunkSize);

    public static async Task InitializeAsync(
        string path,
        VaultInfo info,
        long capacityBytes,
        ReadOnlyMemory<byte> firstKeyHeader,
        ReadOnlyMemory<byte> secondKeyHeader,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        ValidateCapacity(capacityBytes);
        ValidateKeyHeader(firstKeyHeader);
        ValidateKeyHeader(secondKeyHeader);
        var random = new byte[8 * 1024 * 1024];
        try
        {
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                random.Length, FileOptions.Asynchronous | FileOptions.WriteThrough);
            long written = 0;
            while (written < capacityBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var amount = checked((int)Math.Min(random.Length, capacityBytes - written));
                RandomNumberGenerator.Fill(random.AsSpan(0, amount));
                await output.WriteAsync(random.AsMemory(0, amount), cancellationToken).ConfigureAwait(false);
                written += amount;
                progress?.Invoke(amount, "正在建立固定容量并填充未使用区域…");
            }

            var header = BuildHeader(info, capacityBytes);
            try
            {
                output.Position = 0;
                await output.WriteAsync(header, cancellationToken).ConfigureAwait(false);
                await WriteKeyAreaAsync(output, 0, firstKeyHeader, random, cancellationToken).ConfigureAwait(false);
                await WriteKeyAreaAsync(output, 1, secondKeyHeader, random, cancellationToken).ConfigureAwait(false);
                var compatibilityArchive = BuildPreviousReleaseCompatibilityArchive(info, capacityBytes);
                try
                {
                    output.Position = checked(capacityBytes - compatibilityArchive.Length);
                    await output.WriteAsync(compatibilityArchive, cancellationToken).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(compatibilityArchive); }
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            finally { CryptographicOperations.ZeroMemory(header); }
        }
        catch (IOException exception) when (IsDiskFull(exception))
        {
            throw new NingRanException("保存位置空间不足，固定容量保险箱没有创建完成。", exception);
        }
        finally { CryptographicOperations.ZeroMemory(random); }
    }

    public static async Task<VaultInfo> ReadInfoAsync(string path, CancellationToken cancellationToken)
    {
        var normalized = VaultFormat.NormalizeVaultPath(path);
        var header = new byte[HeaderSize];
        try
        {
            await using var input = OpenRead(normalized);
            await input.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            ValidateHeader(header, input.Length);
            DateTimeOffset created;
            try { created = new DateTimeOffset(BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(48, 8)), TimeSpan.Zero); }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new NingRanException("保险箱创建时间不正确，识别信息可能已经损坏。", exception);
            }
            return new VaultInfo(
                normalized,
                new Guid(header.AsSpan(16, 16)),
                (EncryptionMode)header[32],
                (VaultSizeProtection)header[33],
                created,
                FormatVersion,
                BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(56, 8)));
        }
        finally { CryptographicOperations.ZeroMemory(header); }
    }

    public static async Task<byte[]> ReadKeyHeaderAsync(string path, int workspaceIndex, CancellationToken cancellationToken)
    {
        ValidateWorkspaceIndex(workspaceIndex);
        var lengthBytes = new byte[sizeof(int)];
        try
        {
            await using var input = OpenRead(path);
            input.Position = KeyOffset(workspaceIndex);
            await input.ReadExactlyAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length <= 0 || length > KeyAreaSize - sizeof(int))
                throw new NingRanException("保险箱保护信息大小不正确，文件可能已经损坏。");
            var result = new byte[length];
            await input.ReadExactlyAsync(result, cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(lengthBytes); }
    }

    public static async Task WriteCatalogAsync(
        string path,
        VaultInfo info,
        int workspaceIndex,
        VaultWorkspaceRegion region,
        IReadOnlyList<VaultCatalogEntry> entries,
        long revision,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        ValidateWorkspaceIndex(workspaceIndex);
        ValidateRegion(path, region);
        ValidateEntrySlots(entries, region);
        var plaintext = SerializeCatalog(info, region, entries, revision);
        var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
        var ciphertext = new byte[CatalogPlainSize];
        var tag = new byte[CryptoSizes.Tag];
        var generation = checked((int)(revision & 1));
        var physicalSlot = workspaceIndex * 2 + generation;
        var aad = BuildCatalogAad(info.VaultId, physicalSlot);
        try
        {
            using (var cipher = new ChaCha20Poly1305(dataKey.Span))
                cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            await using var output = OpenWrite(path);
            output.Position = CatalogOffset(physicalSlot);
            await output.WriteAsync(nonce, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public static async Task<VaultWorkspaceCatalog> ReadCatalogAsync(
        string path,
        VaultInfo info,
        int workspaceIndex,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        ValidateWorkspaceIndex(workspaceIndex);
        VaultWorkspaceCatalog? best = null;
        for (var generation = 0; generation < 2; generation++)
        {
            var candidate = await TryReadCatalogSlotAsync(
                path, info, workspaceIndex, generation, dataKey, cancellationToken).ConfigureAwait(false);
            if (candidate is not null && (best is null || candidate.Revision > best.Revision)) best = candidate;
        }
        if (best is null)
            throw new NingRanException("无法解锁保险箱。密码条件不正确，或保险箱已经损坏。");
        ValidateRegion(path, best.Region);
        ValidateEntrySlots(best.Entries, best.Region);
        return best;
    }

    public static async Task<VaultCatalogEntry> WriteFileAsync(
        string path,
        VaultInfo info,
        int workspaceIndex,
        VaultWorkspaceRegion region,
        VaultCatalogEntry entry,
        Stream source,
        ReadOnlyMemory<byte> dataKey,
        IReadOnlyList<VaultCatalogEntry> currentCatalog,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        if (entry.IsDirectory || entry.Length < 0) throw new NingRanException("保险箱文件信息不正确。");
        ValidateRegion(path, region);
        var used = currentCatalog.SelectMany(item => item.BlockSlots ?? []).ToHashSet();
        for (var generation = 0; generation < 2; generation++)
        {
            var protectedCatalog = await TryReadCatalogSlotAsync(
                path, info, workspaceIndex, generation, dataKey, cancellationToken).ConfigureAwait(false);
            if (protectedCatalog is null) continue;
            foreach (var slot in protectedCatalog.Entries.SelectMany(item => item.BlockSlots ?? [])) used.Add(slot);
        }
        var free = Enumerable.Range(region.StartSlot, region.SlotCount)
            .Where(slot => !used.Contains(slot)).Take(entry.ChunkCount).ToArray();
        if (free.Length != entry.ChunkCount)
            throw new NingRanException("当前保险箱空间不足。请删除不需要的内容，或新建容量更大的保险箱。");

        var plaintext = new byte[VaultFormat.ChunkSize];
        try
        {
            long completed = 0;
            for (var chunkIndex = 0; chunkIndex < entry.ChunkCount; chunkIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var plainLength = checked((int)Math.Min(VaultFormat.ChunkSize, entry.Length - completed));
                await source.ReadExactlyAsync(plaintext.AsMemory(0, plainLength), cancellationToken).ConfigureAwait(false);
                if (plainLength < plaintext.Length) RandomNumberGenerator.Fill(plaintext.AsSpan(plainLength));
                await WriteDataSlotAsync(
                    path, info, region.WorkspaceId, free[chunkIndex], entry.Id, chunkIndex,
                    plainLength, plaintext, dataKey, cancellationToken).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(plaintext);
                completed += plainLength;
                progress?.Invoke(plainLength, $"正在加入保险箱：{entry.RelativePath}");
            }
            if (source.CanSeek && source.Position != source.Length)
                throw new NingRanException($"文件在加入保险箱时发生了变化：{entry.RelativePath}");
            return entry with { BlockSlots = free };
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static async Task<int> ReadFileAtAsync(
        string path,
        VaultInfo info,
        VaultWorkspaceRegion region,
        VaultCatalogEntry entry,
        long offset,
        Memory<byte> destination,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        if (entry.IsDirectory || offset < 0 || offset >= entry.Length || destination.IsEmpty) return 0;
        ValidateEntrySlots([entry], region);
        var remaining = checked((int)Math.Min(destination.Length, entry.Length - offset));
        var written = 0;
        while (written < remaining)
        {
            var absolute = checked(offset + written);
            var chunkIndex = checked((int)(absolute / VaultFormat.ChunkSize));
            var chunkOffset = checked((int)(absolute % VaultFormat.ChunkSize));
            var chunk = await ReadDataSlotAsync(path, info, region, entry, chunkIndex, dataKey, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                var amount = Math.Min(remaining - written, chunk.PlainLength - chunkOffset);
                if (amount <= 0) throw new NingRanException("保险箱文件的分段长度不正确。");
                chunk.Bytes.AsMemory(chunkOffset, amount).CopyTo(destination[written..]);
                written += amount;
            }
            finally { CryptographicOperations.ZeroMemory(chunk.Bytes); }
        }
        return written;
    }

    public static async Task VerifyFileAsync(
        string path,
        VaultInfo info,
        VaultWorkspaceRegion region,
        VaultCatalogEntry entry,
        ReadOnlyMemory<byte> dataKey,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        ValidateEntrySlots([entry], region);
        for (var index = 0; index < entry.ChunkCount; index++)
        {
            var chunk = await ReadDataSlotAsync(path, info, region, entry, index, dataKey, cancellationToken)
                .ConfigureAwait(false);
            try { progress?.Invoke(chunk.PlainLength, $"正在检查：{entry.RelativePath}"); }
            finally { CryptographicOperations.ZeroMemory(chunk.Bytes); }
        }
    }

    public static (long CapacityBytes, int DataSlotCount) ReadLayout(string path)
    {
        var header = new byte[HeaderSize];
        try
        {
            using var input = OpenRead(path);
            input.ReadExactly(header);
            ValidateHeader(header, input.Length);
            return (BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(56, 8)),
                BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(72, 4)));
        }
        finally { CryptographicOperations.ZeroMemory(header); }
    }

    private static async Task<VaultWorkspaceCatalog?> TryReadCatalogSlotAsync(
        string path,
        VaultInfo info,
        int workspaceIndex,
        int generation,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        var nonce = new byte[CryptoSizes.Nonce];
        var ciphertext = new byte[CatalogPlainSize];
        var plaintext = new byte[CatalogPlainSize];
        var tag = new byte[CryptoSizes.Tag];
        var physicalSlot = workspaceIndex * 2 + generation;
        var aad = BuildCatalogAad(info.VaultId, physicalSlot);
        try
        {
            await using var input = OpenRead(path);
            input.Position = CatalogOffset(physicalSlot);
            await input.ReadExactlyAsync(nonce, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false);
            try
            {
                using var cipher = new ChaCha20Poly1305(dataKey.Span);
                cipher.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                return DeserializeCatalog(info, plaintext);
            }
            catch (Exception exception) when (exception is CryptographicException or NingRanException) { return null; }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static async Task WriteDataSlotAsync(
        string path,
        VaultInfo info,
        Guid workspaceId,
        int slotIndex,
        Guid fileId,
        int chunkIndex,
        int plainLength,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
        var plaintext = new byte[BlockPlainHeaderSize + VaultFormat.ChunkSize];
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[CryptoSizes.Tag];
        var aad = BuildBlockAad(info.VaultId, slotIndex);
        try
        {
            BlockMagic.CopyTo(plaintext);
            info.VaultId.TryWriteBytes(plaintext.AsSpan(8, 16));
            workspaceId.TryWriteBytes(plaintext.AsSpan(24, 16));
            fileId.TryWriteBytes(plaintext.AsSpan(40, 16));
            BinaryPrimitives.WriteInt32LittleEndian(plaintext.AsSpan(56, 4), chunkIndex);
            BinaryPrimitives.WriteInt32LittleEndian(plaintext.AsSpan(60, 4), plainLength);
            payload.CopyTo(plaintext.AsMemory(BlockPlainHeaderSize));
            using (var cipher = new ChaCha20Poly1305(dataKey.Span))
                cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            await using var output = OpenWrite(path);
            output.Position = checked(DataOffset + (long)slotIndex * DataSlotSize);
            await output.WriteAsync(nonce, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static async Task<WorkspaceChunk> ReadDataSlotAsync(
        string path,
        VaultInfo info,
        VaultWorkspaceRegion region,
        VaultCatalogEntry entry,
        int chunkIndex,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        if (entry.BlockSlots is null || chunkIndex < 0 || chunkIndex >= entry.BlockSlots.Length)
            throw new NingRanException("保险箱文件的数据位置记录不正确。");
        var slotIndex = entry.BlockSlots[chunkIndex];
        var nonce = new byte[CryptoSizes.Nonce];
        var ciphertext = new byte[BlockPlainHeaderSize + VaultFormat.ChunkSize];
        var plaintext = new byte[ciphertext.Length];
        var tag = new byte[CryptoSizes.Tag];
        var aad = BuildBlockAad(info.VaultId, slotIndex);
        try
        {
            await using var input = OpenRead(path);
            input.Position = checked(DataOffset + (long)slotIndex * DataSlotSize);
            await input.ReadExactlyAsync(nonce, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false);
            try
            {
                using var cipher = new ChaCha20Poly1305(dataKey.Span);
                cipher.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            }
            catch (CryptographicException exception)
            {
                throw new NingRanException($"保险箱文件“{entry.Name}”的第 {chunkIndex + 1} 段未通过完整性检查。", exception);
            }
            var expectedLength = checked((int)Math.Min(
                VaultFormat.ChunkSize, entry.Length - (long)chunkIndex * VaultFormat.ChunkSize));
            var plainLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(60, 4));
            if (!plaintext.AsSpan(0, 8).SequenceEqual(BlockMagic) ||
                new Guid(plaintext.AsSpan(8, 16)) != info.VaultId ||
                new Guid(plaintext.AsSpan(24, 16)) != region.WorkspaceId ||
                new Guid(plaintext.AsSpan(40, 16)) != entry.Id ||
                BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(56, 4)) != chunkIndex ||
                plainLength != expectedLength)
                throw new NingRanException($"保险箱文件“{entry.Name}”的第 {chunkIndex + 1} 段格式不正确。");
            var result = new byte[VaultFormat.ChunkSize];
            plaintext.AsSpan(BlockPlainHeaderSize, VaultFormat.ChunkSize).CopyTo(result);
            return new WorkspaceChunk(result, plainLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] SerializeCatalog(
        VaultInfo info,
        VaultWorkspaceRegion region,
        IReadOnlyList<VaultCatalogEntry> entries,
        long revision)
    {
        var result = RandomNumberGenerator.GetBytes(CatalogPlainSize);
        using var stream = new MemoryStream(result, writable: true);
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(CatalogMagic);
        writer.Write(info.VaultId.ToByteArray());
        writer.Write(region.WorkspaceId.ToByteArray());
        writer.Write(revision);
        writer.Write(region.StartSlot);
        writer.Write(region.SlotCount);
        writer.Write(entries.Count);
        var lengthPosition = stream.Position;
        writer.Write(0);
        foreach (var entry in entries.OrderBy(item => item.Id))
        {
            writer.Write(entry.Id.ToByteArray());
            writer.Write(entry.ParentId.ToByteArray());
            writer.Write(entry.IsDirectory ? (byte)1 : (byte)2);
            writer.Write(entry.Length);
            writer.Write(entry.LastWriteUtcTicks);
            writer.Write(entry.ChunkCount);
            var name = Encoding.UTF8.GetBytes(entry.Name);
            writer.Write(name.Length);
            writer.Write(name);
            CryptographicOperations.ZeroMemory(name);
            var slots = entry.BlockSlots ?? [];
            writer.Write(slots.Length);
            foreach (var slot in slots) writer.Write(slot);
            if (stream.Position > CatalogPlainSize)
            {
                CryptographicOperations.ZeroMemory(result);
                throw new NingRanException("保险箱目录过大，已超过新版容器的安全上限。");
            }
        }
        var contentLength = checked((int)stream.Position);
        stream.Position = lengthPosition;
        writer.Write(contentLength);
        return result;
    }

    private static VaultWorkspaceCatalog DeserializeCatalog(VaultInfo info, byte[] plaintext)
    {
        try
        {
            using var stream = new MemoryStream(plaintext, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
            if (!reader.ReadBytes(8).AsSpan().SequenceEqual(CatalogMagic) ||
                new Guid(reader.ReadBytes(16)) != info.VaultId)
                throw new NingRanException("保险箱目录与识别信息不一致。");
            var workspaceId = new Guid(reader.ReadBytes(16));
            var revision = reader.ReadInt64();
            var region = new VaultWorkspaceRegion(workspaceId, reader.ReadInt32(), reader.ReadInt32());
            var count = reader.ReadInt32();
            var contentLength = reader.ReadInt32();
            if (workspaceId == Guid.Empty || revision < 1 || count is < 0 or > VaultFormat.MaximumEntries ||
                contentLength < stream.Position || contentLength > plaintext.Length)
                throw new NingRanException("保险箱目录项目数量或长度不正确。");
            var entries = new List<VaultCatalogEntry>(count);
            for (var index = 0; index < count; index++)
            {
                var id = new Guid(reader.ReadBytes(16));
                var parentId = new Guid(reader.ReadBytes(16));
                var kind = reader.ReadByte();
                var length = reader.ReadInt64();
                var lastWrite = reader.ReadInt64();
                var chunkCount = reader.ReadInt32();
                var nameLength = reader.ReadInt32();
                if (kind is not (1 or 2) || nameLength is <= 0 or > 1024 || stream.Position + nameLength > contentLength)
                    throw new NingRanException("保险箱目录包含格式不正确的项目。");
                var name = Encoding.UTF8.GetString(reader.ReadBytes(nameLength));
                var slotCount = reader.ReadInt32();
                if (slotCount < 0 || slotCount > chunkCount || stream.Position + slotCount * (long)sizeof(int) > contentLength)
                    throw new NingRanException("保险箱目录的数据位置数量不正确。");
                var slots = new int[slotCount];
                for (var slot = 0; slot < slotCount; slot++) slots[slot] = reader.ReadInt32();
                entries.Add(new VaultCatalogEntry(id, parentId, name, kind == 1, length, lastWrite, chunkCount, slots));
            }
            if (stream.Position != contentLength) throw new NingRanException("保险箱目录结束位置不正确。");
            return new VaultWorkspaceCatalog(region, entries, revision);
        }
        catch (NingRanException) { throw; }
        catch (Exception exception) when (exception is IOException or EndOfStreamException or ArgumentException or DecoderFallbackException)
        {
            throw new NingRanException("保险箱目录格式不正确或已经损坏。", exception);
        }
    }

    private static byte[] BuildHeader(VaultInfo info, long capacityBytes)
    {
        var bytes = RandomNumberGenerator.GetBytes(HeaderSize);
        HeaderMagic.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), FormatVersion);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), HeaderSize);
        info.VaultId.TryWriteBytes(bytes.AsSpan(16, 16));
        bytes[32] = (byte)info.Mode;
        bytes[33] = (byte)info.SizeProtection;
        bytes.AsSpan(34, 14).Clear();
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(48, 8), info.CreatedAt.UtcTicks);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(56, 8), capacityBytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(64, 4), VaultFormat.ChunkSize);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(68, 4), DataSlotSize);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(72, 4), CalculateDataSlotCount(capacityBytes));
        bytes.AsSpan(76, 52).Clear();
        SHA256.HashData(bytes.AsSpan(0, HeaderHashOffset), bytes.AsSpan(HeaderHashOffset, HeaderHashLength));
        return bytes;
    }

    private static void ValidateHeader(byte[] header, long fileLength)
    {
        if (header.Length != HeaderSize || !header.AsSpan(0, 8).SequenceEqual(HeaderMagic))
            throw new NingRanException("这不是凝然支持的新版保险箱。");
        var version = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8, 4));
        if (version > FormatVersion)
            throw new NingRanException($"此保险箱使用格式版本 {version}，当前凝然最高支持版本 {FormatVersion}。请更新凝然后再打开；程序没有修改该保险箱。");
        var capacity = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(56, 8));
        var slots = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(72, 4));
        Span<byte> hash = stackalloc byte[HeaderHashLength];
        SHA256.HashData(header.AsSpan(0, HeaderHashOffset), hash);
        if (version != FormatVersion ||
            BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(12, 4)) != HeaderSize ||
            header[32] > (byte)EncryptionMode.PhysicalDevice ||
            header[33] > (byte)VaultSizeProtection.HideExactSize ||
            header.AsSpan(34, 14).IndexOfAnyExcept((byte)0) >= 0 ||
            header.AsSpan(76, 52).IndexOfAnyExcept((byte)0) >= 0 ||
            capacity != fileLength || capacity < MinimumCapacityBytes ||
            BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(64, 4)) != VaultFormat.ChunkSize ||
            BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(68, 4)) != DataSlotSize ||
            slots != CalculateDataSlotCount(capacity) || slots < 1 ||
            !CryptographicOperations.FixedTimeEquals(hash, header.AsSpan(HeaderHashOffset, HeaderHashLength)))
            throw new NingRanException("新版保险箱识别信息不正确或已经损坏。");
    }

    private static void ValidateCapacity(long capacityBytes)
    {
        if (capacityBytes < MinimumCapacityBytes || capacityBytes > 16L * 1024 * 1024 * 1024 * 1024)
            throw new NingRanException("保险箱固定容量必须在 128 MB 到 16 TB 之间。");
        if (CalculateDataSlotCount(capacityBytes) < 2)
            throw new NingRanException("保险箱容量太小，无法容纳必要的加密结构。");
    }

    private static void ValidateRegion(string path, VaultWorkspaceRegion region)
    {
        var layout = ReadLayout(path);
        if (region.WorkspaceId == Guid.Empty || region.StartSlot < 0 || region.SlotCount < 1 ||
            (long)region.StartSlot + region.SlotCount > layout.DataSlotCount)
            throw new NingRanException("保险箱当前空间的容量范围不正确。");
    }

    private static void ValidateEntrySlots(IReadOnlyList<VaultCatalogEntry> entries, VaultWorkspaceRegion region)
    {
        var used = new HashSet<int>();
        foreach (var entry in entries)
        {
            if (entry.IsDirectory)
            {
                if (entry.BlockSlots is { Length: > 0 }) throw new NingRanException("保险箱文件夹错误地占用了数据位置。");
                continue;
            }
            if (entry.BlockSlots is null || entry.BlockSlots.Length != entry.ChunkCount)
                throw new NingRanException("保险箱文件的数据位置数量不正确。");
            foreach (var slot in entry.BlockSlots)
            {
                if (slot < region.StartSlot || slot >= region.StartSlot + region.SlotCount || !used.Add(slot))
                    throw new NingRanException("保险箱目录包含重复或越界的数据位置。");
            }
        }
    }

    private static async Task WriteKeyAreaAsync(
        FileStream output,
        int workspaceIndex,
        ReadOnlyMemory<byte> keyHeader,
        Memory<byte> scratch,
        CancellationToken cancellationToken)
    {
        output.Position = KeyOffset(workspaceIndex);
        BinaryPrimitives.WriteInt32LittleEndian(scratch.Span[..sizeof(int)], keyHeader.Length);
        keyHeader.CopyTo(scratch[sizeof(int)..]);
        await output.WriteAsync(scratch[..(sizeof(int) + keyHeader.Length)], cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateKeyHeader(ReadOnlyMemory<byte> keyHeader)
    {
        if (keyHeader.Length <= 0 || keyHeader.Length > KeyAreaSize - sizeof(int))
            throw new NingRanException("保险箱保护信息超过新版容器允许的大小。");
    }

    private static byte[] BuildCatalogAad(Guid vaultId, int physicalSlot)
    {
        var result = new byte[32];
        CatalogAadMagic.CopyTo(result);
        vaultId.TryWriteBytes(result.AsSpan(8, 16));
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(24, 4), physicalSlot);
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(28, 4), FormatVersion);
        return result;
    }

    private static byte[] BuildBlockAad(Guid vaultId, int slotIndex)
    {
        var result = new byte[32];
        BlockAadMagic.CopyTo(result);
        vaultId.TryWriteBytes(result.AsSpan(8, 16));
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(24, 4), slotIndex);
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(28, 4), FormatVersion);
        return result;
    }

    private static long KeyOffset(int workspaceIndex) => KeyBaseOffset + (long)workspaceIndex * KeyAreaSize;
    private static long CatalogOffset(int physicalSlot) => CatalogBaseOffset + (long)physicalSlot * CatalogSlotSize;

    private static int CalculateDataSlotCount(long capacityBytes) =>
        checked((int)((capacityBytes - DataOffset - CompatibilityTailSize) / DataSlotSize));

    private static byte[] BuildPreviousReleaseCompatibilityArchive(VaultInfo info, long capacityBytes)
    {
        var archiveStart = capacityBytes - CompatibilityTailSize;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var result = BuildPreviousReleaseCompatibilityArchiveAtOffset(info, archiveStart);
            if (result.Length > CompatibilityTailSize)
            {
                CryptographicOperations.ZeroMemory(result);
                throw new InvalidOperationException("旧版只读识别信息超出保留区域。");
            }
            var finalStart = capacityBytes - result.Length;
            if (finalStart == archiveStart) return result;
            CryptographicOperations.ZeroMemory(result);
            archiveStart = finalStart;
        }
        throw new InvalidOperationException("无法稳定生成旧版只读识别信息。");
    }

    internal static byte[] BuildPreviousReleaseCompatibilityArchiveForTesting(VaultInfo info, long capacityBytes) =>
        BuildPreviousReleaseCompatibilityArchive(info, capacityBytes);

    private static byte[] BuildPreviousReleaseCompatibilityArchiveAtOffset(VaultInfo info, long archiveStart)
    {
        var publicInfo = RandomNumberGenerator.GetBytes(64);
        try
        {
            "NRVAULT1"u8.CopyTo(publicInfo);
            BinaryPrimitives.WriteInt32LittleEndian(publicInfo.AsSpan(8, 4), FormatVersion);
            info.VaultId.TryWriteBytes(publicInfo.AsSpan(12, 16));
            publicInfo[28] = (byte)info.Mode;
            publicInfo[29] = (byte)info.SizeProtection;
            publicInfo.AsSpan(30, 18).Clear();
            BinaryPrimitives.WriteInt64LittleEndian(publicInfo.AsSpan(48, 8), info.CreatedAt.UtcTicks);
            publicInfo.AsSpan(56, 8).Clear();

            using var archiveBytes = new MemoryStream();
            using var positioned = new AbsolutePositionWriteStream(archiveBytes, archiveStart);
            using (var archive = new ZipArchive(positioned, ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = archive.CreateEntry("vault.info", CompressionLevel.NoCompression);
                using var entryStream = entry.Open();
                entryStream.Write(publicInfo);
            }
            var result = archiveBytes.ToArray();
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(publicInfo); }
    }

    private sealed class AbsolutePositionWriteStream(Stream inner, long prefixLength) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => true;
        public override bool CanWrite => true;
        public override long Length => checked(prefixLength + inner.Length);
        public override long Position
        {
            get => checked(prefixLength + inner.Position);
            set
            {
                if (value < prefixLength) throw new IOException("兼容识别流不能写入保险箱数据区域。");
                inner.Position = value - prefixLength;
            }
        }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin)
        {
            var absolute = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(Position + offset),
                SeekOrigin.End => checked(Length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
            Position = absolute;
            return Position;
        }
        public override void SetLength(long value)
        {
            if (value < prefixLength) throw new IOException("兼容识别流长度不能小于保险箱数据区域。");
            inner.SetLength(value - prefixLength);
        }
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override void Write(ReadOnlySpan<byte> buffer) => inner.Write(buffer);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.WriteAsync(buffer, cancellationToken);
    }
    private static void ValidateWorkspaceIndex(int workspaceIndex)
    {
        if (workspaceIndex is < 0 or >= WorkspaceCount) throw new ArgumentOutOfRangeException(nameof(workspaceIndex));
    }
    private static FileStream OpenRead(string path) => new(path, FileMode.Open, FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete, 1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess);
    private static FileStream OpenWrite(string path) => new(path, FileMode.Open, FileAccess.ReadWrite,
        FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough);
    private static bool IsDiskFull(IOException exception) => (exception.HResult & 0xFFFF) is 0x27 or 0x70;
    private sealed record WorkspaceChunk(byte[] Bytes, int PlainLength);
}

internal sealed record VaultWorkspaceRegion(Guid WorkspaceId, int StartSlot, int SlotCount);
internal sealed record VaultWorkspaceCatalog(
    VaultWorkspaceRegion Region,
    IReadOnlyList<VaultCatalogEntry> Entries,
    long Revision);
