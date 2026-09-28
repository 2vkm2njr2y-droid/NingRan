using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NingRan.Core.Internal;

/// <summary>
/// Version 2 single-file vault storage. Metadata uses two authenticated catalog slots and
/// file data is stored in fixed-size authenticated blocks. The container is updated in place;
/// opening or changing one file never requires unpacking or rewriting the whole vault.
/// </summary>
internal static class FixedVaultContainer
{
    private static ReadOnlySpan<byte> HeaderMagic => "NRVBLK02"u8;
    private static ReadOnlySpan<byte> CatalogMagic => "NRBCAT02"u8;
    private static ReadOnlySpan<byte> CatalogAadMagic => "NRBCAD02"u8;
    private static ReadOnlySpan<byte> BlockMagic => "NRBDAT02"u8;
    private static ReadOnlySpan<byte> BlockAadMagic => "NRBDAA02"u8;

    public const int FormatVersion = 2;
    public const int HeaderSize = 4096;
    public const int KeyAreaSize = 256 * 1024;
    public const int CatalogSlotSize = 16 * 1024 * 1024;
    public const int CatalogPlainSize = CatalogSlotSize - CryptoSizes.Nonce - CryptoSizes.Tag;
    public const int BlockPlainHeaderSize = 8 + 16 + 16 + sizeof(int) + sizeof(int);
    public const int DataSlotSize = CryptoSizes.Nonce + BlockPlainHeaderSize + VaultFormat.ChunkSize + CryptoSizes.Tag;
    public const long MinimumCapacityBytes = 64L * 1024 * 1024;

    private const long KeyOffset = HeaderSize;
    private const long CatalogAOffset = KeyOffset + KeyAreaSize;
    private const long CatalogBOffset = CatalogAOffset + CatalogSlotSize;
    private const long DataOffset = CatalogBOffset + CatalogSlotSize;
    private const int HeaderHashOffset = 128;
    private const int HeaderHashLength = 32;

    public static bool IsFormat(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            Span<byte> magic = stackalloc byte[8];
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return input.Read(magic) == magic.Length && magic.SequenceEqual(HeaderMagic);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static long CalculateRecommendedCapacity(long contentBytes)
    {
        if (contentBytes < 0) throw new ArgumentOutOfRangeException(nameof(contentBytes));
        var chunks = contentBytes == 0 ? 8 : checked((contentBytes + VaultFormat.ChunkSize - 1) / VaultFormat.ChunkSize);
        var required = checked(DataOffset + Math.Max(8, chunks + Math.Max(4, chunks / 4)) * (long)DataSlotSize);
        var gib = 1024L * 1024 * 1024;
        return Math.Max(gib, checked(((required + gib - 1) / gib) * gib));
    }

    public static int GetDataSlotCount(long capacityBytes)
    {
        ValidateCapacity(capacityBytes);
        return checked((int)((capacityBytes - DataOffset) / DataSlotSize));
    }

    public static async Task InitializeAsync(
        string path,
        VaultInfo info,
        long capacityBytes,
        ReadOnlyMemory<byte> keyHeader,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        ValidateCapacity(capacityBytes);
        if (keyHeader.Length <= 0 || keyHeader.Length > KeyAreaSize - sizeof(int))
        {
            throw new NingRanException("保险箱保护信息超过新版容器允许的大小。");
        }

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
                output.Position = KeyOffset;
                BinaryPrimitives.WriteInt32LittleEndian(random.AsSpan(0, sizeof(int)), keyHeader.Length);
                keyHeader.CopyTo(random.AsMemory(sizeof(int)));
                await output.WriteAsync(random.AsMemory(0, sizeof(int) + keyHeader.Length), cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(header);
            }
        }
        catch (IOException exception) when (IsDiskFull(exception))
        {
            throw new NingRanException("保存位置空间不足，固定容量保险箱没有创建完成。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    public static async Task<VaultInfo> ReadInfoAsync(string path, CancellationToken cancellationToken)
    {
        var normalized = VaultFormat.NormalizeVaultPath(path);
        var header = new byte[HeaderSize];
        try
        {
            await using var input = OpenRead(normalized);
            await input.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            if (BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8, 4)) == WorkspaceVaultContainer.FormatVersion)
            {
                return await WorkspaceVaultContainer.ReadInfoAsync(normalized, cancellationToken).ConfigureAwait(false);
            }
            ValidateHeader(header, input.Length);
            var ticks = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(48, 8));
            DateTimeOffset created;
            try { created = new DateTimeOffset(ticks, TimeSpan.Zero); }
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
        catch (NingRanException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or EndOfStreamException)
        {
            throw new NingRanException("无法读取新版保险箱识别信息。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
        }
    }

    public static async Task<byte[]> ReadKeyHeaderAsync(string path, CancellationToken cancellationToken)
    {
        var lengthBytes = new byte[sizeof(int)];
        try
        {
            await using var input = OpenRead(path);
            input.Position = KeyOffset;
            await input.ReadExactlyAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length <= 0 || length > KeyAreaSize - sizeof(int))
            {
                throw new NingRanException("保险箱保护信息大小不正确，文件可能已经损坏。");
            }
            var result = new byte[length];
            await input.ReadExactlyAsync(result, cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(lengthBytes);
        }
    }

    public static async Task WriteCatalogAsync(
        string path,
        VaultInfo info,
        IReadOnlyList<VaultCatalogEntry> entries,
        long revision,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        ValidateEntrySlots(path, entries);
        var plaintext = SerializeCatalog(info, entries, revision);
        var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
        var ciphertext = new byte[CatalogPlainSize];
        var tag = new byte[CryptoSizes.Tag];
        var slotIndex = checked((int)(revision & 1));
        var aad = BuildCatalogAad(info.VaultId, slotIndex);
        try
        {
            using (var cipher = new ChaCha20Poly1305(dataKey.Span))
            {
                cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            }
            await using var output = OpenWrite(path);
            output.Position = slotIndex == 0 ? CatalogAOffset : CatalogBOffset;
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

    public static async Task<(IReadOnlyList<VaultCatalogEntry> Entries, long Revision)> ReadCatalogAsync(
        string path,
        VaultInfo info,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        (IReadOnlyList<VaultCatalogEntry> Entries, long Revision)? best = null;
        for (var slotIndex = 0; slotIndex < 2; slotIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = await TryReadCatalogSlotAsync(path, info, dataKey, slotIndex, cancellationToken).ConfigureAwait(false);
            if (candidate is not null && (best is null || candidate.Value.Revision > best.Value.Revision)) best = candidate;
        }
        if (best is null)
        {
            throw new NingRanException("保险箱目录未通过完整性检查，密码条件不正确或目录已经损坏。");
        }
        ValidateEntrySlots(path, best.Value.Entries);
        return best.Value;
    }

    public static async Task<VaultCatalogEntry> WriteFileAsync(
        string path,
        VaultInfo info,
        VaultCatalogEntry entry,
        Stream source,
        ReadOnlyMemory<byte> dataKey,
        IReadOnlyList<VaultCatalogEntry> currentCatalog,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        if (entry.IsDirectory || entry.Length < 0) throw new NingRanException("保险箱文件信息不正确。");
        var layout = ReadLayout(path);
        var used = currentCatalog.SelectMany(item => item.BlockSlots ?? []).ToHashSet();
        // Keep every block referenced by either authenticated catalog copy. This is what makes
        // an interrupted catalog update able to fall back without reading overwritten data.
        for (var catalogSlot = 0; catalogSlot < 2; catalogSlot++)
        {
            var protectedCatalog = await TryReadCatalogSlotAsync(
                path, info, dataKey, catalogSlot, cancellationToken).ConfigureAwait(false);
            if (protectedCatalog is null) continue;
            foreach (var slot in protectedCatalog.Value.Entries.SelectMany(item => item.BlockSlots ?? [])) used.Add(slot);
        }
        var free = Enumerable.Range(0, layout.DataSlotCount).Where(index => !used.Contains(index)).Take(entry.ChunkCount).ToArray();
        if (free.Length != entry.ChunkCount)
        {
            throw new NingRanException("当前保险箱空间不足。请删除不需要的内容，或新建容量更大的保险箱。");
        }

        var plaintext = new byte[VaultFormat.ChunkSize];
        try
        {
            long completed = 0;
            for (var index = 0; index < entry.ChunkCount; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var plainLength = checked((int)Math.Min(VaultFormat.ChunkSize, entry.Length - completed));
                await source.ReadExactlyAsync(plaintext.AsMemory(0, plainLength), cancellationToken).ConfigureAwait(false);
                if (plainLength < plaintext.Length) RandomNumberGenerator.Fill(plaintext.AsSpan(plainLength));
                await WriteDataSlotAsync(path, info, free[index], entry.Id, index, plainLength, plaintext, dataKey, cancellationToken)
                    .ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(plaintext);
                completed += plainLength;
                progress?.Invoke(plainLength, $"正在加入保险箱：{entry.RelativePath}");
            }
            if (source.CanSeek && source.Position != source.Length)
            {
                throw new NingRanException($"文件在加入保险箱时发生了变化：{entry.RelativePath}");
            }
            return entry with { BlockSlots = free };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static async Task<int> ReadFileAtAsync(
        string path,
        VaultInfo info,
        VaultCatalogEntry entry,
        long offset,
        Memory<byte> destination,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        if (entry.IsDirectory || offset < 0 || offset >= entry.Length || destination.IsEmpty) return 0;
        if (entry.BlockSlots is null || entry.BlockSlots.Length != entry.ChunkCount)
        {
            throw new NingRanException("保险箱文件的数据位置记录不正确。");
        }
        var remaining = checked((int)Math.Min(destination.Length, entry.Length - offset));
        var written = 0;
        while (written < remaining)
        {
            var absolute = checked(offset + written);
            var chunkIndex = checked((int)(absolute / VaultFormat.ChunkSize));
            var chunkOffset = checked((int)(absolute % VaultFormat.ChunkSize));
            var chunk = await ReadDataSlotAsync(path, info, entry, chunkIndex, dataKey, cancellationToken).ConfigureAwait(false);
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
        VaultCatalogEntry entry,
        ReadOnlyMemory<byte> dataKey,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        for (var index = 0; index < entry.ChunkCount; index++)
        {
            var chunk = await ReadDataSlotAsync(path, info, entry, index, dataKey, cancellationToken).ConfigureAwait(false);
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
            return (
                BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(56, 8)),
                BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(72, 4)));
        }
        finally { CryptographicOperations.ZeroMemory(header); }
    }

    private static async Task<(IReadOnlyList<VaultCatalogEntry> Entries, long Revision)?> TryReadCatalogSlotAsync(
        string path, VaultInfo info, ReadOnlyMemory<byte> dataKey, int slotIndex, CancellationToken cancellationToken)
    {
        var nonce = new byte[CryptoSizes.Nonce];
        var ciphertext = new byte[CatalogPlainSize];
        var plaintext = new byte[CatalogPlainSize];
        var tag = new byte[CryptoSizes.Tag];
        var aad = BuildCatalogAad(info.VaultId, slotIndex);
        try
        {
            await using var input = OpenRead(path);
            input.Position = slotIndex == 0 ? CatalogAOffset : CatalogBOffset;
            await input.ReadExactlyAsync(nonce, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false);
            try
            {
                using var cipher = new ChaCha20Poly1305(dataKey.Span);
                cipher.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            }
            catch (CryptographicException) { return null; }
            try { return DeserializeCatalog(info, plaintext); }
            catch (NingRanException) { return null; }
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
        string path, VaultInfo info, int slotIndex, Guid fileId, int chunkIndex, int plainLength,
        ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> dataKey, CancellationToken cancellationToken)
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
            fileId.TryWriteBytes(plaintext.AsSpan(24, 16));
            BinaryPrimitives.WriteInt32LittleEndian(plaintext.AsSpan(40, 4), chunkIndex);
            BinaryPrimitives.WriteInt32LittleEndian(plaintext.AsSpan(44, 4), plainLength);
            payload.CopyTo(plaintext.AsMemory(BlockPlainHeaderSize));
            using (var cipher = new ChaCha20Poly1305(dataKey.Span))
            {
                cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            }
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

    private static async Task<FixedVaultChunk> ReadDataSlotAsync(
        string path, VaultInfo info, VaultCatalogEntry entry, int chunkIndex,
        ReadOnlyMemory<byte> dataKey, CancellationToken cancellationToken)
    {
        if (entry.BlockSlots is null || chunkIndex < 0 || chunkIndex >= entry.BlockSlots.Length)
            throw new NingRanException("保险箱文件的数据位置记录不正确。");
        var slotIndex = entry.BlockSlots[chunkIndex];
        var layout = ReadLayout(path);
        if (slotIndex < 0 || slotIndex >= layout.DataSlotCount) throw new NingRanException("保险箱文件的数据位置超出范围。");
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
            var expectedLength = checked((int)Math.Min(VaultFormat.ChunkSize, entry.Length - (long)chunkIndex * VaultFormat.ChunkSize));
            var plainLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(44, 4));
            if (!plaintext.AsSpan(0, 8).SequenceEqual(BlockMagic) ||
                new Guid(plaintext.AsSpan(8, 16)) != info.VaultId ||
                new Guid(plaintext.AsSpan(24, 16)) != entry.Id ||
                BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(40, 4)) != chunkIndex ||
                plainLength != expectedLength)
            {
                throw new NingRanException($"保险箱文件“{entry.Name}”的第 {chunkIndex + 1} 段格式不正确。");
            }
            var result = new byte[VaultFormat.ChunkSize];
            plaintext.AsSpan(BlockPlainHeaderSize, VaultFormat.ChunkSize).CopyTo(result);
            return new FixedVaultChunk(result, plainLength);
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

    private static byte[] SerializeCatalog(VaultInfo info, IReadOnlyList<VaultCatalogEntry> entries, long revision)
    {
        var result = RandomNumberGenerator.GetBytes(CatalogPlainSize);
        using var stream = new MemoryStream(result, writable: true);
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(CatalogMagic);
        writer.Write(info.VaultId.ToByteArray());
        writer.Write(revision);
        writer.Write((byte)info.Mode);
        writer.Write((byte)info.SizeProtection);
        writer.Write((ushort)0);
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

    private static (IReadOnlyList<VaultCatalogEntry> Entries, long Revision) DeserializeCatalog(VaultInfo info, byte[] plaintext)
    {
        try
        {
            using var stream = new MemoryStream(plaintext, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
            if (!reader.ReadBytes(8).AsSpan().SequenceEqual(CatalogMagic) ||
                new Guid(reader.ReadBytes(16)) != info.VaultId)
                throw new NingRanException("保险箱目录与识别信息不一致。");
            var revision = reader.ReadInt64();
            if (reader.ReadByte() != (byte)info.Mode || reader.ReadByte() != (byte)info.SizeProtection || reader.ReadUInt16() != 0)
                throw new NingRanException("保险箱目录与保护信息不一致。");
            var count = reader.ReadInt32();
            var contentLength = reader.ReadInt32();
            if (revision < 1 || count is < 0 or > VaultFormat.MaximumEntries || contentLength < stream.Position || contentLength > plaintext.Length)
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
            return (entries, revision);
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
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(72, 4), checked((int)((capacityBytes - DataOffset) / DataSlotSize)));
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
            slots != (capacity - DataOffset) / DataSlotSize || slots < 1 ||
            !CryptographicOperations.FixedTimeEquals(hash, header.AsSpan(HeaderHashOffset, HeaderHashLength)))
            throw new NingRanException("新版保险箱识别信息不正确或已经损坏。");
    }

    private static void ValidateCapacity(long capacityBytes)
    {
        if (capacityBytes < MinimumCapacityBytes || capacityBytes > 16L * 1024 * 1024 * 1024 * 1024)
            throw new NingRanException("保险箱固定容量必须在 64 MB 到 16 TB 之间。");
        if ((capacityBytes - DataOffset) / DataSlotSize < 1)
            throw new NingRanException("保险箱容量太小，无法容纳必要的加密结构。");
    }

    private static void ValidateEntrySlots(string path, IReadOnlyList<VaultCatalogEntry> entries)
    {
        var layout = ReadLayout(path);
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
                if (slot < 0 || slot >= layout.DataSlotCount || !used.Add(slot))
                    throw new NingRanException("保险箱目录包含重复或越界的数据位置。");
            }
        }
    }

    private static byte[] BuildCatalogAad(Guid vaultId, int slotIndex)
    {
        var result = new byte[32];
        CatalogAadMagic.CopyTo(result);
        vaultId.TryWriteBytes(result.AsSpan(8, 16));
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(24, 4), slotIndex);
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

    private static FileStream OpenRead(string path) => new(path, FileMode.Open, FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete, 1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess);
    private static FileStream OpenWrite(string path) => new(path, FileMode.Open, FileAccess.ReadWrite,
        FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough);
    private static bool IsDiskFull(IOException exception) => (exception.HResult & 0xFFFF) is 0x27 or 0x70;
    private sealed record FixedVaultChunk(byte[] Bytes, int PlainLength);
}
