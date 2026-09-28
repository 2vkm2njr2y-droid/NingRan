using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NingRan.Core.Internal;

internal static class VaultFormat
{
    private static ReadOnlySpan<byte> InfoMagic => "NRVAULT1"u8;
    private static ReadOnlySpan<byte> CatalogMagic => "NRCAT001"u8;
    private static ReadOnlySpan<byte> CatalogPlainMagic => "NRDIR001"u8;
    private static ReadOnlySpan<byte> ChunkMagic => "NRCHK001"u8;
    private const int InfoSize = 64;
    private const int CatalogHeaderSize = 8 + sizeof(int) + sizeof(int) + CryptoSizes.Nonce;
    private const int CatalogMaximumPlaintext = 64 * 1024 * 1024;
    private const int ChunkHeaderSize = 8 + 16 + 16 + sizeof(long) + sizeof(int) + sizeof(int) + CryptoSizes.Nonce;
    // New formats must keep an explicit read-only path for every version at or above this value.
    public const int MinimumSupportedVersion = 1;
    public const int CurrentVersion = 1;
    public const int ChunkSize = 1024 * 1024;
    public const int MaximumEntries = 100_000;
    private const int MaximumTotalNameBytes = 32 * 1024 * 1024;

    public static string NormalizeVaultPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var name = Path.GetFileName(fullPath);
        PathSafety.ValidateNameSegment(name);
        return fullPath;
    }

    public static async Task WriteInfoAsync(string path, VaultInfo info, CancellationToken cancellationToken)
    {
        var bytes = RandomNumberGenerator.GetBytes(InfoSize);
        try
        {
            InfoMagic.CopyTo(bytes);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), CurrentVersion);
            info.VaultId.TryWriteBytes(bytes.AsSpan(12, 16));
            bytes[28] = (byte)info.Mode;
            bytes[29] = (byte)info.SizeProtection;
            bytes.AsSpan(30, 18).Clear();
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(48, 8), info.CreatedAt.UtcTicks);
            bytes.AsSpan(56, 8).Clear();
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
            await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static async Task<VaultInfo> ReadInfoAsync(string vaultPath, CancellationToken cancellationToken)
    {
        var normalized = NormalizeVaultPath(vaultPath);
        if (!Directory.Exists(normalized))
        {
            throw new NingRanException("请选择存在的凝然保险箱文件。");
        }

        return await ReadInfoFromDirectoryAsync(normalized, cancellationToken).ConfigureAwait(false);
    }

    internal static VaultInfo ParseInfoBytes(string vaultPath, ReadOnlySpan<byte> bytes)
    {
        var formatVersion = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(8, 4));
        if (bytes.Length != InfoSize ||
            !bytes[..8].SequenceEqual(InfoMagic) ||
            formatVersion < MinimumSupportedVersion ||
            bytes.Slice(30, 18).IndexOfAnyExcept((byte)0) >= 0 ||
            bytes.Slice(56, 8).IndexOfAnyExcept((byte)0) >= 0 ||
            bytes[28] > (byte)EncryptionMode.PhysicalDevice ||
            bytes[29] > (byte)VaultSizeProtection.HideExactSize)
        {
            throw new NingRanException("这不是凝然支持的保险箱，或识别信息已经损坏。");
        }
        if (formatVersion > CurrentVersion)
        {
            throw new NingRanException($"此保险箱使用格式版本 {formatVersion}，当前凝然最高支持版本 {CurrentVersion}。请更新凝然后再打开；程序没有修改该保险箱。");
        }
        var ticks = BinaryPrimitives.ReadInt64LittleEndian(bytes.Slice(48, 8));
        DateTimeOffset created;
        try { created = new DateTimeOffset(ticks, TimeSpan.Zero); }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new NingRanException("保险箱创建时间不正确，识别信息可能已经损坏。", exception);
        }
        return new VaultInfo(
            vaultPath,
            new Guid(bytes.Slice(12, 16)),
            (EncryptionMode)bytes[28],
            (VaultSizeProtection)bytes[29],
            created,
            formatVersion);
    }

    public static async Task<VaultInfo> ReadInfoFromDirectoryAsync(string directory, CancellationToken cancellationToken)
    {
        var normalized = NormalizeVaultPath(directory);
        if (!Directory.Exists(normalized)) throw new NingRanException("保险箱内部目录不存在。");

        var infoPath = Path.Combine(normalized, "vault.info");
        var bytes = new byte[InfoSize];
        try
        {
            await using var input = new FileStream(infoPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (input.Length != InfoSize)
            {
                throw new NingRanException("保险箱识别信息大小不正确，可能已经损坏。");
            }

            await input.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return ParseInfoBytes(normalized, bytes);
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new NingRanException("无法读取保险箱识别信息。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static async Task WriteCatalogAsync(
        string vaultPath,
        VaultInfo info,
        IReadOnlyList<VaultCatalogEntry> entries,
        long revision,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        if (info.FormatVersion == WorkspaceVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            var region = info.WorkspaceRegion ?? throw new NingRanException("保险箱当前空间尚未解锁。");
            await WorkspaceVaultContainer.WriteCatalogAsync(
                vaultPath, info, info.WorkspaceIndex, region, entries, revision, dataKey, cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        if (info.FormatVersion == FixedVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            await FixedVaultContainer.WriteCatalogAsync(vaultPath, info, entries, revision, dataKey, cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        var plaintext = SerializeCatalog(info, entries, revision);
        var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
        var header = new byte[CatalogHeaderSize];
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[CryptoSizes.Tag];
        try
        {
            CatalogMagic.CopyTo(header);
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8, 4), CurrentVersion);
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12, 4), plaintext.Length);
            nonce.CopyTo(header.AsSpan(16));
            using (var cipher = new ChaCha20Poly1305(dataKey.Span))
            {
                cipher.Encrypt(nonce, plaintext, ciphertext, tag, header);
            }

            var directory = Path.Combine(vaultPath, "catalog");
            Directory.CreateDirectory(directory);
            var finalPath = Path.Combine(directory, "current.nrcat");
            var temporaryPath = Path.Combine(directory, $".{Guid.NewGuid():N}.part");
            try
            {
                await using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                                 1024 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await output.WriteAsync(header, cancellationToken).ConfigureAwait(false);
                    await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
                    await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }

                if (File.Exists(finalPath))
                {
                    var backupPath = Path.Combine(directory, $".{Guid.NewGuid():N}.backup");
                    try
                    {
                        File.Replace(temporaryPath, finalPath, backupPath, ignoreMetadataErrors: true);
                    }
                    finally
                    {
                        try { if (File.Exists(backupPath)) File.Delete(backupPath); } catch { }
                    }
                }
                else
                {
                    File.Move(temporaryPath, finalPath);
                }
            }
            finally
            {
                try { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); } catch { }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static async Task<(IReadOnlyList<VaultCatalogEntry> Entries, long Revision)> ReadCatalogAsync(
        string vaultPath,
        VaultInfo info,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        if (info.FormatVersion == WorkspaceVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            var catalog = await WorkspaceVaultContainer.ReadCatalogAsync(
                vaultPath, info, info.WorkspaceIndex, dataKey, cancellationToken).ConfigureAwait(false);
            return (catalog.Entries, catalog.Revision);
        }
        if (info.FormatVersion == FixedVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            return await FixedVaultContainer.ReadCatalogAsync(vaultPath, info, dataKey, cancellationToken)
                .ConfigureAwait(false);
        }
        var path = Path.Combine(vaultPath, "catalog", "current.nrcat");
        var header = new byte[CatalogHeaderSize];
        byte[]? ciphertext = null;
        byte[]? plaintext = null;
        var tag = new byte[CryptoSizes.Tag];
        try
        {
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess);
            await input.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(12, 4));
            if (!header.AsSpan(0, 8).SequenceEqual(CatalogMagic) ||
                BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8, 4)) != CurrentVersion ||
                length is < 0 or > CatalogMaximumPlaintext ||
                input.Length != CatalogHeaderSize + (long)length + CryptoSizes.Tag)
            {
                throw new NingRanException("保险箱的加密目录格式不正确或已经损坏。");
            }

            ciphertext = new byte[length];
            plaintext = new byte[length];
            await input.ReadExactlyAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false);
            try
            {
                using var cipher = new ChaCha20Poly1305(dataKey.Span);
                cipher.Decrypt(header.AsSpan(16, CryptoSizes.Nonce), ciphertext, tag, plaintext, header);
            }
            catch (CryptographicException exception)
            {
                throw new NingRanException("保险箱目录未通过完整性检查，密码条件不正确或目录已经损坏。", exception);
            }

            return DeserializeCatalog(info, plaintext);
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or EndOfStreamException)
        {
            throw new NingRanException("无法读取保险箱的加密目录。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static async Task<VaultCatalogEntry> WriteFileAsync(
        string vaultPath,
        VaultInfo info,
        VaultCatalogEntry entry,
        Stream source,
        ReadOnlyMemory<byte> dataKey,
        IReadOnlyList<VaultCatalogEntry>? currentCatalog,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        if (entry.IsDirectory || entry.Length < 0)
        {
            throw new NingRanException("保险箱文件信息不正确。");
        }

        if (info.FormatVersion == WorkspaceVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            var region = info.WorkspaceRegion ?? throw new NingRanException("保险箱当前空间尚未解锁。");
            return await WorkspaceVaultContainer.WriteFileAsync(
                vaultPath, info, info.WorkspaceIndex, region, entry, source, dataKey,
                currentCatalog ?? [], progress, cancellationToken).ConfigureAwait(false);
        }

        if (info.FormatVersion == FixedVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            return await FixedVaultContainer.WriteFileAsync(
                vaultPath, info, entry, source, dataKey, currentCatalog ?? [], progress, cancellationToken)
                .ConfigureAwait(false);
        }

        var fileDirectory = GetFileDirectory(vaultPath, entry.Id);
        Directory.CreateDirectory(fileDirectory);
        var plaintext = new byte[ChunkSize];
        try
        {
            long completed = 0;
            for (var index = 0; index < entry.ChunkCount; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var plainLength = checked((int)Math.Min(ChunkSize, entry.Length - completed));
                await source.ReadExactlyAsync(plaintext.AsMemory(0, plainLength), cancellationToken).ConfigureAwait(false);
                var storedLength = info.SizeProtection == VaultSizeProtection.HideExactSize ? ChunkSize : plainLength;
                if (storedLength > plainLength)
                {
                    RandomNumberGenerator.Fill(plaintext.AsSpan(plainLength, storedLength - plainLength));
                }

                await WriteChunkAsync(vaultPath, info, entry.Id, index, plaintext.AsMemory(0, storedLength), plainLength,
                    dataKey, cancellationToken).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(plaintext);
                completed = checked(completed + plainLength);
                progress?.Invoke(plainLength, $"正在加入保险箱：{entry.RelativePath}");
            }

            if (source.CanSeek && source.Position != source.Length)
            {
                throw new NingRanException($"文件在加入保险箱时发生了变化：{entry.RelativePath}");
            }
            return entry;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static async Task<int> ReadFileAtAsync(
        string vaultPath,
        VaultInfo info,
        VaultCatalogEntry entry,
        long offset,
        Memory<byte> destination,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        if (info.FormatVersion == WorkspaceVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            var region = info.WorkspaceRegion ?? throw new NingRanException("保险箱当前空间尚未解锁。");
            return await WorkspaceVaultContainer.ReadFileAtAsync(
                vaultPath, info, region, entry, offset, destination, dataKey, cancellationToken).ConfigureAwait(false);
        }
        if (info.FormatVersion == FixedVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            return await FixedVaultContainer.ReadFileAtAsync(
                vaultPath, info, entry, offset, destination, dataKey, cancellationToken).ConfigureAwait(false);
        }
        if (entry.IsDirectory || offset < 0 || offset >= entry.Length || destination.IsEmpty)
        {
            return 0;
        }

        var remaining = checked((int)Math.Min(destination.Length, entry.Length - offset));
        var written = 0;
        while (written < remaining)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var absolute = checked(offset + written);
            var chunkIndex = checked((int)(absolute / ChunkSize));
            var chunkOffset = checked((int)(absolute % ChunkSize));
            var chunk = await ReadChunkAsync(vaultPath, info, entry, chunkIndex, dataKey, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                var count = Math.Min(remaining - written, chunk.PlainLength - chunkOffset);
                if (count <= 0)
                {
                    throw new NingRanException("保险箱文件的分段长度不正确。");
                }
                chunk.Bytes.AsMemory(chunkOffset, count).CopyTo(destination[written..]);
                written += count;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(chunk.Bytes);
            }
        }

        return written;
    }

    public static async Task VerifyFileAsync(
        string vaultPath,
        VaultInfo info,
        VaultCatalogEntry entry,
        ReadOnlyMemory<byte> dataKey,
        Action<long, string>? progress,
        CancellationToken cancellationToken)
    {
        if (info.FormatVersion == WorkspaceVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            var region = info.WorkspaceRegion ?? throw new NingRanException("保险箱当前空间尚未解锁。");
            await WorkspaceVaultContainer.VerifyFileAsync(
                vaultPath, info, region, entry, dataKey, progress, cancellationToken).ConfigureAwait(false);
            return;
        }
        if (info.FormatVersion == FixedVaultContainer.FormatVersion && File.Exists(vaultPath))
        {
            await FixedVaultContainer.VerifyFileAsync(
                vaultPath, info, entry, dataKey, progress, cancellationToken).ConfigureAwait(false);
            return;
        }
        for (var index = 0; index < entry.ChunkCount; index++)
        {
            var chunk = await ReadChunkAsync(vaultPath, info, entry, index, dataKey, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                progress?.Invoke(chunk.PlainLength, $"正在检查：{entry.RelativePath}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(chunk.Bytes);
            }
        }
    }

    public static string GetFileDirectory(string vaultPath, Guid fileId)
    {
        var id = fileId.ToString("N");
        return Path.Combine(vaultPath, "data", id[..2], id);
    }

    public static void DeleteFileData(string vaultPath, Guid fileId)
    {
        if (File.Exists(vaultPath) && FixedVaultContainer.IsFormat(vaultPath)) return;
        var directory = GetFileDirectory(vaultPath, fileId);
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static byte[] SerializeCatalog(VaultInfo info, IReadOnlyList<VaultCatalogEntry> entries, long revision)
    {
        ValidateCatalog(entries);
        using var output = new MemoryStream();
        using (var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(CatalogPlainMagic);
            writer.Write(info.VaultId.ToByteArray());
            writer.Write((byte)info.Mode);
            writer.Write((byte)info.SizeProtection);
            writer.Write((ushort)0);
            writer.Write(revision);
            writer.Write(entries.Count);
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
            }
        }

        if (output.Length > CatalogMaximumPlaintext)
        {
            throw new NingRanException("保险箱目录过大，已超过当前版本的安全上限。");
        }
        return output.ToArray();
    }

    private static (IReadOnlyList<VaultCatalogEntry> Entries, long Revision) DeserializeCatalog(
        VaultInfo info,
        byte[] plaintext)
    {
        try
        {
            using var input = new MemoryStream(plaintext, writable: false);
            using var reader = new BinaryReader(input, Encoding.UTF8, leaveOpen: true);
            if (!reader.ReadBytes(8).AsSpan().SequenceEqual(CatalogPlainMagic) ||
                new Guid(reader.ReadBytes(16)) != info.VaultId ||
                reader.ReadByte() != (byte)info.Mode ||
                reader.ReadByte() != (byte)info.SizeProtection ||
                reader.ReadUInt16() != 0)
            {
                throw new NingRanException("保险箱目录与识别信息不一致，可能已经损坏或被替换。");
            }

            var revision = reader.ReadInt64();
            var count = reader.ReadInt32();
            if (revision < 1 || count is < 0 or > MaximumEntries)
            {
                throw new NingRanException("保险箱目录的项目数量或修改编号不正确。");
            }

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
                if (kind is not (1 or 2) || nameLength is <= 0 or > 1024 ||
                    input.Position + nameLength > input.Length)
                {
                    throw new NingRanException("保险箱目录包含格式不正确的项目。");
                }

                var name = Encoding.UTF8.GetString(reader.ReadBytes(nameLength));
                entries.Add(new VaultCatalogEntry(id, parentId, name, kind == 1, length, lastWrite, chunkCount));
            }

            if (input.Position != input.Length)
            {
                throw new NingRanException("保险箱目录结束位置之后还有异常数据。");
            }

            ValidateCatalog(entries);
            return (entries, revision);
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception exception) when (exception is EndOfStreamException or IOException or ArgumentException or DecoderFallbackException)
        {
            throw new NingRanException("保险箱目录格式不正确或已经损坏。", exception);
        }
    }

    private static void ValidateCatalog(IReadOnlyList<VaultCatalogEntry> entries)
    {
        if (entries.Count > MaximumEntries)
        {
            throw new NingRanException($"保险箱最多支持 {MaximumEntries:N0} 个文件和文件夹。");
        }

        var ids = new HashSet<Guid>();
        var byParent = new Dictionary<Guid, HashSet<string>>();
        var totalNameBytes = 0;
        foreach (var entry in entries)
        {
            if (entry.Id == Guid.Empty || !ids.Add(entry.Id))
            {
                throw new NingRanException("保险箱目录包含重复或空白的内部编号。");
            }
            PathSafety.ValidateNameSegment(entry.Name);
            totalNameBytes = checked(totalNameBytes + Encoding.UTF8.GetByteCount(entry.Name));
            if (totalNameBytes > MaximumTotalNameBytes)
            {
                throw new NingRanException("保险箱目录中的名称总长度超过安全上限。");
            }
            if (!byParent.TryGetValue(entry.ParentId, out var names))
            {
                names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                byParent.Add(entry.ParentId, names);
            }
            if (!names.Add(entry.Name))
            {
                throw new NingRanException("保险箱的同一文件夹中存在重名项目。");
            }
            if (entry.IsDirectory)
            {
                if (entry.Length != 0 || entry.ChunkCount != 0)
                {
                    throw new NingRanException("保险箱文件夹信息不正确。");
                }
            }
            else
            {
                var expected = entry.Length == 0 ? 0 : checked((int)((entry.Length + ChunkSize - 1) / ChunkSize));
                if (entry.Length < 0 || entry.ChunkCount != expected)
                {
                    throw new NingRanException("保险箱文件大小或分段数量不正确。");
                }
            }
        }

        foreach (var entry in entries)
        {
            if (entry.ParentId != Guid.Empty && !ids.Contains(entry.ParentId))
            {
                throw new NingRanException("保险箱目录包含失去上级文件夹的项目。");
            }
        }

        var map = entries.ToDictionary(entry => entry.Id);
        foreach (var entry in entries)
        {
            var seen = new HashSet<Guid> { entry.Id };
            var parent = entry.ParentId;
            var depth = 0;
            while (parent != Guid.Empty)
            {
                if (!seen.Add(parent) || !map.TryGetValue(parent, out var parentEntry) || !parentEntry.IsDirectory || ++depth > 1024)
                {
                    throw new NingRanException("保险箱目录的上下级关系不正确。");
                }
                parent = parentEntry.ParentId;
            }
        }
    }

    private static async Task WriteChunkAsync(
        string vaultPath,
        VaultInfo info,
        Guid fileId,
        long chunkIndex,
        ReadOnlyMemory<byte> plaintext,
        int plainLength,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
        var header = new byte[ChunkHeaderSize];
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[CryptoSizes.Tag];
        try
        {
            ChunkMagic.CopyTo(header);
            info.VaultId.TryWriteBytes(header.AsSpan(8, 16));
            fileId.TryWriteBytes(header.AsSpan(24, 16));
            BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(40, 8), chunkIndex);
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(48, 4), plainLength);
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(52, 4), plaintext.Length);
            nonce.CopyTo(header.AsSpan(56, CryptoSizes.Nonce));
            using (var cipher = new ChaCha20Poly1305(dataKey.Span))
            {
                cipher.Encrypt(nonce, plaintext.Span, ciphertext, tag, header);
            }

            var path = Path.Combine(GetFileDirectory(vaultPath, fileId), $"{chunkIndex:D8}.nrc");
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
            await output.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async Task<VaultChunk> ReadChunkAsync(
        string vaultPath,
        VaultInfo info,
        VaultCatalogEntry entry,
        int chunkIndex,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        var path = Path.Combine(GetFileDirectory(vaultPath, entry.Id), $"{chunkIndex:D8}.nrc");
        var header = new byte[ChunkHeaderSize];
        byte[]? ciphertext = null;
        byte[]? plaintext = null;
        var tag = new byte[CryptoSizes.Tag];
        try
        {
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess);
            await input.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            var plainLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(48, 4));
            var storedLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(52, 4));
            var expectedPlainLength = checked((int)Math.Min(ChunkSize, entry.Length - (long)chunkIndex * ChunkSize));
            var expectedStoredLength = info.SizeProtection == VaultSizeProtection.HideExactSize
                ? ChunkSize
                : expectedPlainLength;
            if (!header.AsSpan(0, 8).SequenceEqual(ChunkMagic) ||
                new Guid(header.AsSpan(8, 16)) != info.VaultId ||
                new Guid(header.AsSpan(24, 16)) != entry.Id ||
                BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(40, 8)) != chunkIndex ||
                chunkIndex < 0 || chunkIndex >= entry.ChunkCount ||
                plainLength != expectedPlainLength || storedLength != expectedStoredLength ||
                input.Length != ChunkHeaderSize + (long)storedLength + CryptoSizes.Tag)
            {
                throw new NingRanException($"保险箱文件“{entry.Name}”的第 {chunkIndex + 1} 段格式不正确。");
            }

            ciphertext = new byte[storedLength];
            plaintext = new byte[storedLength];
            await input.ReadExactlyAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false);
            try
            {
                using var cipher = new ChaCha20Poly1305(dataKey.Span);
                cipher.Decrypt(header.AsSpan(56, CryptoSizes.Nonce), ciphertext, tag, plaintext, header);
            }
            catch (CryptographicException exception)
            {
                throw new NingRanException($"保险箱文件“{entry.Name}”的第 {chunkIndex + 1} 段未通过完整性检查。", exception);
            }

            var result = plaintext;
            plaintext = null;
            return new VaultChunk(result, plainLength);
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or EndOfStreamException)
        {
            throw new NingRanException($"无法读取保险箱文件“{entry.Name}”的第 {chunkIndex + 1} 段。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private sealed record VaultChunk(byte[] Bytes, int PlainLength);
}

internal sealed record VaultCatalogEntry(
    Guid Id,
    Guid ParentId,
    string Name,
    bool IsDirectory,
    long Length,
    long LastWriteUtcTicks,
    int ChunkCount,
    int[]? BlockSlots = null)
{
    public string RelativePath { get; set; } = Name;
}
