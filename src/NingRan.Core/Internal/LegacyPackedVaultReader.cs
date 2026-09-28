using System.IO.Compression;
using System.Security.Cryptography;

namespace NingRan.Core.Internal;

/// <summary>
/// Reads an old ZIP-backed single-file vault a single encrypted entry at a time.
/// Only encrypted metadata or one encrypted data block is written to the temporary directory;
/// plaintext remains in bounded memory.
/// </summary>
internal sealed class LegacyPackedVaultReader : IDisposable
{
    private readonly FileStream _containerStream;
    private readonly ZipArchive _archive;
    private readonly IReadOnlyDictionary<string, ZipArchiveEntry> _entries;
    private readonly string _temporaryRoot;
    private readonly VaultInfo _temporaryInfo;
    private bool _disposed;

    public LegacyPackedVaultReader(string containerPath, VaultInfo info)
    {
        ContainerPath = VaultFormat.NormalizeVaultPath(containerPath);
        if (!File.Exists(ContainerPath) || FixedVaultContainer.IsFormat(ContainerPath))
            throw new NingRanException("请选择旧版单文件保险箱进行升级。");
        _temporaryRoot = Path.Combine(Path.GetTempPath(), "NingRanVaultUpgrade", $"{info.VaultId:N}-{Guid.NewGuid():N}");
        _temporaryInfo = info with { VaultPath = _temporaryRoot };
        try
        {
            _containerStream = new FileStream(ContainerPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.RandomAccess);
            _archive = new ZipArchive(_containerStream, ZipArchiveMode.Read, leaveOpen: false);
            var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
            foreach (var entry in _archive.Entries)
            {
                var name = entry.FullName.Replace('\\', '/');
                if (string.IsNullOrEmpty(name) || name.EndsWith('/')) continue;
                if (name.StartsWith('/') || name.Split('/').Any(part => part is "" or "." or ".."))
                    throw new NingRanException("旧版保险箱包含不安全的内部路径，程序没有读取或修改它。");
                if (!entries.TryAdd(name, entry))
                    throw new NingRanException("旧版保险箱包含重复的内部项目，无法安全升级。");
            }
            _entries = entries;
            Directory.CreateDirectory(_temporaryRoot);
        }
        catch
        {
            try { _archive?.Dispose(); } catch { }
            try { _containerStream?.Dispose(); } catch { }
            TryDeleteTemporaryRoot();
            throw;
        }
    }

    public string ContainerPath { get; }

    public async Task<byte[]> ReadKeyHeaderAsync(CancellationToken cancellationToken)
    {
        var entry = GetRequiredEntry("vault.keys");
        if (entry.Length <= 0 || entry.Length > FixedVaultContainer.KeyAreaSize - sizeof(int))
            throw new NingRanException("旧版保险箱保护信息大小不正确。");
        var bytes = new byte[checked((int)entry.Length)];
        try
        {
            await using var input = entry.Open();
            await input.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            if (input.ReadByte() != -1) throw new NingRanException("旧版保险箱保护信息长度不正确。");
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    public async Task<(IReadOnlyList<VaultCatalogEntry> Entries, long Revision)> ReadCatalogAsync(
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        var path = Path.Combine(_temporaryRoot, "catalog", "current.nrcat");
        await ExtractEncryptedEntryAsync("catalog/current.nrcat", path, 64L * 1024 * 1024 + 1024, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return await VaultFormat.ReadCatalogAsync(_temporaryRoot, _temporaryInfo, dataKey, cancellationToken)
                .ConfigureAwait(false);
        }
        finally { TryDeleteFile(path); }
    }

    public Stream OpenPlaintextStream(
        VaultCatalogEntry entry,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken) =>
        new LegacyVaultPlaintextStream(this, entry, dataKey, cancellationToken);

    internal async Task<byte[]> ReadPlainChunkAsync(
        VaultCatalogEntry entry,
        int chunkIndex,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (entry.IsDirectory || chunkIndex < 0 || chunkIndex >= entry.ChunkCount)
            throw new NingRanException("旧版保险箱的数据分段编号不正确。");
        var id = entry.Id.ToString("N");
        var relative = $"data/{id[..2]}/{id}/{chunkIndex:D8}.nrc";
        var local = Path.Combine(VaultFormat.GetFileDirectory(_temporaryRoot, entry.Id), $"{chunkIndex:D8}.nrc");
        await ExtractEncryptedEntryAsync(relative, local, VaultFormat.ChunkSize + 4096L, cancellationToken)
            .ConfigureAwait(false);
        var plainLength = checked((int)Math.Min(
            VaultFormat.ChunkSize,
            entry.Length - (long)chunkIndex * VaultFormat.ChunkSize));
        var plaintext = new byte[plainLength];
        try
        {
            var read = await VaultFormat.ReadFileAtAsync(
                _temporaryRoot,
                _temporaryInfo,
                entry,
                (long)chunkIndex * VaultFormat.ChunkSize,
                plaintext,
                dataKey,
                cancellationToken).ConfigureAwait(false);
            if (read != plainLength) throw new NingRanException("旧版保险箱的数据分段没有完整读出。");
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            TryDeleteFile(local);
            TryDeleteEmptyParents(Path.GetDirectoryName(local));
        }
    }

    private async Task ExtractEncryptedEntryAsync(
        string relativeName,
        string destination,
        long maximumLength,
        CancellationToken cancellationToken)
    {
        var entry = GetRequiredEntry(relativeName);
        if (entry.Length < 0 || entry.Length > maximumLength)
            throw new NingRanException("旧版保险箱中的加密分段大小不正确。");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = destination + $".{Guid.NewGuid():N}.part";
        try
        {
            await using var input = entry.Open();
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             1024 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await input.CopyToAsync(output, 1024 * 1024, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            if (new FileInfo(temporary).Length != entry.Length)
                throw new NingRanException("旧版保险箱中的加密分段没有完整读出。");
            File.Move(temporary, destination, overwrite: false);
        }
        finally { TryDeleteFile(temporary); }
    }

    private ZipArchiveEntry GetRequiredEntry(string name)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _entries.TryGetValue(name, out var entry)
            ? entry
            : throw new NingRanException($"旧版保险箱缺少必要的内部项目：{name}");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _archive.Dispose();
        _containerStream.Dispose();
        TryDeleteTemporaryRoot();
    }

    private void TryDeleteTemporaryRoot()
    {
        try { if (Directory.Exists(_temporaryRoot)) Directory.Delete(_temporaryRoot, recursive: true); } catch { }
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private void TryDeleteEmptyParents(string? directory)
    {
        while (!string.IsNullOrEmpty(directory) &&
               !string.Equals(directory, _temporaryRoot, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                if (Directory.EnumerateFileSystemEntries(directory).Any()) break;
                Directory.Delete(directory);
                directory = Path.GetDirectoryName(directory);
            }
            catch { break; }
        }
    }
}

internal sealed class LegacyVaultPlaintextStream : Stream
{
    private readonly LegacyPackedVaultReader _reader;
    private readonly VaultCatalogEntry _entry;
    private readonly ReadOnlyMemory<byte> _dataKey;
    private readonly CancellationToken _operationToken;
    private byte[]? _cachedChunk;
    private int _cachedChunkIndex = -1;
    private long _position;
    private bool _disposed;

    public LegacyVaultPlaintextStream(
        LegacyPackedVaultReader reader,
        VaultCatalogEntry entry,
        ReadOnlyMemory<byte> dataKey,
        CancellationToken operationToken)
    {
        _reader = reader;
        _entry = entry;
        _dataKey = dataKey;
        _operationToken = operationToken;
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;
    public override long Length => _entry.Length;
    public override long Position
    {
        get => _position;
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (value < 0 || value > Length) throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_position >= Length || buffer.IsEmpty) return 0;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_operationToken, cancellationToken);
        var remaining = checked((int)Math.Min(buffer.Length, Length - _position));
        var written = 0;
        while (written < remaining)
        {
            linked.Token.ThrowIfCancellationRequested();
            var chunkIndex = checked((int)(_position / VaultFormat.ChunkSize));
            if (_cachedChunkIndex != chunkIndex)
            {
                ClearCache();
                _cachedChunk = await _reader.ReadPlainChunkAsync(_entry, chunkIndex, _dataKey, linked.Token)
                    .ConfigureAwait(false);
                _cachedChunkIndex = chunkIndex;
            }
            var chunkOffset = checked((int)(_position % VaultFormat.ChunkSize));
            var amount = Math.Min(remaining - written, _cachedChunk!.Length - chunkOffset);
            _cachedChunk.AsMemory(chunkOffset, amount).CopyTo(buffer[written..]);
            written += amount;
            _position += amount;
        }
        return written;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var next = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(Length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (next < 0 || next > Length) throw new IOException("读取位置超出旧版保险箱文件范围。");
        _position = next;
        return next;
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;
        ClearCache();
        base.Dispose(disposing);
    }

    private void ClearCache()
    {
        if (_cachedChunk is not null) CryptographicOperations.ZeroMemory(_cachedChunk);
        _cachedChunk = null;
        _cachedChunkIndex = -1;
    }

    public override void Flush() => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
