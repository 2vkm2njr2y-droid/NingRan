using System.Security.Cryptography;
using NingRan.Core.Internal;

namespace NingRan.Core;

/// <summary>
/// 已通过密码、密匙和物理设备验证的加密文件会话。
/// 会话只保存加密文件句柄和内存中的数据密钥，不会创建明文临时文件。
/// </summary>
public sealed class SecureArchiveSession : IDisposable
{
    private readonly FileStream _input;
    private readonly ArchiveHeader _header;
    private byte[]? _dataKey;
    private readonly IndexedPayloadContainer.IndexedPayload _payload;
    private readonly PhysicalDeviceUnlock? _physicalUnlock;
    private readonly PhysicalDeviceMonitor? _physicalMonitor;
    private readonly Dictionary<string, IndexedPayloadContainer.IndexedPayloadEntry> _entries;
    private bool _disposed;

    internal SecureArchiveSession(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayloadContainer.IndexedPayload payload,
        PhysicalDeviceUnlock? physicalUnlock,
        PhysicalDeviceMonitor? physicalMonitor,
        string verifiedSenderName)
    {
        _input = input;
        _header = header;
        _dataKey = dataKey;
        _payload = payload;
        _physicalUnlock = physicalUnlock;
        _physicalMonitor = physicalMonitor;
        VerifiedSenderName = verifiedSenderName;
        _entries = payload.Entries.ToDictionary(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase);
        Entries = payload.Entries.Select(entry => new SecureArchiveEntry(
            entry.RelativePath,
            Path.GetFileName(entry.RelativePath),
            entry.Kind == PayloadEntryKind.Directory,
            entry.Length,
            entry.MediaKind)).ToArray();
    }

    public string RootName => _payload.RootName;
    public bool IsDirectory => _payload.IsDirectory;
    public string VerifiedSenderName { get; }
    public IReadOnlyList<SecureArchiveEntry> Entries { get; }
    public CancellationToken CancellationToken => _physicalMonitor?.Token ?? CancellationToken.None;

    public Stream OpenEntryReadStream(string relativePath)
    {
        var entry = GetFileEntry(relativePath);
        ThrowIfDisposed();
        return new SecureArchiveReadStream(this, entry);
    }

    public async Task ExportEntryAsync(string relativePath, string outputPath, CancellationToken cancellationToken = default)
    {
        var entry = GetFileEntry(relativePath);
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        var finalPath = Path.GetFullPath(outputPath);
        if (File.Exists(finalPath) || Directory.Exists(finalPath))
        {
            throw new NingRanException("导出位置已经有同名文件，请更换名称。");
        }

        var directory = Path.GetDirectoryName(finalPath) ?? throw new NingRanException("导出位置不正确。");
        Directory.CreateDirectory(directory);
        using var directoryLock = WindowsFileSystemSafety.LockDirectoryPath(directory);
        var temporaryPath = Path.Combine(directory, $".ningran-export-{Guid.NewGuid():N}.part");
        FileStream? output = null;
        try
        {
            output = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath);
            await CopyEntryAsync(entry, output, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
            WindowsFileSystemSafety.RenameOpenFile(output.SafeFileHandle, temporaryPath, finalPath);
            output.Dispose();
            output = null;
            File.SetLastWriteTimeUtc(finalPath, new DateTime(entry.LastWriteUtcTicks, DateTimeKind.Utc));
        }
        catch
        {
            if (output is not null)
            {
                try
                {
                    WindowsFileSystemSafety.DeleteOpenFile(output.SafeFileHandle, temporaryPath);
                }
                catch
                {
                    // 用户选择导出的临时明文会在下次启动时继续清理。
                }
            }

            throw;
        }
        finally
        {
            output?.Dispose();
        }
    }

    public async Task<DecryptionResult> ExportAllAsync(
        string destinationDirectory,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var destination = Path.GetFullPath(destinationDirectory);
        Directory.CreateDirectory(destination);
        using var destinationLock = WindowsFileSystemSafety.LockDirectoryPath(destination);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        var token = linked.Token;
        var totalBlocks = Math.Max(_payload.TotalBlockCount, 1);
        progress?.Report(new CryptoProgress(CryptoStage.Verifying, 0, totalBlocks, "正在完整验证加密内容，不创建文件…"));
        await IndexedPayloadContainer.ValidateAllAsync(
            _input,
            _header,
            _dataKey!,
            _payload,
            (completed, message) => progress?.Report(new CryptoProgress(CryptoStage.Verifying, completed, totalBlocks, message)),
            token).ConfigureAwait(false);

        var staging = SecureStagingArea.Create(destination);
        try
        {
            var directoryTimes = new List<(string Path, long Ticks)>();
            long completed = 0;
            var totalBytes = Math.Max(_payload.Entries.Where(entry => entry.Kind == PayloadEntryKind.File).Sum(entry => entry.Length), 1);
            foreach (var entry in _payload.Entries)
            {
                token.ThrowIfCancellationRequested();
                var stagingPath = PathSafety.GetSafeDestination(staging.PayloadDirectory, entry.RelativePath);
                if (entry.Kind == PayloadEntryKind.Directory)
                {
                    Directory.CreateDirectory(stagingPath);
                    directoryTimes.Add((stagingPath, entry.LastWriteUtcTicks));
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(stagingPath)!);
                await using (var output = new FileStream(
                                 stagingPath,
                                 FileMode.CreateNew,
                                 FileAccess.Write,
                                 FileShare.None,
                                 IndexedPayloadContainer.BlockSize,
                                 FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await CopyEntryAsync(entry, output, token).ConfigureAwait(false);
                    await output.FlushAsync(token).ConfigureAwait(false);
                }

                File.SetLastWriteTimeUtc(stagingPath, new DateTime(entry.LastWriteUtcTicks, DateTimeKind.Utc));
                completed = checked(completed + entry.Length);
                progress?.Report(new CryptoProgress(CryptoStage.Decrypting, completed, totalBytes, $"正在还原：{entry.RelativePath}"));
            }

            for (var index = directoryTimes.Count - 1; index >= 0; index--)
            {
                var directory = directoryTimes[index];
                Directory.SetLastWriteTimeUtc(directory.Path, new DateTime(directory.Ticks, DateTimeKind.Utc));
            }

            token.ThrowIfCancellationRequested();
            var stagedRoot = PathSafety.GetSafeDestination(staging.PayloadDirectory, RootName);
            if (IsDirectory ? !Directory.Exists(stagedRoot) : !File.Exists(stagedRoot))
            {
                throw new NingRanException("还原后的内容不完整，未找到根文件或根文件夹。");
            }

            var finalPath = PathSafety.GetUniquePath(Path.Combine(destination, RootName));
            progress?.Report(new CryptoProgress(CryptoStage.Finalizing, totalBytes, totalBytes, "正在完成还原…"));
            if (IsDirectory) Directory.Move(stagedRoot, finalPath);
            else File.Move(stagedRoot, finalPath);
            staging.MarkPayloadMoved();
            staging.TryCleanup(out _);
            return new DecryptionResult(finalPath, IsDirectory, VerifiedSenderName);
        }
        catch (Exception exception)
        {
            if (!staging.TryCleanup(out var cleanupError))
            {
                throw new NingRanException(
                    "导出没有完成，而且临时明文未能自动删除。请关闭程序并重新打开，让程序再次尝试安全清理。",
                    new AggregateException(exception, cleanupError!));
            }

            throw;
        }
    }

    internal async Task ReadEntryBlockAsync(
        IndexedPayloadContainer.IndexedPayloadEntry entry,
        long blockOffset,
        byte[] ciphertext,
        byte[] tag,
        byte[] plaintext,
        ChaCha20Poly1305 cipher,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (blockOffset < 0 || blockOffset >= entry.DataBlockCount)
        {
            throw new ArgumentOutOfRangeException(nameof(blockOffset));
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        await IndexedPayloadContainer.ReadEntryBlockAsync(
            _input,
            _header,
            _dataKey!,
            _payload,
            checked(entry.DataBlockStart + blockOffset),
            ciphertext,
            tag,
            plaintext,
            cipher,
            linked.Token).ConfigureAwait(false);
    }

    internal ChaCha20Poly1305 CreateCipher()
    {
        ThrowIfDisposed();
        return new ChaCha20Poly1305(_dataKey!);
    }

    private async Task CopyEntryAsync(
        IndexedPayloadContainer.IndexedPayloadEntry entry,
        Stream output,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        await IndexedPayloadContainer.CopyEntryToStreamAsync(
            _input,
            _header,
            _dataKey!,
            _payload,
            entry,
            output,
            linked.Token).ConfigureAwait(false);
    }

    private IndexedPayloadContainer.IndexedPayloadEntry GetFileEntry(string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        if (!_entries.TryGetValue(relativePath, out var entry) || entry.Kind != PayloadEntryKind.File)
        {
            throw new NingRanException("未找到要打开的普通文件。");
        }

        return entry;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_physicalMonitor is not null)
        {
            _physicalMonitor.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        _physicalUnlock?.Dispose();
        _input.Dispose();
        _payload.Dispose();
        if (_dataKey is not null)
        {
            CryptographicOperations.ZeroMemory(_dataKey);
            _dataKey = null;
        }

        CryptographicOperations.ZeroMemory(_header.Bytes);
        CryptographicOperations.ZeroMemory(_header.PayloadNoncePrefix);
        CryptographicOperations.ZeroMemory(_header.HeaderHash);
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

public sealed record SecureArchiveEntry(
    string RelativePath,
    string Name,
    bool IsDirectory,
    long Length,
    SecureMediaKind? MediaKind);

internal sealed class SecureArchiveReadStream : Stream
{
    private readonly SecureArchiveSession _session;
    private readonly IndexedPayloadContainer.IndexedPayloadEntry _entry;
    private readonly byte[] _ciphertext = new byte[IndexedPayloadContainer.BlockSize];
    private readonly byte[] _tag = new byte[16];
    private readonly byte[] _plaintext = new byte[IndexedPayloadContainer.BlockSize];
    private readonly ChaCha20Poly1305 _cipher;
    private long _position;
    private long _loadedBlock = -1;
    private bool _disposed;

    public SecureArchiveReadStream(SecureArchiveSession session, IndexedPayloadContainer.IndexedPayloadEntry entry)
    {
        _session = session;
        _entry = entry;
        _cipher = session.CreateCipher();
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
            if (value < 0 || value > Length) throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty || _position >= Length) return 0;
        var wanted = (int)Math.Min(buffer.Length, Length - _position);
        var copied = 0;
        while (copied < wanted)
        {
            var block = _position / IndexedPayloadContainer.BlockSize;
            var offset = (int)(_position % IndexedPayloadContainer.BlockSize);
            if (_loadedBlock != block)
            {
                await _session.ReadEntryBlockAsync(_entry, block, _ciphertext, _tag, _plaintext, _cipher, cancellationToken)
                    .ConfigureAwait(false);
                _loadedBlock = block;
            }

            var count = Math.Min(wanted - copied, IndexedPayloadContainer.BlockSize - offset);
            _plaintext.AsMemory(offset, count).CopyTo(buffer[copied..]);
            copied += count;
            _position += count;
        }

        return copied;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(Length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0 || target > Length) throw new IOException("读取位置超出文件范围。");
        _position = target;
        return target;
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _cipher.Dispose();
            CryptographicOperations.ZeroMemory(_ciphertext);
            CryptographicOperations.ZeroMemory(_tag);
            CryptographicOperations.ZeroMemory(_plaintext);
        }

        _disposed = true;
        base.Dispose(disposing);
    }

    public override void Flush() => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
