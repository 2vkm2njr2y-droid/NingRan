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
    private readonly SensitiveMemoryLock _dataKeyMemory;
    private readonly IndexedPayloadContainer.IndexedPayload _payload;
    private readonly PhysicalDeviceUnlock? _physicalUnlock;
    private readonly PhysicalDeviceMonitor? _physicalMonitor;
    private readonly Dictionary<string, IndexedPayloadContainer.IndexedPayloadEntry> _entries;
    private readonly long _archiveOffset;
    private readonly long _archiveLength;
    private readonly CancellationTokenSource _sessionCancellation;
    private Timer? _expirationTimer;
    private bool _disposed;

    internal SecureArchiveSession(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayloadContainer.IndexedPayload payload,
        PhysicalDeviceUnlock? physicalUnlock,
        PhysicalDeviceMonitor? physicalMonitor,
        string verifiedSenderName,
        bool senderIsTrusted,
        string archivePath,
        long archiveOffset,
        long archiveLength,
        long incrementalBaseLength = 0,
        long incrementalNextBlockIndex = 0,
        long incrementalGeneration = 0,
        long incrementalLastSegmentStart = -1)
    {
        _input = input;
        _header = header;
        _dataKey = dataKey;
        _dataKeyMemory = SensitiveMemoryLock.Create(dataKey);
        _payload = payload;
        _physicalUnlock = physicalUnlock;
        _physicalMonitor = physicalMonitor;
        VerifiedSenderName = verifiedSenderName;
        SenderIsTrusted = senderIsTrusted;
        ArchivePath = archivePath;
        _archiveOffset = archiveOffset;
        _archiveLength = archiveLength;
        IncrementalBaseLength = incrementalBaseLength;
        IncrementalNextBlockIndex = incrementalNextBlockIndex;
        IncrementalGeneration = incrementalGeneration;
        IncrementalLastSegmentStart = incrementalLastSegmentStart;
        _entries = payload.Entries.ToDictionary(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase);
        Entries = payload.Entries.Select(entry => new SecureArchiveEntry(
            entry.RelativePath,
            Path.GetFileName(entry.RelativePath),
            entry.Kind == PayloadEntryKind.Directory,
            entry.Length,
            entry.MediaKind ?? NrMediaFiles.TryGetKind(entry.RelativePath),
            entry.LastWriteUtcTicks)).ToArray();
        _sessionCancellation = physicalMonitor is null
            ? new CancellationTokenSource()
            : CancellationTokenSource.CreateLinkedTokenSource(physicalMonitor.Token);
        ScheduleExpirationCheck();
    }

    public string RootName => _payload.RootName;
    public bool IsDirectory => _payload.IsDirectory;
    public EncryptionMode Mode => _header.Mode;
    public string ArchivePath { get; }
    public bool IsOpen => !_disposed;
    public string VerifiedSenderName { get; }
    public bool SenderIsTrusted { get; }
    public IReadOnlyList<SecureArchiveEntry> Entries { get; }
    public DeliveryPackageInfo? DeliveryInfo => _payload.DeliveryInfo;
    public bool IsDelivery => DeliveryInfo is not null;
    public bool IsExpired => DeliveryInfo?.IsExpiredAt(DateTimeOffset.UtcNow) == true;
    public bool CanExportPlaintext => !IsExpired && (DeliveryInfo?.AllowExport ?? true);
    public ArchiveSizeReport SizeReport => IndexedPayloadContainer.CreateSizeReport(_payload, _archiveLength);
    public CancellationToken CancellationToken => _sessionCancellation.Token;
    internal long ArchiveOffset => _archiveOffset;
    internal long ArchiveLength => _archiveLength;
    internal FileStream ArchiveFile => _input;
    internal ArchiveHeader Header => _header;
    internal byte[] DataKey => _dataKey ?? throw new ObjectDisposedException(nameof(SecureArchiveSession));
    internal IndexedPayloadContainer.IndexedPayload Payload => _payload;
    internal long IncrementalBaseLength { get; }
    internal long IncrementalNextBlockIndex { get; }
    internal long IncrementalGeneration { get; }
    internal long IncrementalLastSegmentStart { get; }

    public Stream OpenEntryReadStream(string relativePath)
    {
        EnsureContentAccessAllowed();
        var entry = GetFileEntry(relativePath);
        return new SecureArchiveReadStream(this, entry);
    }

    public async Task ExportEntryAsync(string relativePath, string outputPath, CancellationToken cancellationToken = default)
    {
        EnsurePlaintextExportAllowed();
        var entry = GetFileEntry(relativePath);
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
        EnsurePlaintextExportAllowed();
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
            token,
            _archiveOffset).ConfigureAwait(false);

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

    /// <summary>
    /// 将当前已打开的加密内容导出为可移动的普通 .nrenc 加密包，不会创建明文。
    /// </summary>
    public async Task<string> ExportEncryptedArchiveAsync(
        string outputPath,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        var finalPath = Path.GetFullPath(outputPath);
        if (!string.Equals(Path.GetExtension(finalPath), ".nrenc", StringComparison.OrdinalIgnoreCase))
        {
            finalPath += ".nrenc";
        }

        if (File.Exists(finalPath) || Directory.Exists(finalPath))
        {
            throw new NingRanException("导出位置已经有同名文件，请更换名称。");
        }

        var directory = Path.GetDirectoryName(finalPath)
            ?? throw new NingRanException("导出位置不正确。");
        Directory.CreateDirectory(directory);
        using var directoryLock = WindowsFileSystemSafety.LockDirectoryPath(directory);
        var temporaryPath = Path.Combine(directory, $".ningran-package-{Guid.NewGuid():N}.part");
        FileStream? output = null;
        byte[]? buffer = null;
        try
        {
            output = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath);
            // A photo archive reads from its NTFS hidden stream. Copy only the
            // encrypted archive region so the exported file is always a normal .nrenc.
            _input.Position = _archiveOffset;
            var totalBytes = Math.Max(_archiveLength, 1);
            var copiedBytes = 0L;
            var remainingBytes = _archiveLength;
            buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(IndexedPayloadContainer.BlockSize);
            progress?.Report(new CryptoProgress(CryptoStage.Finalizing, 0, totalBytes, "正在导出加密包…"));
            while (remainingBytes > 0)
            {
                var requested = (int)Math.Min(buffer.Length, remainingBytes);
                var read = await _input.ReadAsync(buffer.AsMemory(0, requested), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("加密内容读取不完整，无法导出加密包。");
                }

                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                copiedBytes = checked(copiedBytes + read);
                remainingBytes -= read;
                progress?.Report(new CryptoProgress(CryptoStage.Finalizing, copiedBytes, totalBytes, "正在导出加密包…"));
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
            WindowsFileSystemSafety.RenameOpenFile(output.SafeFileHandle, temporaryPath, finalPath);
            output.Dispose();
            output = null;
            return finalPath;
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
                    // 加密包临时文件会在下次启动时继续清理。
                }
            }

            throw;
        }
        finally
        {
            if (buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
                System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
            }

            output?.Dispose();
        }
    }

    /// <summary>
    /// 导出文件树中的一个文件，或将选中的文件夹及其所有内容作为独立副本导出。
    /// </summary>
    public async Task<DecryptionResult> ExportSelectionAsync(
        string relativePath,
        string destinationDirectory,
        string? outputName = null,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        EnsurePlaintextExportAllowed();
        var selected = GetArchiveEntry(relativePath);
        var destination = Path.GetFullPath(destinationDirectory);
        Directory.CreateDirectory(destination);
        using var destinationLock = WindowsFileSystemSafety.LockDirectoryPath(destination);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        var token = linked.Token;
        var selectedPath = selected.RelativePath;
        var selectedIsDirectory = selected.Kind == PayloadEntryKind.Directory;
        var selectedEntries = _payload.Entries
            .Where(entry => string.Equals(entry.RelativePath, selectedPath, StringComparison.OrdinalIgnoreCase) ||
                            selectedIsDirectory && entry.RelativePath.StartsWith(selectedPath + "/", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var name = PathSafety.ValidateNameSegment(outputName ?? Path.GetFileName(selectedPath));
        var totalBlocks = Math.Max(_payload.TotalBlockCount, 1);
        progress?.Report(new CryptoProgress(CryptoStage.Verifying, 0, totalBlocks, "正在完整验证加密内容，不创建文件…"));
        await IndexedPayloadContainer.ValidateAllAsync(
            _input,
            _header,
            _dataKey!,
            _payload,
            (completed, message) => progress?.Report(new CryptoProgress(CryptoStage.Verifying, completed, totalBlocks, message)),
            token,
            _archiveOffset).ConfigureAwait(false);

        var staging = SecureStagingArea.Create(destination);
        try
        {
            var directoryTimes = new List<(string Path, long Ticks)>();
            var totalBytes = Math.Max(selectedEntries.Where(entry => entry.Kind == PayloadEntryKind.File).Sum(entry => entry.Length), 1);
            long completed = 0;
            foreach (var entry in selectedEntries)
            {
                token.ThrowIfCancellationRequested();
                var suffix = string.Equals(entry.RelativePath, selectedPath, StringComparison.OrdinalIgnoreCase)
                    ? string.Empty
                    : entry.RelativePath[selectedPath.Length..];
                var stagingPath = PathSafety.GetSafeDestination(staging.PayloadDirectory, name + suffix);
                if (entry.Kind == PayloadEntryKind.Directory)
                {
                    Directory.CreateDirectory(stagingPath);
                    directoryTimes.Add((stagingPath, entry.LastWriteUtcTicks));
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(stagingPath)!);
                await using var output = new FileStream(
                    stagingPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    IndexedPayloadContainer.BlockSize,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
                await CopyEntryAsync(entry, output, token).ConfigureAwait(false);
                await output.FlushAsync(token).ConfigureAwait(false);
                File.SetLastWriteTimeUtc(stagingPath, DateTime.SpecifyKind(new DateTime(entry.LastWriteUtcTicks), DateTimeKind.Utc));
                completed = checked(completed + entry.Length);
                progress?.Report(new CryptoProgress(CryptoStage.Decrypting, completed, totalBytes, $"正在导出：{entry.RelativePath}"));
            }

            for (var index = directoryTimes.Count - 1; index >= 0; index--)
            {
                var directory = directoryTimes[index];
                Directory.SetLastWriteTimeUtc(directory.Path, new DateTime(directory.Ticks, DateTimeKind.Utc));
            }

            token.ThrowIfCancellationRequested();
            var stagedRoot = PathSafety.GetSafeDestination(staging.PayloadDirectory, name);
            if (selectedIsDirectory ? !Directory.Exists(stagedRoot) : !File.Exists(stagedRoot))
            {
                throw new NingRanException("导出的内容不完整，未找到文件或文件夹。");
            }

            var finalPath = PathSafety.GetUniquePath(Path.Combine(destination, name));
            progress?.Report(new CryptoProgress(CryptoStage.Finalizing, totalBytes, totalBytes, "正在完成导出…"));
            if (selectedIsDirectory) Directory.Move(stagedRoot, finalPath);
            else File.Move(stagedRoot, finalPath);
            staging.MarkPayloadMoved();
            staging.TryCleanup(out _);
            return new DecryptionResult(finalPath, selectedIsDirectory, VerifiedSenderName);
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
        EnsureContentAccessAllowed();
        if (blockOffset < 0 || blockOffset >= entry.Blocks.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(blockOffset));
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        await IndexedPayloadContainer.ReadEntryBlockAsync(
            _input,
            _header,
            _dataKey!,
            _payload,
            entry,
            blockOffset,
            ciphertext,
            tag,
            plaintext,
            cipher,
            linked.Token,
            _archiveOffset).ConfigureAwait(false);
    }

    internal ChaCha20Poly1305 CreateCipher()
    {
        ThrowIfDisposed();
        return new ChaCha20Poly1305(_dataKey!);
    }

    /// <summary>完整校验全部加密分段，不创建或导出明文。</summary>
    public async Task ValidateAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        await IndexedPayloadContainer.ValidateAllAsync(
                _input, _header, _dataKey!, _payload, null, linked.Token, _archiveOffset)
            .ConfigureAwait(false);
    }

    internal PayloadManifest CreateRebuildManifest(
        IReadOnlySet<string> pathsToRemove,
        IReadOnlyList<(PayloadManifest Manifest, string TargetDirectory, string? TargetName)> additions,
        SizePaddingMode sizePadding)
    {
        ThrowIfDisposed();
        var entries = new List<PayloadEntry>();
        foreach (var original in _payload.Entries)
        {
            if (pathsToRemove.Any(path => string.Equals(original.RelativePath, path, StringComparison.OrdinalIgnoreCase) ||
                                          original.RelativePath.StartsWith(path + "/", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var path = original.RelativePath;
            entries.Add(new PayloadEntry(original.Kind, path, path, original.Length, original.LastWriteUtcTicks,
                default, null,
                original.Kind == PayloadEntryKind.File
                    ? cancellationToken => new ValueTask<Stream>(OpenEntryReadStream(path))
                    : null));
        }

        foreach (var (manifest, targetDirectory, targetName) in additions)
        {
            var target = PathSafety.NormalizeRelativePath(targetDirectory);
            var destinationRoot = PathSafety.NormalizeRelativePath(target + "/" +
                PathSafety.ValidateNameSegment(targetName ?? manifest.RootName));
            foreach (var entry in manifest.Entries)
            {
                var suffix = entry.RelativePath[manifest.RootName.Length..];
                var destination = PathSafety.NormalizeRelativePath(destinationRoot + suffix);
                entries.Add(entry with { RelativePath = destination });
            }
        }

        return PayloadManifest.Create(IsDirectory, RootName, entries, sizePadding);
    }

    private async Task CopyEntryAsync(
        IndexedPayloadContainer.IndexedPayloadEntry entry,
        Stream output,
        CancellationToken cancellationToken)
    {
        EnsureContentAccessAllowed();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        await IndexedPayloadContainer.CopyEntryToStreamAsync(
            _input,
            _header,
            _dataKey!,
            _payload,
            entry,
            output,
            linked.Token,
            _archiveOffset).ConfigureAwait(false);
    }

    private IndexedPayloadContainer.IndexedPayloadEntry GetFileEntry(string relativePath)
    {
        var entry = GetArchiveEntry(relativePath);
        if (entry.Kind != PayloadEntryKind.File)
        {
            throw new NingRanException("未找到要打开的普通文件。");
        }

        return entry;
    }

    private IndexedPayloadContainer.IndexedPayloadEntry GetArchiveEntry(string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        if (!_entries.TryGetValue(relativePath, out var entry))
        {
            throw new NingRanException("未找到要导出的文件或文件夹。");
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
        _expirationTimer?.Dispose();
        _expirationTimer = null;
        _sessionCancellation.Cancel();
        _sessionCancellation.Dispose();
        _input.Dispose();
        _payload.Dispose();
        if (_dataKey is not null)
        {
            CryptographicOperations.ZeroMemory(_dataKey);
            _dataKey = null;
        }
        _dataKeyMemory.Dispose();

        CryptographicOperations.ZeroMemory(_header.Bytes);
        CryptographicOperations.ZeroMemory(_header.PayloadNoncePrefix);
        CryptographicOperations.ZeroMemory(_header.HeaderHash);
    }

    internal void EnsureContentAccessAllowed()
    {
        ThrowIfDisposed();
        if (IsExpired)
        {
            throw new NingRanException("此交付包已过期。你仍可查看交付信息和文件列表，但不能打开或导出文件。");
        }
    }

    private void ScheduleExpirationCheck()
    {
        if (DeliveryInfo?.ExpiresAtUtc is not { } expiresAt) return;
        var remaining = expiresAt - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            _sessionCancellation.Cancel();
            return;
        }

        var due = remaining > TimeSpan.FromHours(12) ? TimeSpan.FromHours(12) : remaining;
        _expirationTimer = new Timer(_ =>
        {
            if (_disposed) return;
            var next = expiresAt - DateTimeOffset.UtcNow;
            if (next <= TimeSpan.Zero)
            {
                try { _sessionCancellation.Cancel(); } catch (ObjectDisposedException) { }
                return;
            }

            var nextDue = next > TimeSpan.FromHours(12) ? TimeSpan.FromHours(12) : next;
            try { _expirationTimer?.Change(nextDue, Timeout.InfiniteTimeSpan); }
            catch (ObjectDisposedException) { }
        }, null, due, Timeout.InfiniteTimeSpan);
    }

    private void EnsurePlaintextExportAllowed()
    {
        EnsureContentAccessAllowed();
        if (DeliveryInfo?.AllowExport == false)
        {
            throw new NingRanException("发送方已禁止从此安全交付包导出明文文件。你仍可在凝然内安全查看支持的内容。");
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

public sealed record SecureArchiveEntry(
    string RelativePath,
    string Name,
    bool IsDirectory,
    long Length,
    SecureMediaKind? MediaKind,
    long LastWriteUtcTicks = 0);

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
        _session.EnsureContentAccessAllowed();
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
