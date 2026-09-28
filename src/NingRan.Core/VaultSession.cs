using System.Security.Cryptography;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class VaultSession : IDisposable
{
    private readonly object _catalogGate = new();
    private readonly SemaphoreSlim _mutationGate = new(1, 1);
    private readonly HashSet<Guid> _retiredFileIds = [];
    private byte[]? _dataKey;
    private readonly SensitiveMemoryLock _dataKeyMemory;
    private IReadOnlyList<VaultCatalogEntry> _catalog;
    private IReadOnlyDictionary<string, VaultCatalogEntry> _byPath;
    private IReadOnlyDictionary<Guid, IReadOnlyList<VaultCatalogEntry>> _children;
    private readonly PhysicalDeviceUnlock? _physicalUnlock;
    private readonly PhysicalDeviceMonitor? _physicalMonitor;
    private readonly VaultHistoryStore _history;
    private readonly string _journalPath;
    private string? _singleFilePath;
    private string? _workingPath;
    private bool _disposed;

    internal VaultSession(
        VaultInfo info,
        ArchiveHeader keyHeader,
        byte[] dataKey,
        IReadOnlyList<VaultCatalogEntry> catalog,
        long revision,
        PhysicalDeviceUnlock? physicalUnlock,
        PhysicalDeviceMonitor? physicalMonitor,
        bool embeddedContainer = false)
    {
        Info = info;
        KeyHeader = keyHeader;
        _dataKey = dataKey;
        _dataKeyMemory = SensitiveMemoryLock.Create(dataKey);
        _physicalUnlock = physicalUnlock;
        _physicalMonitor = physicalMonitor;
        Revision = revision;
        (_catalog, _byPath, _children, Entries) = BuildViews(catalog);
        _history = new VaultHistoryStore(
            info.VaultPath,
            embeddedContainer,
            enabled: info.FormatVersion < FixedVaultContainer.FormatVersion);
        _journalPath = info.FormatVersion >= FixedVaultContainer.FormatVersion && File.Exists(info.VaultPath)
            ? Path.Combine(Path.GetTempPath(), "NingRanVault", $"journal-{info.VaultId:N}-{info.WorkspaceRegion?.WorkspaceId.ToString("N") ?? "single"}")
            : Path.Combine(info.VaultPath, "journal");
        ClearAbandonedJournal(_journalPath);
    }

    public VaultInfo Info { get; }
    public string VaultPath => Info.VaultPath;
    public string Name => _singleFilePath is null ? Info.Name : Path.GetFileName(_singleFilePath);
    public EncryptionMode Mode => Info.Mode;
    public bool IsOpen => !_disposed;
    public long Revision { get; private set; }
    public IReadOnlyList<VaultEntry> Entries { get; private set; }
    public CancellationToken CancellationToken => _physicalMonitor?.Token ?? CancellationToken.None;
    public long ContentBytes => Entries.Where(entry => !entry.IsDirectory).Sum(entry => entry.Length);
    public long WorkspaceCapacityBytes => Info.WorkspaceRegion is { } region
        ? WorkspaceVaultContainer.GetRegionCapacityBytes(region.SlotCount)
        : Info.CapacityBytes;
    /// <summary>Space occupied by allocated encrypted data blocks in the currently opened workspace.</summary>
    public long WorkspaceUsedBytes => Entries
        .Where(entry => !entry.IsDirectory)
        .Sum(entry => checked((long)entry.ChunkCount * VaultFormat.ChunkSize));
    public bool TemporaryDriveAllowed => true;
    public long StoredBytesEstimate => EstimateStoredBytes();
    public IReadOnlyList<VaultHistoryEntry> History => _history.List();
    public int HistoryRetentionDays { get => _history.RetentionDays; set => _history.RetentionDays = value; }
    public long HistoryMaximumBytes { get => _history.MaximumBytes; set => _history.MaximumBytes = value; }
    internal void AttachSingleFileContainer(string containerPath, string workingPath)
    {
        _singleFilePath = containerPath;
        _workingPath = workingPath;
    }
    public void DeleteHistory(Guid id) => _history.Delete(id);
    public async Task<VaultEntry> RestoreHistoryAsync(Guid historyId, string targetRelativePath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        var history = _history.Get(historyId);
        var normalized = NormalizeLookupPath(targetRelativePath);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var catalog = Catalog.Select(entry => entry with { }).ToList();
            var existing = FindByPath(catalog, normalized);
            if (existing is not null && !overwrite) throw new NingRanException("目标位置已有同名内容。请先选择覆盖或另存为其他名称。");
            if (existing is not null && existing.IsDirectory) throw new NingRanException("目标位置是文件夹，不能覆盖。");
            var (parentId, name) = ResolveParent(catalog, normalized);
            var restored = new VaultCatalogEntry(Guid.NewGuid(), parentId, name, false, history.Length,
                history.LastWriteTimeUtc.Ticks, history.Length == 0 ? 0 : checked((int)((history.Length + VaultFormat.ChunkSize - 1) / VaultFormat.ChunkSize)));
            _history.CloneSnapshot(historyId, VaultFormat.GetFileDirectory(VaultPath, restored.Id));
            if (existing is null) catalog.Add(restored); else { catalog[catalog.FindIndex(x => x.Id == existing.Id)] = restored; _retiredFileIds.Add(existing.Id); }
            await PublishCatalogAsync(catalog, cancellationToken).ConfigureAwait(false);
            return new VaultEntry(restored.Id, restored.ParentId, restored.Name, normalized, false, restored.Length,
                new DateTime(restored.LastWriteUtcTicks, DateTimeKind.Utc), restored.ChunkCount);
        }
        finally { _mutationGate.Release(); }
    }

    internal ArchiveHeader KeyHeader { get; }
    internal ReadOnlyMemory<byte> DataKey => _dataKey ?? throw new ObjectDisposedException(nameof(VaultSession));
    internal string JournalPath => _journalPath;
    internal IReadOnlyList<VaultCatalogEntry> Catalog
    {
        get
        {
            lock (_catalogGate)
            {
                ThrowIfDisposed();
                return _catalog;
            }
        }
    }

    internal async ValueTask<IDisposable> AcquireExportLockAsync(CancellationToken cancellationToken)
    {
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return new ExportLock(_mutationGate);
        }
        catch
        {
            _mutationGate.Release();
            throw;
        }
    }

    public Stream OpenReadStream(string relativePath)
    {
        ThrowIfDisposed();
        if (!TryGetCatalogEntry(relativePath, out var entry) || entry.IsDirectory)
        {
            throw new NingRanException("保险箱中没有找到所选文件。");
        }
        return new VaultReadStream(this, entry);
    }

    public VaultWriteSession OpenWriteStream(string relativePath, bool createNew = false, bool truncate = false)
    {
        ThrowIfDisposed();
        var normalized = NormalizeLookupPath(relativePath);
        if (string.IsNullOrEmpty(normalized)) throw new NingRanException("不能把保险箱根目录作为文件打开。");
        TryGetCatalogEntry(normalized, out var existing);
        if (createNew && existing is not null) throw new NingRanException("同一文件夹中已经存在同名内容。");
        if (existing?.IsDirectory == true) throw new NingRanException("不能把文件夹作为文件写入。");
        ValidateTargetPath(normalized);
        return new VaultWriteSession(this, normalized, existing, truncate);
    }

    public async Task CreateDirectoryAsync(string relativePath, CancellationToken cancellationToken = default)
    {
        var normalized = NormalizeLookupPath(relativePath);
        if (string.IsNullOrEmpty(normalized)) throw new NingRanException("不能重新创建保险箱根目录。");
        ValidateTargetPath(normalized);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var catalog = Catalog.Select(entry => entry with { }).ToList();
            if (FindByPath(catalog, normalized) is not null) throw new NingRanException("同一文件夹中已经存在同名内容。");
            var (parentId, name) = ResolveParent(catalog, normalized);
            catalog.Add(new VaultCatalogEntry(Guid.NewGuid(), parentId, name, true, 0, DateTime.UtcNow.Ticks, 0));
            await PublishCatalogAsync(catalog, cancellationToken).ConfigureAwait(false);
        }
        finally { _mutationGate.Release(); }
    }

    public async Task MoveAsync(
        string sourceRelativePath,
        string targetRelativePath,
        bool replaceIfExists,
        CancellationToken cancellationToken = default)
    {
        var source = NormalizeLookupPath(sourceRelativePath);
        var target = NormalizeLookupPath(targetRelativePath);
        if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(target)) throw new NingRanException("不能移动保险箱根目录。");
        ValidateTargetPath(target);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var catalog = Catalog.Select(entry => entry with { }).ToList();
            var entry = FindByPath(catalog, source) ?? throw new NingRanException("没有找到要移动的内容。");
            var existing = FindByPath(catalog, target);
            if (existing is not null && existing.Id != entry.Id)
            {
                if (!replaceIfExists) throw new NingRanException("目标位置已经存在同名内容。");
                if (existing.IsDirectory != entry.IsDirectory) throw new NingRanException("文件和文件夹不能互相替换。");
                RemoveSubtree(catalog, existing.Id);
            }
            var (parentId, name) = ResolveParent(catalog, target);
            if (entry.IsDirectory && IsDescendant(catalog, parentId, entry.Id))
            {
                throw new NingRanException("不能把文件夹移动到它自己的内部。");
            }
            var index = catalog.FindIndex(item => item.Id == entry.Id);
            catalog[index] = entry with { ParentId = parentId, Name = name, LastWriteUtcTicks = DateTime.UtcNow.Ticks };
            await PublishCatalogAsync(catalog, cancellationToken).ConfigureAwait(false);
        }
        finally { _mutationGate.Release(); }
    }

    public async Task DeleteAsync(string relativePath, CancellationToken cancellationToken = default)
    {
        const string recycleBinName = "保险箱回收站";
        var normalized = NormalizeLookupPath(relativePath);
        if (string.IsNullOrEmpty(normalized)) throw new NingRanException("不能删除保险箱根目录。");
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var catalog = Catalog.Select(entry => entry with { }).ToList();
            var entry = FindByPath(catalog, normalized) ?? throw new NingRanException("没有找到要删除的内容。");
            if (!entry.IsDirectory)
            {
                _history.Capture(entry, VaultPath, VaultHistoryOperation.Deleted);
            }
            else
            {
                var subtreeIds = new HashSet<Guid> { entry.Id };
                var expanded = true;
                while (expanded)
                {
                    expanded = false;
                    foreach (var child in catalog)
                    {
                        if (subtreeIds.Contains(child.ParentId) && subtreeIds.Add(child.Id)) expanded = true;
                    }
                }
                foreach (var child in catalog.Where(x => subtreeIds.Contains(x.Id) && !x.IsDirectory))
                    _history.Capture(child, VaultPath, VaultHistoryOperation.Deleted);
            }
            var recycle = FindByPath(catalog, recycleBinName);
            var insideRecycle = recycle is not null && (entry.Id == recycle.Id || IsDescendant(catalog, entry.ParentId, recycle.Id));
            if (insideRecycle)
            {
                if (entry.Id == recycle!.Id) throw new NingRanException("不能删除保险箱回收站本身。");
                RemoveSubtree(catalog, entry.Id);
            }
            else
            {
                if (recycle is null)
                {
                    recycle = new VaultCatalogEntry(Guid.NewGuid(), Guid.Empty, recycleBinName, true, 0, DateTime.UtcNow.Ticks, 0);
                    catalog.Add(recycle);
                }
                var name = GetUniqueName(entry.Name, catalog.Where(item => item.ParentId == recycle.Id).Select(item => item.Name));
                var index = catalog.FindIndex(item => item.Id == entry.Id);
                catalog[index] = entry with { ParentId = recycle.Id, Name = name, LastWriteUtcTicks = DateTime.UtcNow.Ticks };
            }
            await PublishCatalogAsync(catalog, cancellationToken).ConfigureAwait(false);
        }
        finally { _mutationGate.Release(); }
    }

    public async Task SetLastWriteTimeAsync(string relativePath, DateTime lastWriteUtc, CancellationToken cancellationToken = default)
    {
        var normalized = NormalizeLookupPath(relativePath);
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var catalog = Catalog.Select(entry => entry with { }).ToList();
            var entry = FindByPath(catalog, normalized) ?? throw new NingRanException("没有找到要更新时间的内容。");
            var index = catalog.FindIndex(item => item.Id == entry.Id);
            catalog[index] = entry with { LastWriteUtcTicks = lastWriteUtc.ToUniversalTime().Ticks };
            await PublishCatalogAsync(catalog, cancellationToken).ConfigureAwait(false);
        }
        finally { _mutationGate.Release(); }
    }

    public bool TryGetEntry(string relativePath, out VaultEntry? entry)
    {
        ThrowIfDisposed();
        var normalized = NormalizeLookupPath(relativePath);
        entry = Entries.FirstOrDefault(item =>
            string.Equals(item.RelativePath, normalized, StringComparison.OrdinalIgnoreCase));
        return entry is not null;
    }

    public IReadOnlyList<VaultEntry> GetChildren(string? directoryRelativePath = null)
    {
        ThrowIfDisposed();
        var parentId = Guid.Empty;
        if (!string.IsNullOrWhiteSpace(directoryRelativePath))
        {
            if (!TryGetCatalogEntry(directoryRelativePath, out var directory) || !directory.IsDirectory)
            {
                return [];
            }
            parentId = directory.Id;
        }

        lock (_catalogGate)
        {
            if (!_children.TryGetValue(parentId, out var children))
            {
                return [];
            }
            var paths = _byPath.ToDictionary(pair => pair.Value.Id, pair => pair.Key);
            return children.Select(item => ToPublicEntry(item, paths[item.Id])).ToArray();
        }
    }

    public async Task VerifyAsync(
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cancellationToken);
        var files = Catalog.Where(entry => !entry.IsDirectory).ToArray();
        var total = Math.Max(files.Sum(entry => entry.Length), 1);
        long completed = 0;
        progress?.Report(new CryptoProgress(CryptoStage.Verifying, 0, total, "正在检查保险箱目录…"));
        foreach (var entry in files)
        {
            await VaultFormat.VerifyFileAsync(
                VaultPath,
                Info,
                entry,
                DataKey,
                (amount, message) =>
                {
                    completed = checked(completed + amount);
                    progress?.Report(new CryptoProgress(CryptoStage.Verifying, completed, total, message));
                },
                linked.Token).ConfigureAwait(false);
        }
        progress?.Report(new CryptoProgress(CryptoStage.Verifying, total, total, "保险箱完整检查通过。"));
    }

    internal bool TryGetCatalogEntry(string relativePath, out VaultCatalogEntry entry)
    {
        var normalized = NormalizeLookupPath(relativePath);
        lock (_catalogGate)
        {
            ThrowIfDisposed();
            return _byPath.TryGetValue(normalized, out entry!);
        }
    }

    internal void ReplaceCatalog(IReadOnlyList<VaultCatalogEntry> catalog, long revision)
    {
        lock (_catalogGate)
        {
            ThrowIfDisposed();
            var views = BuildViews(catalog);
            _catalog = views.Catalog;
            _byPath = views.ByPath;
            _children = views.Children;
            Entries = views.PublicEntries;
            Revision = revision;
        }
    }

    internal async Task CommitWriteAsync(VaultWriteSession write, CancellationToken cancellationToken)
    {
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Guid newId = Guid.Empty;
        try
        {
            ThrowIfDisposed();
            var catalog = Catalog.Select(entry => entry with { }).ToList();
            var current = write.BaseEntry is null
                ? FindByPath(catalog, write.RelativePath)
                : catalog.FirstOrDefault(entry => entry.Id == write.BaseEntry.Id);
            if (write.BaseEntry is null && current is not null) throw new NingRanException("同一文件夹中已经存在同名内容。");
            if (write.BaseEntry is not null && current is null) throw new NingRanException("文件已被其他操作删除，请重新打开后再保存。");
            if (current is not null) _history.Capture(current, VaultPath, VaultHistoryOperation.Modified);
            var (parentId, name) = ResolveParent(catalog, write.RelativePath);
            EnsureFreeSpace(write.Length);
            newId = Guid.NewGuid();
            var replacement = new VaultCatalogEntry(
                newId, parentId, name, false, write.Length, DateTime.UtcNow.Ticks,
                write.Length == 0 ? 0 : checked((int)((write.Length + VaultFormat.ChunkSize - 1) / VaultFormat.ChunkSize)));
            write.Position = 0;
            replacement = await VaultFormat.WriteFileAsync(
                VaultPath, Info, replacement, write, DataKey, catalog, null, cancellationToken).ConfigureAwait(false);
            if (current is null) catalog.Add(replacement);
            else catalog[catalog.FindIndex(entry => entry.Id == current.Id)] = replacement;
            await PublishCatalogAsync(catalog, cancellationToken).ConfigureAwait(false);
            if (current is not null) _retiredFileIds.Add(current.Id);
            write.MarkCommitted(replacement);
        }
        catch (IOException exception) when ((exception.HResult & 0xFFFF) is 0x27 or 0x70)
        {
            if (newId != Guid.Empty) TryDeleteFileData(newId);
            throw new NingRanException("保险箱所在磁盘空间不足，原文件没有改变。", exception);
        }
        catch
        {
            if (newId != Guid.Empty) TryDeleteFileData(newId);
            throw;
        }
        finally { _mutationGate.Release(); }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (_physicalMonitor is not null)
        {
            _physicalMonitor.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        _physicalUnlock?.Dispose();
        var key = Interlocked.Exchange(ref _dataKey, null);
        if (key is not null)
        {
            CryptographicOperations.ZeroMemory(key);
        }
        _dataKeyMemory.Dispose();
        foreach (var fileId in _retiredFileIds) TryDeleteFileData(fileId);
        if (_singleFilePath is not null && _workingPath is not null)
        {
            try { VaultContainer.Pack(_workingPath, _singleFilePath); }
            finally { VaultContainer.DeleteWorkingDirectory(_workingPath); }
            _singleFilePath = null;
            _workingPath = null;
        }
        _mutationGate.Dispose();
        if (Info.FormatVersion >= FixedVaultContainer.FormatVersion)
        {
            try { if (Directory.Exists(_journalPath)) Directory.Delete(_journalPath, recursive: true); } catch { }
        }
        CryptographicOperations.ZeroMemory(KeyHeader.Bytes);
        CryptographicOperations.ZeroMemory(KeyHeader.PayloadNoncePrefix);
        CryptographicOperations.ZeroMemory(KeyHeader.HeaderHash);
    }

    private long EstimateStoredBytes()
    {
        const int chunkOverhead = 68 + 16;
        long result = 64 + KeyHeader.Bytes.Length;
        foreach (var entry in Entries)
        {
            if (entry.IsDirectory) continue;
            if (Info.SizeProtection == VaultSizeProtection.HideExactSize)
            {
                result = checked(result + (long)entry.ChunkCount * (VaultFormat.ChunkSize + chunkOverhead));
            }
            else
            {
                result = checked(result + entry.Length + (long)entry.ChunkCount * chunkOverhead);
            }
        }
        return result;
    }

    private static (
        IReadOnlyList<VaultCatalogEntry> Catalog,
        IReadOnlyDictionary<string, VaultCatalogEntry> ByPath,
        IReadOnlyDictionary<Guid, IReadOnlyList<VaultCatalogEntry>> Children,
        IReadOnlyList<VaultEntry> PublicEntries) BuildViews(IReadOnlyList<VaultCatalogEntry> catalog)
    {
        var copied = catalog.Select(entry => entry with { }).ToArray();
        var byId = copied.ToDictionary(entry => entry.Id);
        var paths = new Dictionary<Guid, string>();
        string BuildPath(VaultCatalogEntry entry)
        {
            if (paths.TryGetValue(entry.Id, out var existing)) return existing;
            var path = entry.ParentId == Guid.Empty
                ? entry.Name
                : BuildPath(byId[entry.ParentId]) + "/" + entry.Name;
            paths.Add(entry.Id, path);
            entry.RelativePath = path;
            return path;
        }

        foreach (var entry in copied)
        {
            BuildPath(entry);
        }

        var byPath = copied.ToDictionary(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase);
        var children = copied.GroupBy(entry => entry.ParentId)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<VaultCatalogEntry>)group
                    .OrderBy(entry => entry.IsDirectory ? 0 : 1)
                    .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                    .ToArray());
        var publicEntries = copied.Select(entry => ToPublicEntry(entry, entry.RelativePath)).ToArray();
        return (copied, byPath, children, publicEntries);
    }

    private static VaultEntry ToPublicEntry(VaultCatalogEntry entry, string path) => new(
        entry.Id,
        entry.ParentId,
        entry.Name,
        path,
        entry.IsDirectory,
        entry.Length,
        new DateTime(entry.LastWriteUtcTicks, DateTimeKind.Utc),
        entry.ChunkCount);

    private static string NormalizeLookupPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || relativePath is "\\" or "/")
        {
            return string.Empty;
        }
        return PathSafety.NormalizeRelativePath(relativePath.TrimStart('\\', '/').Replace('\\', '/'));
    }

    private async Task PublishCatalogAsync(IReadOnlyList<VaultCatalogEntry> catalog, CancellationToken cancellationToken)
    {
        var revision = checked(Revision + 1);
        await VaultFormat.WriteCatalogAsync(VaultPath, Info, catalog, revision, DataKey, cancellationToken).ConfigureAwait(false);
        ReplaceCatalog(catalog, revision);
    }

    private static VaultCatalogEntry? FindByPath(IReadOnlyList<VaultCatalogEntry> catalog, string path)
    {
        var byId = catalog.ToDictionary(entry => entry.Id);
        string Build(VaultCatalogEntry entry) => entry.ParentId == Guid.Empty
            ? entry.Name
            : Build(byId[entry.ParentId]) + "/" + entry.Name;
        return catalog.FirstOrDefault(entry => string.Equals(Build(entry), path, StringComparison.OrdinalIgnoreCase));
    }

    private static (Guid ParentId, string Name) ResolveParent(IReadOnlyList<VaultCatalogEntry> catalog, string path)
    {
        var slash = path.LastIndexOf('/');
        var parentPath = slash < 0 ? string.Empty : path[..slash];
        var name = slash < 0 ? path : path[(slash + 1)..];
        PathSafety.ValidateNameSegment(name);
        if (string.IsNullOrEmpty(parentPath)) return (Guid.Empty, name);
        var parent = FindByPath(catalog, parentPath);
        if (parent?.IsDirectory != true) throw new NingRanException("目标文件夹不存在。");
        return (parent.Id, name);
    }

    private void RemoveSubtree(List<VaultCatalogEntry> catalog, Guid rootId)
    {
        var ids = new HashSet<Guid> { rootId };
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var entry in catalog)
            {
                if (ids.Contains(entry.ParentId) && ids.Add(entry.Id)) changed = true;
            }
        }
        foreach (var file in catalog.Where(entry => ids.Contains(entry.Id) && !entry.IsDirectory))
        {
            _retiredFileIds.Add(file.Id);
        }
        catalog.RemoveAll(entry => ids.Contains(entry.Id));
    }

    private static bool IsDescendant(IReadOnlyList<VaultCatalogEntry> catalog, Guid candidate, Guid ancestor)
    {
        var map = catalog.ToDictionary(entry => entry.Id);
        while (candidate != Guid.Empty && map.TryGetValue(candidate, out var entry))
        {
            if (candidate == ancestor) return true;
            candidate = entry.ParentId;
        }
        return false;
    }

    private static string GetUniqueName(string name, IEnumerable<string> existingNames)
    {
        var existing = new HashSet<string>(existingNames, StringComparer.OrdinalIgnoreCase);
        if (!existing.Contains(name)) return name;
        var extension = Path.GetExtension(name);
        var stem = Path.GetFileNameWithoutExtension(name);
        for (var index = 1; index < 100_000; index++)
        {
            var candidate = $"{stem} ({index}){extension}";
            if (!existing.Contains(candidate)) return candidate;
        }
        throw new NingRanException("回收站中的同名内容过多，无法自动生成新名称。");
    }

    private static void ValidateTargetPath(string path)
    {
        foreach (var segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries)) PathSafety.ValidateNameSegment(segment);
    }

    private void EnsureFreeSpace(long length)
    {
        var root = Path.GetPathRoot(VaultPath);
        if (string.IsNullOrEmpty(root)) return;
        var drive = new DriveInfo(root);
        var stored = Info.SizeProtection == VaultSizeProtection.HideExactSize
            ? checked((length == 0 ? 0 : (length + VaultFormat.ChunkSize - 1) / VaultFormat.ChunkSize) * VaultFormat.ChunkSize)
            : length;
        var required = checked(stored + 2L * VaultFormat.ChunkSize);
        if (drive.AvailableFreeSpace < required) throw new NingRanException("保险箱所在磁盘空间不足，原文件没有改变。");
    }

    private void TryDeleteFileData(Guid fileId) { try { VaultFormat.DeleteFileData(VaultPath, fileId); } catch { } }

    private static void ClearAbandonedJournal(string journal)
    {
        try
        {
            if (Directory.Exists(journal)) Directory.Delete(journal, recursive: true);
            Directory.CreateDirectory(journal);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new NingRanException("无法清理保险箱上次未完成的保存记录。", exception);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private sealed class ExportLock(SemaphoreSlim gate) : IDisposable
    {
        private SemaphoreSlim? _gate = gate;

        public void Dispose()
        {
            var current = Interlocked.Exchange(ref _gate, null);
            if (current is null) return;
            try { current.Release(); }
            catch (ObjectDisposedException)
            {
                // 立即锁定保险箱会取消导出并清理会话；此时锁本身也已经释放。
            }
        }
    }
}

internal sealed class VaultReadStream : Stream
{
    private readonly VaultSession _session;
    private readonly VaultCatalogEntry _entry;
    private long _position;
    private bool _disposed;

    public VaultReadStream(VaultSession session, VaultCatalogEntry entry)
    {
        _session = session;
        _entry = entry;
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
        if (_position >= Length || buffer.IsEmpty) return 0;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_session.CancellationToken, cancellationToken);
        var read = await VaultFormat.ReadFileAtAsync(
            _session.VaultPath,
            _session.Info,
            _entry,
            _position,
            buffer,
            _session.DataKey,
            linked.Token).ConfigureAwait(false);
        _position = checked(_position + read);
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(Length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (position < 0 || position > Length) throw new IOException("读取位置超出保险箱文件范围。");
        _position = position;
        return position;
    }

    protected override void Dispose(bool disposing)
    {
        _disposed = true;
        base.Dispose(disposing);
    }

    public override void Flush() => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
