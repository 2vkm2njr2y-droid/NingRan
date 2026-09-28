using System.Security.Cryptography;
using System.Text.Json;
using NingRan.Core.Internal;

namespace NingRan.Core;

public enum VaultHistoryOperation { Modified, Overwritten, Deleted }

public sealed record VaultHistoryEntry(
    Guid Id, Guid OriginalEntryId, string RelativePath, string Name, bool IsDirectory,
    long Length, DateTime LastWriteTimeUtc, VaultHistoryOperation Operation,
    DateTime CreatedUtc);

internal sealed class VaultHistoryStore
{
    private sealed record StoredRecord(Guid Id, Guid OriginalEntryId, string RelativePath, string Name,
        bool IsDirectory, long Length, long LastWriteUtcTicks, VaultHistoryOperation Operation,
        DateTime CreatedUtc, string SnapshotDirectory);
    private sealed class State
    {
        public int RetentionDays { get; set; } = 15;
        public long MaximumBytes { get; set; }
        public List<StoredRecord> Records { get; set; } = [];
    }
    private readonly string _root;
    private readonly string _statePath;
    private readonly bool _enabled;
    private State _state;
    public VaultHistoryStore(string vaultPath, bool embedded, bool enabled = true)
    {
        _enabled = enabled;
        // Keep snapshots beside the vault so integrity checks over active vault data do not treat history as current content.
        _root = embedded ? Path.Combine(vaultPath, "history") : vaultPath + ".history";
        _statePath = Path.Combine(_root, "index.bin");
        if (_enabled) Directory.CreateDirectory(_root);
        _state = _enabled ? Load() : new State();
    }
    public int RetentionDays { get => _state.RetentionDays; set { _state.RetentionDays = Math.Max(1, value); Save(); Cleanup(); } }
    public long MaximumBytes { get => _state.MaximumBytes; set { _state.MaximumBytes = Math.Max(0, value); Save(); Cleanup(); } }
    public IReadOnlyList<VaultHistoryEntry> List() => _state.Records.OrderByDescending(x => x.CreatedUtc).Select(ToPublic).ToArray();
    public void Capture(VaultCatalogEntry entry, string vaultPath, VaultHistoryOperation operation)
    {
        if (!_enabled || entry.IsDirectory) return;
        var id = Guid.NewGuid();
        var snapshot = Path.Combine(_root, id.ToString("N"));
        var source = Internal.VaultFormat.GetFileDirectory(vaultPath, entry.Id);
        if (!Directory.Exists(source)) return;
        CopyDirectory(source, snapshot);
        _state.Records.Add(new StoredRecord(id, entry.Id, entry.RelativePath, entry.Name, false, entry.Length,
            entry.LastWriteUtcTicks, operation, DateTime.UtcNow, snapshot));
        Save(); Cleanup();
    }
    public void Delete(Guid id)
    {
        var record = _state.Records.FirstOrDefault(x => x.Id == id) ?? throw new NingRanException("没有找到历史版本。");
        TryDelete(record.SnapshotDirectory); _state.Records.Remove(record); Save();
    }
    public string SnapshotPath(Guid id) => _state.Records.FirstOrDefault(x => x.Id == id)?.SnapshotDirectory
        ?? throw new NingRanException("没有找到历史版本。");
    public VaultHistoryEntry Get(Guid id) => ToPublic(_state.Records.FirstOrDefault(x => x.Id == id) ?? throw new NingRanException("没有找到历史版本。"));
    public void CloneSnapshot(Guid id, string targetDirectory) => CopyDirectory(SnapshotPath(id), targetDirectory);
    private void Cleanup()
    {
        if (!_enabled) return;
        var cutoff = DateTime.UtcNow.AddDays(-Math.Max(1, _state.RetentionDays));
        foreach (var record in _state.Records.Where(x => x.CreatedUtc < cutoff).ToArray()) { TryDelete(record.SnapshotDirectory); _state.Records.Remove(record); }
        long total = _state.Records.Sum(x => DirectorySize(x.SnapshotDirectory));
        foreach (var record in _state.Records.OrderBy(x => x.CreatedUtc).ToArray())
        {
            if (_state.MaximumBytes <= 0 || total <= _state.MaximumBytes) break;
            total -= DirectorySize(record.SnapshotDirectory); TryDelete(record.SnapshotDirectory); _state.Records.Remove(record);
        }
        Save();
    }
    private State Load()
    {
        try
        {
            if (!File.Exists(_statePath)) return new State();
            var protectedBytes = File.ReadAllBytes(_statePath);
            var json = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<State>(json) ?? new State();
        }
        catch { return new State(); }
    }
    private void Save()
    {
        if (!_enabled) return;
        var json = JsonSerializer.SerializeToUtf8Bytes(_state);
        var protectedBytes = ProtectedData.Protect(json, null, DataProtectionScope.CurrentUser);
        var temp = _statePath + ".tmp"; File.WriteAllBytes(temp, protectedBytes); File.Move(temp, _statePath, true);
        CryptographicOperations.ZeroMemory(json); CryptographicOperations.ZeroMemory(protectedBytes);
    }
    private static VaultHistoryEntry ToPublic(StoredRecord x) => new(x.Id, x.OriginalEntryId, x.RelativePath, x.Name, x.IsDirectory,
        x.Length, new DateTime(x.LastWriteUtcTicks, DateTimeKind.Utc), x.Operation, x.CreatedUtc);
    private static void CopyDirectory(string source, string target) { Directory.CreateDirectory(target); foreach (var file in Directory.EnumerateFiles(source)) File.Copy(file, Path.Combine(target, Path.GetFileName(file))); foreach (var dir in Directory.EnumerateDirectories(source)) CopyDirectory(dir, Path.Combine(target, Path.GetFileName(dir))); }
    private static long DirectorySize(string path) => Directory.Exists(path) ? Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Sum(x => new FileInfo(x).Length) : 0;
    private static void TryDelete(string path) { try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch { } }
}
