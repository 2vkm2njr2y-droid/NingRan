using NingRan.Core.Internal;

namespace NingRan.Core;

public enum VaultSizeProtection : byte
{
    SaveSpace = 0,
    HideExactSize = 1,
}

public sealed class CreateVaultRequest : IDisposable
{
    public CreateVaultRequest(
        string vaultPath,
        SensitivePassword password,
        EncryptionMode mode = EncryptionMode.Standard,
        string? keyFilePath = null,
        IReadOnlyList<PhysicalDeviceDescriptor>? physicalDevices = null,
        IReadOnlyList<string>? sourcePaths = null,
        VaultSizeProtection sizeProtection = VaultSizeProtection.HideExactSize,
        nint ownerWindowHandle = 0,
        long? fixedCapacityBytes = null)
    {
        VaultPath = vaultPath;
        Password = password;
        Mode = mode;
        KeyFilePath = keyFilePath;
        PhysicalDevices = physicalDevices?.ToArray() ?? [];
        SourcePaths = sourcePaths?.ToArray() ?? [];
        SizeProtection = sizeProtection;
        OwnerWindowHandle = ownerWindowHandle;
        FixedCapacityBytes = fixedCapacityBytes;
    }

    public string VaultPath { get; }
    public SensitivePassword Password { get; }
    public EncryptionMode Mode { get; }
    public string? KeyFilePath { get; }
    public IReadOnlyList<PhysicalDeviceDescriptor> PhysicalDevices { get; }
    public IReadOnlyList<string> SourcePaths { get; }
    public VaultSizeProtection SizeProtection { get; }
    public nint OwnerWindowHandle { get; }
    public long? FixedCapacityBytes { get; }

    public void Dispose() => Password.Dispose();
}

public sealed class UnlockVaultRequest : IDisposable
{
    public UnlockVaultRequest(
        string vaultPath,
        SensitivePassword password,
        string? keyFilePath = null,
        nint ownerWindowHandle = 0)
    {
        VaultPath = vaultPath;
        Password = password;
        KeyFilePath = keyFilePath;
        OwnerWindowHandle = ownerWindowHandle;
    }

    public string VaultPath { get; }
    public SensitivePassword Password { get; }
    public string? KeyFilePath { get; }
    public nint OwnerWindowHandle { get; }

    public void Dispose() => Password.Dispose();
}

public sealed class CreateDualVaultRequest : IDisposable
{
    public CreateDualVaultRequest(
        string vaultPath,
        SensitivePassword dailyPassword,
        SensitivePassword hiddenPassword,
        EncryptionMode dailyMode = EncryptionMode.Standard,
        string? dailyKeyFilePath = null,
        IReadOnlyList<string>? dailySourcePaths = null,
        IReadOnlyList<string>? hiddenSourcePaths = null,
        VaultSizeProtection sizeProtection = VaultSizeProtection.HideExactSize,
        nint ownerWindowHandle = 0,
        long? fixedCapacityBytes = null,
        long? dailyCapacityBytes = null,
        long? hiddenCapacityBytes = null)
    {
        VaultPath = vaultPath;
        DailyPassword = dailyPassword;
        HiddenPassword = hiddenPassword;
        DailyMode = dailyMode;
        DailyKeyFilePath = dailyKeyFilePath;
        DailySourcePaths = dailySourcePaths?.ToArray() ?? [];
        HiddenSourcePaths = hiddenSourcePaths?.ToArray() ?? [];
        SizeProtection = sizeProtection;
        OwnerWindowHandle = ownerWindowHandle;
        FixedCapacityBytes = fixedCapacityBytes;
        DailyCapacityBytes = dailyCapacityBytes;
        HiddenCapacityBytes = hiddenCapacityBytes;
    }

    public string VaultPath { get; }
    public SensitivePassword DailyPassword { get; }
    public SensitivePassword HiddenPassword { get; }
    public EncryptionMode DailyMode { get; }
    public string? DailyKeyFilePath { get; }
    public IReadOnlyList<string> DailySourcePaths { get; }
    public IReadOnlyList<string> HiddenSourcePaths { get; }
    public VaultSizeProtection SizeProtection { get; }
    public nint OwnerWindowHandle { get; }
    public long? FixedCapacityBytes { get; }
    public long? DailyCapacityBytes { get; }
    public long? HiddenCapacityBytes { get; }

    public void Dispose()
    {
        DailyPassword.Dispose();
        HiddenPassword.Dispose();
    }
}

public sealed class UpgradeVaultRequest : IDisposable
{
    public UpgradeVaultRequest(
        string sourceVaultPath,
        string targetVaultPath,
        SensitivePassword password,
        string? keyFilePath = null,
        nint ownerWindowHandle = 0,
        long? fixedCapacityBytes = null)
    {
        SourceVaultPath = sourceVaultPath;
        TargetVaultPath = targetVaultPath;
        Password = password;
        KeyFilePath = keyFilePath;
        OwnerWindowHandle = ownerWindowHandle;
        FixedCapacityBytes = fixedCapacityBytes;
    }

    public string SourceVaultPath { get; }
    public string TargetVaultPath { get; }
    public SensitivePassword Password { get; }
    public string? KeyFilePath { get; }
    public nint OwnerWindowHandle { get; }
    public long? FixedCapacityBytes { get; }

    public void Dispose() => Password.Dispose();
}

public sealed record VaultInfo(
    string VaultPath,
    Guid VaultId,
    EncryptionMode Mode,
    VaultSizeProtection SizeProtection,
    DateTimeOffset CreatedAt,
    int FormatVersion,
    long CapacityBytes = 0)
{
    public string Name => Path.GetFileNameWithoutExtension(Path.TrimEndingDirectorySeparator(VaultPath));
    internal int WorkspaceIndex { get; init; } = -1;
    internal VaultWorkspaceRegion? WorkspaceRegion { get; init; }
}

public sealed record VaultEntry(
    Guid Id,
    Guid ParentId,
    string Name,
    string RelativePath,
    bool IsDirectory,
    long Length,
    DateTime LastWriteTimeUtc,
    int ChunkCount);

public sealed record VaultCreationResult(VaultInfo Info, int EntryCount, long ContentBytes);

public sealed record VaultDualCreationResult(
    VaultInfo Info,
    int DailyEntryCount,
    long DailyContentBytes,
    int HiddenEntryCount,
    long HiddenContentBytes);

public sealed record VaultImportResult(int AddedEntries, long AddedBytes);

public sealed record VaultUpgradeResult(
    VaultInfo SourceInfo,
    VaultInfo UpgradedInfo,
    int EntryCount,
    long ContentBytes);
