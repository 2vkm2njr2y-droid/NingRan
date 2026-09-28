using NingRan.Core.Internal;

namespace NingRan.Core;

public enum SizePaddingMode
{
    None,
    Rounded,
    Fixed100MiB,
    Fixed1GiB,
    Fixed10GiB,
}

public enum ArchiveCompressionLevel
{
    Store,
    Fastest,
    Standard,
    Maximum,
    /// <summary>媒体图片先降低质量，再进行加密；非图片仍使用无损压缩。</summary>
    SmallestLossy,
}

public sealed record SizePaddingEstimate(long ContentBytes, long AdditionalPaddingBytes);

public sealed record ArchiveSizeReport(
    long ContentBytes,
    long StoredContentBytes,
    long ArchiveBytes,
    long StructureBytes,
    ArchiveCompressionLevel Compression)
{
    public long SavedBytes => Math.Max(0, ContentBytes - StoredContentBytes);
    public double SavedPercent => ContentBytes == 0 ? 0 : SavedBytes * 100d / ContentBytes;
}

public sealed class EncryptRequest : IDisposable
{
    /// <summary>直接把已解锁的保险箱导出为可移动加密包，不依赖临时磁盘。</summary>
    public EncryptRequest(
        VaultSession SourceVault,
        string OutputPath,
        SensitivePassword Password,
        EncryptionMode Mode = EncryptionMode.Standard,
        string? KeyFilePath = null,
        SizePaddingMode SizePadding = SizePaddingMode.None,
        ArchiveCompressionLevel Compression = ArchiveCompressionLevel.Standard,
        string? SigningIdentityId = null,
        SensitivePassword? SigningIdentityPassword = null,
        IReadOnlyList<PhysicalDeviceDescriptor>? PhysicalDevices = null,
        nint OwnerWindowHandle = 0)
    {
        ArgumentNullException.ThrowIfNull(SourceVault);
        this.SourceVault = SourceVault;
        SourcePaths = [];
        this.OutputPath = OutputPath;
        this.Password = Password;
        this.Mode = Mode;
        this.KeyFilePath = KeyFilePath;
        this.SizePadding = SizePadding;
        this.Compression = Compression;
        this.SigningIdentityId = SigningIdentityId;
        this.SigningIdentityPassword = SigningIdentityPassword;
        this.PhysicalDevices = PhysicalDevices?.ToArray() ?? [];
        this.OwnerWindowHandle = OwnerWindowHandle;
    }

    public EncryptRequest(
        string SourcePath,
        string OutputPath,
        string Password,
        EncryptionMode Mode = EncryptionMode.Standard,
        string? KeyFilePath = null,
        bool HideExactSize = false,
        ArchiveCompressionLevel Compression = ArchiveCompressionLevel.Standard,
        string? SigningIdentityId = null,
        string? SigningIdentityPassword = null,
        IReadOnlyList<PhysicalDeviceDescriptor>? PhysicalDevices = null,
        nint OwnerWindowHandle = 0,
        string? CoverImagePath = null)
        : this(
            SourcePath,
            OutputPath,
            SensitivePassword.FromString(Password),
            Mode,
            KeyFilePath,
            HideExactSize ? SizePaddingMode.Rounded : SizePaddingMode.None,
            Compression,
            SigningIdentityId,
            SigningIdentityPassword is null ? null : SensitivePassword.FromString(SigningIdentityPassword),
            PhysicalDevices,
            OwnerWindowHandle,
            CoverImagePath)
    {
    }

    public EncryptRequest(
        string SourcePath,
        string OutputPath,
        SensitivePassword Password,
        EncryptionMode Mode = EncryptionMode.Standard,
        string? KeyFilePath = null,
        SizePaddingMode SizePadding = SizePaddingMode.None,
        ArchiveCompressionLevel Compression = ArchiveCompressionLevel.Standard,
        string? SigningIdentityId = null,
        SensitivePassword? SigningIdentityPassword = null,
        IReadOnlyList<PhysicalDeviceDescriptor>? PhysicalDevices = null,
        nint OwnerWindowHandle = 0,
        string? CoverImagePath = null)
    {
        SourcePaths = [SourcePath];
        this.OutputPath = OutputPath;
        this.Password = Password;
        this.Mode = Mode;
        this.KeyFilePath = KeyFilePath;
        this.SizePadding = SizePadding;
        this.Compression = Compression;
        this.SigningIdentityId = SigningIdentityId;
        this.SigningIdentityPassword = SigningIdentityPassword;
        this.PhysicalDevices = PhysicalDevices?.ToArray() ?? [];
        this.OwnerWindowHandle = OwnerWindowHandle;
        this.CoverImagePath = CoverImagePath;
    }

    /// <summary>创建安全交付包时使用，可同时包含多个顶层文件和文件夹。</summary>
    public EncryptRequest(
        IReadOnlyList<string> SourcePaths,
        string OutputPath,
        SensitivePassword Password,
        DeliveryPackageInfo DeliveryInfo,
        EncryptionMode Mode = EncryptionMode.Standard,
        string? KeyFilePath = null,
        SizePaddingMode SizePadding = SizePaddingMode.None,
        ArchiveCompressionLevel Compression = ArchiveCompressionLevel.Standard,
        string? SigningIdentityId = null,
        SensitivePassword? SigningIdentityPassword = null,
        IReadOnlyList<PhysicalDeviceDescriptor>? PhysicalDevices = null,
        nint OwnerWindowHandle = 0)
    {
        ArgumentNullException.ThrowIfNull(SourcePaths);
        if (SourcePaths.Count == 0)
        {
            throw new ArgumentException("请至少选择一个要交付的文件或文件夹。", nameof(SourcePaths));
        }

        this.SourcePaths = SourcePaths.ToArray();
        this.OutputPath = OutputPath;
        this.Password = Password;
        this.DeliveryInfo = DeliveryInfo;
        this.Mode = Mode;
        this.KeyFilePath = KeyFilePath;
        this.SizePadding = SizePadding;
        this.Compression = Compression;
        this.SigningIdentityId = SigningIdentityId;
        this.SigningIdentityPassword = SigningIdentityPassword;
        this.PhysicalDevices = PhysicalDevices?.ToArray() ?? [];
        this.OwnerWindowHandle = OwnerWindowHandle;
    }

    public string SourcePath => SourceVault?.VaultPath ?? SourcePaths[0];

    public IReadOnlyList<string> SourcePaths { get; }

    public VaultSession? SourceVault { get; }

    public string OutputPath { get; }

    public SensitivePassword Password { get; }

    public EncryptionMode Mode { get; }

    public string? KeyFilePath { get; }

    public SizePaddingMode SizePadding { get; }

    public bool HideExactSize => SizePadding != SizePaddingMode.None;

    public ArchiveCompressionLevel Compression { get; }

    public string? SigningIdentityId { get; }

    public SensitivePassword? SigningIdentityPassword { get; }

    public IReadOnlyList<PhysicalDeviceDescriptor> PhysicalDevices { get; }

    public nint OwnerWindowHandle { get; }

    public string? CoverImagePath { get; }

    public DeliveryPackageInfo? DeliveryInfo { get; }

    public bool IsDelivery => DeliveryInfo is not null;

    public bool IsVaultExport => SourceVault is not null;

    public void Dispose()
    {
        Password.Dispose();
        SigningIdentityPassword?.Dispose();
    }
}

public sealed class DecryptRequest : IDisposable
{
    public DecryptRequest(
        string ArchivePath,
        string DestinationDirectory,
        string Password,
        string? KeyFilePath = null,
        string? TrustedSenderId = null,
        nint OwnerWindowHandle = 0,
        EncryptionMode? ExpectedMode = null)
        : this(
            ArchivePath,
            DestinationDirectory,
            SensitivePassword.FromString(Password),
            KeyFilePath,
            TrustedSenderId,
            OwnerWindowHandle,
            ExpectedMode)
    {
    }

    public DecryptRequest(
        string ArchivePath,
        string DestinationDirectory,
        SensitivePassword Password,
        string? KeyFilePath = null,
        string? TrustedSenderId = null,
        nint OwnerWindowHandle = 0,
        EncryptionMode? ExpectedMode = null)
    {
        this.ArchivePath = ArchivePath;
        this.DestinationDirectory = DestinationDirectory;
        this.Password = Password;
        this.KeyFilePath = KeyFilePath;
        this.TrustedSenderId = TrustedSenderId;
        this.OwnerWindowHandle = OwnerWindowHandle;
        this.ExpectedMode = ExpectedMode;
    }

    public string ArchivePath { get; }

    public string DestinationDirectory { get; }

    public SensitivePassword Password { get; }

    public string? KeyFilePath { get; }

    public string? TrustedSenderId { get; }

    public nint OwnerWindowHandle { get; }

    /// <summary>
    /// 由界面明确选择的解锁方式。老调用方不传时仍会依次尝试所有受支持的方式。
    /// </summary>
    public EncryptionMode? ExpectedMode { get; }

    public void Dispose() => Password.Dispose();
}

public sealed class EncryptionResult
{
    internal EncryptionResult(
        string archivePath,
        long archiveSize,
        ArchiveSizeReport sizeReport,
        IReadOnlyList<SourceEntrySnapshot> sourceSnapshot,
        string? sourceParentPath,
        WindowsFileIdentity? sourceParentIdentity,
        WindowsFileIdentity archiveIdentity,
        byte[] archiveHash)
    {
        ArchivePath = archivePath;
        ArchiveSize = archiveSize;
        SizeReport = sizeReport;
        SourceSnapshot = sourceSnapshot;
        SourceParentPath = sourceParentPath;
        SourceParentIdentity = sourceParentIdentity;
        ArchiveIdentity = archiveIdentity;
        ArchiveHash = archiveHash;
    }

    public string ArchivePath { get; }

    public long ArchiveSize { get; }

    public ArchiveSizeReport SizeReport { get; }

    public string SourcePath => SourceSnapshot[0].FullPath;

    public string SourceName => Path.GetFileName(SourcePath);

    public bool SourceIsDirectory => SourceSnapshot[0].Kind == PayloadEntryKind.Directory;

    internal IReadOnlyList<SourceEntrySnapshot> SourceSnapshot { get; }

    internal string? SourceParentPath { get; }

    internal WindowsFileIdentity? SourceParentIdentity { get; }

    internal WindowsFileIdentity ArchiveIdentity { get; }

    internal byte[] ArchiveHash { get; }
}

internal sealed record SourceEntrySnapshot(
    PayloadEntryKind Kind,
    string FullPath,
    string RelativePath,
    long Length,
    long LastWriteUtcTicks,
    WindowsFileIdentity Identity);

public sealed record DecryptionResult(
    string OutputPath,
    bool IsDirectory,
    string? VerifiedSenderName = null);

/// <summary>对已安全打开的加密文件进行删除或追加所需的信息。</summary>
public sealed class ArchiveUpdateRequest : IDisposable
{
    public ArchiveUpdateRequest(
        string archivePath,
        SensitivePassword password,
        string signingIdentityId,
        SensitivePassword signingIdentityPassword,
        string? keyFilePath = null,
        ArchiveCompressionLevel compression = ArchiveCompressionLevel.Standard,
        IReadOnlyList<string>? pathsToRemove = null,
        IReadOnlyList<ArchiveAppendSource>? additions = null,
        nint ownerWindowHandle = 0)
    {
        ArchivePath = archivePath;
        Password = password;
        SigningIdentityId = signingIdentityId;
        SigningIdentityPassword = signingIdentityPassword;
        KeyFilePath = keyFilePath;
        Compression = compression;
        PathsToRemove = pathsToRemove?.ToArray() ?? [];
        Additions = additions?.ToArray() ?? [];
        OwnerWindowHandle = ownerWindowHandle;
    }

    public string ArchivePath { get; }
    public SensitivePassword Password { get; }
    public string SigningIdentityId { get; }
    public SensitivePassword SigningIdentityPassword { get; }
    public string? KeyFilePath { get; }
    public ArchiveCompressionLevel Compression { get; }
    public IReadOnlyList<string> PathsToRemove { get; }
    public IReadOnlyList<ArchiveAppendSource> Additions { get; }
    public nint OwnerWindowHandle { get; }

    public void Dispose()
    {
        Password.Dispose();
        SigningIdentityPassword.Dispose();
    }
}

public sealed record ArchiveAppendSource(string SourcePath, string TargetDirectoryRelativePath, string? TargetName = null);
