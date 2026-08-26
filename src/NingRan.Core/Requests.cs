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
}

public sealed record SizePaddingEstimate(long ContentBytes, long AdditionalPaddingBytes);

public sealed class EncryptRequest : IDisposable
{
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
        nint OwnerWindowHandle = 0)
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
            OwnerWindowHandle)
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
        nint OwnerWindowHandle = 0)
    {
        this.SourcePath = SourcePath;
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

    public string SourcePath { get; }

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
        nint OwnerWindowHandle = 0)
        : this(
            ArchivePath,
            DestinationDirectory,
            SensitivePassword.FromString(Password),
            KeyFilePath,
            TrustedSenderId,
            OwnerWindowHandle)
    {
    }

    public DecryptRequest(
        string ArchivePath,
        string DestinationDirectory,
        SensitivePassword Password,
        string? KeyFilePath = null,
        string? TrustedSenderId = null,
        nint OwnerWindowHandle = 0)
    {
        this.ArchivePath = ArchivePath;
        this.DestinationDirectory = DestinationDirectory;
        this.Password = Password;
        this.KeyFilePath = KeyFilePath;
        this.TrustedSenderId = TrustedSenderId;
        this.OwnerWindowHandle = OwnerWindowHandle;
    }

    public string ArchivePath { get; }

    public string DestinationDirectory { get; }

    public SensitivePassword Password { get; }

    public string? KeyFilePath { get; }

    public string? TrustedSenderId { get; }

    public nint OwnerWindowHandle { get; }

    public void Dispose() => Password.Dispose();
}

public sealed class EncryptionResult
{
    internal EncryptionResult(
        string archivePath,
        long archiveSize,
        IReadOnlyList<SourceEntrySnapshot> sourceSnapshot,
        string? sourceParentPath,
        WindowsFileIdentity? sourceParentIdentity,
        WindowsFileIdentity archiveIdentity,
        byte[] archiveHash)
    {
        ArchivePath = archivePath;
        ArchiveSize = archiveSize;
        SourceSnapshot = sourceSnapshot;
        SourceParentPath = sourceParentPath;
        SourceParentIdentity = sourceParentIdentity;
        ArchiveIdentity = archiveIdentity;
        ArchiveHash = archiveHash;
    }

    public string ArchivePath { get; }

    public long ArchiveSize { get; }

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
