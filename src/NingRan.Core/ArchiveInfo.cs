namespace NingRan.Core;

public sealed record ArchiveInfo(
    EncryptionMode Mode,
    bool HidesExactSize,
    bool HasSenderSignature = false,
    string? LegacySenderMarker = null,
    IReadOnlyList<PhysicalDeviceInfo>? PhysicalDevices = null,
    string FormatVersion = "6.0",
    long FileSize = 0,
    DateTime CreatedAtLocal = default,
    ProtectionFactor? ProtectionFactors = null)
{
    public IReadOnlyList<PhysicalDeviceInfo> RequiredPhysicalDevices => PhysicalDevices ?? [];
}
