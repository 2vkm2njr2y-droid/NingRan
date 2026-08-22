using System.Security.Cryptography;

namespace NingRan.Core;

public enum PhysicalDeviceKind : byte
{
    RemovableStorage = 1,
    Fido2SecurityKey = 2,
}

public sealed record PhysicalDeviceDescriptor(
    PhysicalDeviceKind Kind,
    string Id,
    string Name,
    string Model,
    long CapacityBytes = 0,
    byte[]? CredentialId = null)
{
    public string ShortId => Id.Length <= 8 ? Id : Id[..4] + "…" + Id[^4..];

    public string DisplayText
    {
        get
        {
            var capacity = CapacityBytes > 0 ? $" · {FormatBytes(CapacityBytes)}" : string.Empty;
            var type = Kind == PhysicalDeviceKind.RemovableStorage ? "移动存储" : "FIDO2 安全密钥";
            return $"{Name} 〔{type} · {Model}{capacity} · {ShortId}〕";
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.##} {units[unit]}";
    }
}

public sealed class PhysicalDeviceUnlock : IDisposable
{
    private readonly Func<CancellationToken, Task> _revalidate;
    private readonly Func<bool> _isPresent;
    private byte[]? _secret;

    public PhysicalDeviceUnlock(
        PhysicalDeviceDescriptor device,
        byte[] secret,
        Func<bool>? isPresent = null,
        Func<CancellationToken, Task>? revalidate = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length != 32)
        {
            throw new ArgumentException("物理设备返回的开锁凭证长度不正确。", nameof(secret));
        }

        Device = device;
        _secret = secret;
        _isPresent = isPresent ?? (() => true);
        _revalidate = revalidate ?? (_ => Task.CompletedTask);
    }

    public PhysicalDeviceDescriptor Device { get; }

    public ReadOnlyMemory<byte> Secret => _secret ?? throw new ObjectDisposedException(nameof(PhysicalDeviceUnlock));

    public bool IsPresent => _secret is not null && _isPresent();

    public Task RevalidateAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_secret is null, this);
        return _revalidate(cancellationToken);
    }

    public void Dispose()
    {
        if (_secret is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_secret);
        _secret = null;
    }
}

public interface IPhysicalDeviceProvider
{
    Task<PhysicalDeviceUnlock> UnlockAnyAsync(
        IReadOnlyList<PhysicalDeviceRequirement> devices,
        nint ownerWindowHandle,
        CancellationToken cancellationToken);

    Task<PhysicalDeviceUnlock> UnlockAnonymousAsync(
        IReadOnlyList<AnonymousPhysicalDeviceRequirement> requirements,
        ReadOnlyMemory<byte> archiveSalt,
        nint ownerWindowHandle,
        CancellationToken cancellationToken);
}

public sealed record AnonymousPhysicalDeviceRequirement(
    byte[] DeviceLookupHash,
    byte[] SecretSalt);

public sealed record PhysicalDeviceRequirement(
    PhysicalDeviceDescriptor Device,
    byte[] SecretSalt);

public sealed record PhysicalDeviceInfo(
    PhysicalDeviceKind Kind,
    string Name,
    string Model,
    long CapacityBytes,
    string ShortId);
