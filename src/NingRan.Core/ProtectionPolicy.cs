using System.Collections.ObjectModel;

namespace NingRan.Core;

[Flags]
public enum ProtectionFactor : byte
{
    None = 0,
    Password = 1,
    KeyFile = 2,
    PhysicalDevice = 4,
    WindowsHello = 8,
}

/// <summary>
/// Rules for the external devices used by a flexible protection policy.
/// Device identifiers are only used in memory and are stored in the archive as
/// salted lookup hashes.
/// </summary>
public sealed record PhysicalDevicePolicy
{
    public PhysicalDevicePolicy(
        IReadOnlyList<PhysicalDeviceDescriptor>? devices = null,
        int minimumRequired = 0,
        IReadOnlyList<string>? requiredDeviceIds = null,
        IReadOnlyList<PhysicalDeviceDescriptor>? forbiddenDevices = null)
    {
        Devices = new ReadOnlyCollection<PhysicalDeviceDescriptor>((devices ?? []).ToArray());
        RequiredDeviceIds = new ReadOnlyCollection<string>((requiredDeviceIds ?? []).Distinct(StringComparer.Ordinal).ToArray());
        ForbiddenDevices = new ReadOnlyCollection<PhysicalDeviceDescriptor>((forbiddenDevices ?? []).ToArray());
        MinimumRequired = minimumRequired;
    }

    public IReadOnlyList<PhysicalDeviceDescriptor> Devices { get; }
    public int MinimumRequired { get; }
    public IReadOnlyList<string> RequiredDeviceIds { get; }
    public IReadOnlyList<PhysicalDeviceDescriptor> ForbiddenDevices { get; }

    public void Validate()
    {
        if (Devices.Count is < 1 or > 16)
            throw new NingRanException("物理密匙最多只能登记 16 个。 ");

        var ids = Devices.Select(device => device.Id).ToHashSet(StringComparer.Ordinal);
        if (ids.Count != Devices.Count)
            throw new NingRanException("物理密匙列表中不能重复选择同一把密匙。 ");

        if (MinimumRequired is < 1 || MinimumRequired > Devices.Count)
            throw new NingRanException($"至少需要插入 1 至 {Devices.Count} 把物理密匙。 ");

        if (RequiredDeviceIds.Any(id => !ids.Contains(id)))
            throw new NingRanException("必需物理密匙必须来自已选择的密匙列表。 ");

        if (Devices.Any(device => device.Kind != PhysicalDeviceKind.RemovableStorage) ||
            ForbiddenDevices.Any(device => device.Kind != PhysicalDeviceKind.RemovableStorage))
            throw new NingRanException("新组合规则需要持续检测插拔，目前只支持已登记的移动存储密匙。外接 FIDO2 安全密钥仍可用于旧格式。 ");

        var forbiddenIds = ForbiddenDevices.Select(device => device.Id).ToHashSet(StringComparer.Ordinal);
        if (forbiddenIds.Count != ForbiddenDevices.Count || forbiddenIds.Overlaps(ids))
            throw new NingRanException("禁止插入名单不能重复，也不能包含用于解锁的密匙。 ");

        if (RequiredDeviceIds.Count > MinimumRequired)
            throw new NingRanException("必需物理密匙数量不能超过至少需要的数量。 ");
    }
}

/// <summary>
/// A new-format protection policy. Every factor in Factors is required for
/// the primary unlock path. Password and key file can also be retained as a
/// recovery path when Windows Hello is used alone.
/// </summary>
public sealed record ProtectionPolicy
{
    public ProtectionPolicy(
        ProtectionFactor factors,
        PhysicalDevicePolicy? physicalDevices = null,
        WindowsHelloCredential? windowsHello = null,
        ProtectionFactor recoveryFactors = ProtectionFactor.None)
    {
        Factors = factors;
        PhysicalDevices = physicalDevices;
        WindowsHello = windowsHello;
        RecoveryFactors = recoveryFactors;
    }

    public ProtectionFactor Factors { get; }
    public PhysicalDevicePolicy? PhysicalDevices { get; }
    public WindowsHelloCredential? WindowsHello { get; }
    public ProtectionFactor RecoveryFactors { get; }

    public bool Requires(ProtectionFactor factor) => (Factors & factor) == factor;

    public void ValidateForCreation()
    {
        if (Factors == ProtectionFactor.None)
            throw new NingRanException("请至少选择一种解锁方式。 ");

        if (Requires(ProtectionFactor.PhysicalDevice))
        {
            if (PhysicalDevices is null)
                throw new NingRanException("选择物理密匙条件后，必须设置物理密匙规则。 ");
            PhysicalDevices.Validate();
        }
        else if (PhysicalDevices is not null)
        {
            throw new NingRanException("没有选择物理密匙条件，不能设置物理密匙规则。 ");
        }

        if (Requires(ProtectionFactor.WindowsHello) && WindowsHello is null)
            throw new NingRanException("Windows Hello 条件尚未登记。 ");

        if (Factors == ProtectionFactor.WindowsHello && RecoveryFactors == ProtectionFactor.None)
            throw new NingRanException("单独使用 Windows Hello 时，必须同时设置密码或密匙文件作为恢复方式。 ");

        if ((RecoveryFactors & ~(ProtectionFactor.Password | ProtectionFactor.KeyFile)) != 0)
            throw new NingRanException("恢复方式只能使用密码或密匙文件。 ");
    }
}

public sealed record WindowsHelloCredential(byte[] CredentialId, byte[] Salt, byte[]? ProtectedSecret = null)
{
    public void Validate()
    {
        if (CredentialId is null or { Length: 0 } or { Length: > 2048 })
            throw new NingRanException("Windows Hello 凭据长度不正确。 ");
        if (Salt is null || Salt.Length != 32)
            throw new NingRanException("Windows Hello 验证盐长度不正确。 ");
        if (ProtectedSecret is { Length: 0 or > 4096 })
            throw new NingRanException("Windows Hello 本机恢复资料长度不正确。 ");
    }
}
