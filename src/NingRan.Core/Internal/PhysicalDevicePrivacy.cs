using System.Security.Cryptography;
using System.Text;

namespace NingRan.Core.Internal;

internal static class PhysicalDevicePrivacy
{
    public static byte[] ComputeLookupHash(PhysicalDeviceDescriptor device, ReadOnlySpan<byte> archiveSalt)
    {
        var identifier = GetIdentifierBytes(device);
        var input = new byte[identifier.Length + 1];
        try
        {
            input[0] = (byte)device.Kind;
            identifier.CopyTo(input.AsSpan(1));
            return HMACSHA256.HashData(archiveSalt, input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(identifier);
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public static byte[] GetIdentifierBytes(PhysicalDeviceDescriptor device)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (device.Kind == PhysicalDeviceKind.RemovableStorage &&
            Guid.TryParseExact(device.Id, "N", out _))
        {
            return Encoding.UTF8.GetBytes(device.Id);
        }

        if (device.Kind == PhysicalDeviceKind.Fido2SecurityKey &&
            device.CredentialId is { Length: > 0 and <= 2048 } &&
            string.Equals(
                device.Id,
                Convert.ToHexString(SHA256.HashData(device.CredentialId)),
                StringComparison.Ordinal))
        {
            return device.CredentialId.ToArray();
        }

        throw new NingRanException("物理设备编号不正确。");
    }

    public static bool DeviceMatches(PhysicalDeviceDescriptor first, PhysicalDeviceDescriptor second) =>
        first.Kind == second.Kind && string.Equals(first.Id, second.Id, StringComparison.Ordinal);
}
