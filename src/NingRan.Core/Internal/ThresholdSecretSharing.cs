using System.Security.Cryptography;

namespace NingRan.Core.Internal;

/// <summary>
/// Small byte-wise Shamir implementation used only for the flexible physical
/// device envelope. The secret itself never leaves memory unencrypted.
/// </summary>
internal static class ThresholdSecretSharing
{
    public static IReadOnlyList<byte[]> Split(ReadOnlySpan<byte> secret, int shareCount, int threshold)
    {
        if (secret.Length == 0 || shareCount is < 1 or > 255 || threshold is < 1 || threshold > shareCount)
            throw new ArgumentOutOfRangeException(nameof(threshold));

        var coefficients = new byte[threshold][];
        coefficients[0] = secret.ToArray();
        for (var degree = 1; degree < threshold; degree++)
            coefficients[degree] = RandomNumberGenerator.GetBytes(secret.Length);

        var result = new List<byte[]>(shareCount);
        try
        {
            for (var index = 1; index <= shareCount; index++)
            {
                var share = new byte[secret.Length + 1];
                share[0] = checked((byte)index);
                for (var offset = 0; offset < secret.Length; offset++)
                {
                    byte value = 0;
                    byte power = 1;
                    for (var degree = 0; degree < threshold; degree++)
                    {
                        value ^= Multiply(coefficients[degree][offset], power);
                        power = Multiply(power, share[0]);
                    }

                    share[offset + 1] = value;
                }

                result.Add(share);
            }

            return result;
        }
        finally
        {
            foreach (var coefficient in coefficients.Skip(1))
                CryptographicOperations.ZeroMemory(coefficient);
        }
    }

    public static byte[] Combine(IReadOnlyList<byte[]> shares, int threshold)
    {
        if (shares is null || shares.Count < threshold || threshold is < 1 ||
            shares.Any(share => share is null || share.Length < 2))
            throw new ArgumentException("物理密匙数量不足，无法恢复加密条件。", nameof(shares));

        var selected = shares.Take(threshold).ToArray();
        var length = selected[0].Length;
        if (selected.Any(share => share.Length != length || share[0] == 0) ||
            selected.Select(share => share[0]).Distinct().Count() != selected.Length)
            throw new ArgumentException("物理密匙分片不完整或重复。", nameof(shares));

        var result = new byte[length - 1];
        for (var byteIndex = 0; byteIndex < result.Length; byteIndex++)
        {
            byte value = 0;
            for (var i = 0; i < selected.Length; i++)
            {
                byte basis = 1;
                for (var j = 0; j < selected.Length; j++)
                {
                    if (i == j) continue;
                    basis = Multiply(basis, Divide(selected[j][0], (byte)(selected[j][0] ^ selected[i][0])));
                }

                value ^= Multiply(selected[i][byteIndex + 1], basis);
            }

            result[byteIndex] = value;
        }

        return result;
    }

    private static byte Divide(byte numerator, byte denominator)
    {
        if (denominator == 0) throw new DivideByZeroException();
        return Multiply(numerator, Inverse(denominator));
    }

    private static byte Inverse(byte value)
    {
        if (value == 0) throw new DivideByZeroException();
        byte result = 1;
        var baseValue = value;
        var exponent = 254;
        while (exponent > 0)
        {
            if ((exponent & 1) != 0) result = Multiply(result, baseValue);
            baseValue = Multiply(baseValue, baseValue);
            exponent >>= 1;
        }

        return result;
    }

    private static byte Multiply(byte left, byte right)
    {
        byte result = 0;
        for (var bit = 0; bit < 8; bit++)
        {
            if ((right & 1) != 0) result ^= left;
            var high = (left & 0x80) != 0;
            left <<= 1;
            if (high) left ^= 0x1B;
            right >>= 1;
        }

        return result;
    }
}
