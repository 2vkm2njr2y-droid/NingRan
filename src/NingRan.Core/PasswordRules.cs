using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NingRan.Core;

public enum PasswordStrength
{
    Weak,
    Fair,
    Strong,
}

public sealed record PasswordAssessment(
    PasswordStrength Strength,
    IReadOnlyList<string> Warnings)
{
    public bool HasWarnings => Warnings.Count > 0;
}

public static class PasswordRules
{
    private static readonly string[] CommonPasswords =
    [
        "password",
        "password123",
        "qwerty123",
        "admin123",
        "welcome123",
        "letmein123",
        "iloveyou",
        "123456789",
        "111111111111",
        "密码123456",
    ];

    private static readonly string[] SimpleSequences =
    [
        "0123456789",
        "9876543210",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
    ];

    public static void ValidateForCreation(string password)
    {
        using var sensitive = SensitivePassword.FromString(password);
        ValidateForCreation(sensitive);
    }

    public static void ValidateForCreation(SensitivePassword password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.IsEmpty)
        {
            throw new ArgumentException("密码不能为空。", nameof(password));
        }
    }

    public static PasswordAssessment Assess(string password)
    {
        using var sensitive = SensitivePassword.FromString(password);
        return Assess(sensitive);
    }

    public static PasswordAssessment Assess(SensitivePassword password)
    {
        ArgumentNullException.ThrowIfNull(password);
        ValidateForCreation(password);
        var characters = password.CopyCharacters();
        try
        {
            var span = characters.AsSpan();
            var warnings = new List<string>();
            InspectCharacterKinds(span, out var hasLetter, out var hasDigit, out var hasSymbol);
            var isLongPhrase = span.Length >= 16;

            if (span.Length < 12)
            {
                warnings.Add("长度少于 12 个字符，可能较容易被猜到。");
            }

            if (!isLongPhrase && (!hasLetter || !hasDigit || !hasSymbol))
            {
                warnings.Add("较短的密码建议同时包含文字、数字和符号，或者改用至少 16 个字符的口令短语。");
            }

            if (IsCommonPassword(span))
            {
                warnings.Add("这个密码过于常见。");
            }

            if (ContainsSimpleSequence(span))
            {
                warnings.Add("密码中包含明显的连续字符或连续数字。");
            }

            if (HasLongRepeatedRun(span))
            {
                warnings.Add("密码中包含过多连续重复字符。");
            }

            var strength = warnings.Count == 0 && (span.Length >= 20 || (hasLetter && hasDigit && hasSymbol))
                ? PasswordStrength.Strong
                : warnings.Count <= 1 && span.Length >= 12
                    ? PasswordStrength.Fair
                    : PasswordStrength.Weak;
            return new PasswordAssessment(strength, warnings);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(characters.AsSpan()));
        }
    }

    private static void InspectCharacterKinds(
        ReadOnlySpan<char> password,
        out bool hasLetter,
        out bool hasDigit,
        out bool hasSymbol)
    {
        hasLetter = false;
        hasDigit = false;
        hasSymbol = false;
        foreach (var character in password)
        {
            hasLetter |= char.IsLetter(character);
            hasDigit |= char.IsDigit(character);
            hasSymbol |= !char.IsLetterOrDigit(character);
        }
    }

    private static bool ContainsSimpleSequence(ReadOnlySpan<char> password)
    {
        foreach (var sequence in SimpleSequences)
        {
            for (var length = 5; length <= Math.Min(password.Length, sequence.Length); length++)
            {
                for (var start = 0; start + length <= sequence.Length; start++)
                {
                    if (password.Contains(sequence.AsSpan(start, length), StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static bool IsCommonPassword(ReadOnlySpan<char> password)
    {
        foreach (var common in CommonPasswords)
        {
            if (password.Equals(common.AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasLongRepeatedRun(ReadOnlySpan<char> password)
    {
        var run = 1;
        for (var index = 1; index < password.Length; index++)
        {
            run = password[index] == password[index - 1] ? run + 1 : 1;
            if (run >= 4)
            {
                return true;
            }
        }

        return false;
    }
}
