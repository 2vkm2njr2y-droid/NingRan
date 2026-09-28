using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NingRan.GeneralFileBridge;

internal sealed class BridgeSecurity : IDisposable
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("MierGeneralFileSystem.Bridge.v1");
    private readonly byte[] _secret;

    private BridgeSecurity(byte[] secret) => _secret = secret;

    public static BridgeSecurity ValidateParent(int parentProcessId)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MierGeneralFileSystem");
        var protectedBytes = File.ReadAllBytes(Path.Combine(root, "bridge-credential.bin"));
        byte[] secret;
        try { secret = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser); }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
        try
        {
            var trust = JsonSerializer.Deserialize<BridgeTrust>(File.ReadAllText(Path.Combine(root, "manager.trust.json")))
                ?? throw new UnauthorizedAccessException("受信程序记录无效。");
            using var parent = Process.GetProcessById(parentProcessId);
            var actualPath = Path.GetFullPath(parent.MainModule?.FileName
                ?? throw new UnauthorizedAccessException("无法核对调用程序位置。"));
            var actualHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(actualPath)));
            var expectedMac = HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(
                $"{Path.GetFullPath(trust.Path).ToUpperInvariant()}\n{trust.Sha256.ToUpperInvariant()}"));
            var suppliedMac = Convert.FromHexString(trust.Mac);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expectedMac, suppliedMac) ||
                    !string.Equals(actualPath, Path.GetFullPath(trust.Path), StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(actualHash, trust.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException("调用程序的位置或内容与受信记录不一致。");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedMac);
                CryptographicOperations.ZeroMemory(suppliedMac);
            }
            return new BridgeSecurity(secret);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            throw;
        }
    }

    public async Task AuthorizeConnectionAsync(int parentProcessId)
    {
        var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await BridgeConsole.WriteAsync(new
        {
            kind = "challenge",
            challenge,
            serverProcessId = Environment.ProcessId,
        }).ConfigureAwait(false);
        var proof = await BridgeConsole.ReadAsync<BridgeProof>().ConfigureAwait(false)
            ?? throw new UnauthorizedAccessException("没有收到调用验证。");
        if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - proof.Timestamp) > 120)
            throw new UnauthorizedAccessException("调用验证已经过期。");
        var message = $"{challenge}\n{parentProcessId}\n{Environment.ProcessId}\n{proof.Timestamp}";
        var expected = HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(message));
        byte[] supplied;
        try { supplied = Convert.FromHexString(proof.Proof); }
        catch (FormatException) { throw new UnauthorizedAccessException("调用验证格式不正确。"); }
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, supplied))
                throw new UnauthorizedAccessException("调用验证未通过。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(supplied);
        }
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_secret);

    private sealed record BridgeTrust(string Path, string Sha256, string Mac);
    private sealed record BridgeProof(long Timestamp, string Proof);
}

internal static class BridgeConsole
{
    private const int MaximumMessageCharacters = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<T?> ReadAsync<T>()
    {
        var line = await Console.In.ReadLineAsync().ConfigureAwait(false);
        if (line is null || line.Length > MaximumMessageCharacters)
            throw new InvalidDataException("接口请求为空或超过安全上限。");
        return JsonSerializer.Deserialize<T>(line, JsonOptions);
    }

    public static async Task WriteAsync(object value)
    {
        await Console.Out.WriteLineAsync(JsonSerializer.Serialize(value, JsonOptions)).ConfigureAwait(false);
        await Console.Out.FlushAsync().ConfigureAwait(false);
    }
}
