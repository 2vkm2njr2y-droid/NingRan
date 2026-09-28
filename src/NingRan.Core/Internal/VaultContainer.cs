using System.IO.Compression;

namespace NingRan.Core.Internal;

internal static class VaultContainer
{
    public static bool IsSingleFile(string path) => File.Exists(path) && !Directory.Exists(path);

    public static string CreateWorkingDirectory(string containerPath)
    {
        var parent = Path.GetDirectoryName(containerPath) ?? throw new NingRanException("保险箱保存位置不正确。");
        Directory.CreateDirectory(parent);
        var name = Path.GetFileName(containerPath);
        var working = Path.Combine(Path.GetTempPath(), "NingRanVault", $"{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(working);
        return working;
    }

    public static void Extract(string containerPath, string destination)
    {
        try
        {
            ZipFile.ExtractToDirectory(containerPath, destination, overwriteFiles: false);
        }
        catch (InvalidDataException exception)
        {
            throw new NingRanException("单文件保险箱内容损坏，无法打开。", exception);
        }
    }

    public static void Pack(string sourceDirectory, string containerPath)
    {
        var temporary = containerPath + $".{Guid.NewGuid():N}.part";
        try
        {
            ZipFile.CreateFromDirectory(sourceDirectory, temporary, CompressionLevel.NoCompression, includeBaseDirectory: false);
            File.Move(temporary, containerPath, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch { }
        }
    }

    public static async Task<VaultInfo> ReadInfoWithoutExtractingAsync(
        string containerPath,
        CancellationToken cancellationToken)
    {
        try
        {
            using var archive = ZipFile.OpenRead(containerPath);
            var matches = archive.Entries.Where(entry =>
                string.Equals(entry.FullName.Replace('\\', '/'), "vault.info", StringComparison.Ordinal)).ToArray();
            if (matches.Length != 1 || matches[0].Length != 64)
            {
                throw new NingRanException("单文件保险箱的识别信息缺失或已经损坏。");
            }
            var bytes = new byte[64];
            try
            {
                await using var input = matches[0].Open();
                await input.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
                return VaultFormat.ParseInfoBytes(containerPath, bytes);
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (NingRanException) { throw; }
        catch (InvalidDataException exception)
        {
            throw new NingRanException("单文件保险箱内容损坏，无法读取识别信息。", exception);
        }
    }

    public static void DeleteWorkingDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }
}
