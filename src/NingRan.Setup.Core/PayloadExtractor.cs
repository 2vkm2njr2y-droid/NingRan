using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace NingRan.Setup;

public static class PayloadExtractor
{
    public static async Task ExtractAndVerifyAsync(
        Stream payloadZip,
        string destination,
        IProgress<SetupProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payloadZip);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destination));
        if (File.Exists(root) ||
            (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any()))
        {
            throw new InvalidOperationException("安装临时位置已经存在，已停止处理。");
        }

        Directory.CreateDirectory(root);
        try
        {
            using var archive = new ZipArchive(payloadZip, ZipArchiveMode.Read, leaveOpen: true);
            var entries = archive.Entries
                .Where(entry => !string.IsNullOrEmpty(entry.Name))
                .ToArray();
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var index = 0; index < entries.Length; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var entry = entries[index];
                var relativePath = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                var outputPath = GetSafeOutputPath(root, relativePath);
                if (!seenPaths.Add(outputPath))
                {
                    throw new InvalidDataException("安装包中包含重复文件，已停止安装。");
                }

                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                VerifyDirectoryChain(root, Path.GetDirectoryName(outputPath)!);
                await using var source = entry.Open();
                await using var output = new FileStream(
                    outputPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    1024 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await source.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                progress?.Report(new SetupProgress(
                    Math.Min(65, 5 + ((index + 1) * 60 / Math.Max(entries.Length, 1))),
                    $"正在准备：{entry.Name}"));
            }

            await VerifyAsync(root, progress, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            SafeDirectoryTree.Delete(root);
            throw;
        }
    }

    public static async Task VerifyAsync(
        string directory,
        IProgress<SetupProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        var manifestPath = Path.Combine(root, SetupProduct.PayloadManifestName);
        if (!File.Exists(manifestPath))
        {
            throw new InvalidDataException("安装包缺少完整性清单。");
        }

        var manifestJson = await File.ReadAllTextAsync(manifestPath, cancellationToken).ConfigureAwait(false);
        var manifest = JsonSerializer.Deserialize(manifestJson, SetupJsonContext.Default.PayloadManifest)
            ?? throw new InvalidDataException("安装包完整性清单无法读取。");
        if (!string.Equals(manifest.ProductId, SetupProduct.Id, StringComparison.Ordinal) ||
            !string.Equals(manifest.Version, SetupProduct.Version, StringComparison.Ordinal))
        {
            throw new InvalidDataException("安装包内的程序版本不匹配。");
        }

        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < manifest.Files.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var item = manifest.Files[index];
            var path = GetSafeOutputPath(root, item.Path.Replace('/', Path.DirectorySeparatorChar));
            if (!expected.Add(path) || !File.Exists(path))
            {
                throw new InvalidDataException("安装包缺少文件或清单中存在重复项目。");
            }

            var info = new FileInfo(path);
            if (info.Length != item.Size)
            {
                throw new InvalidDataException($"安装文件大小不正确：{item.Path}");
            }

            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            var actual = Convert.ToHexString(hash);
            CryptographicOperations.ZeroMemory(hash);
            if (!string.Equals(actual, item.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"安装文件完整性检查失败：{item.Path}");
            }

            progress?.Report(new SetupProgress(
                Math.Min(90, 65 + ((index + 1) * 25 / Math.Max(manifest.Files.Count, 1))),
                $"正在核对：{Path.GetFileName(item.Path)}"));
        }

        var actualFiles = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(path => !string.Equals(path, manifestPath, StringComparison.OrdinalIgnoreCase));
        if (actualFiles.Any(path => !expected.Contains(Path.GetFullPath(path))))
        {
            throw new InvalidDataException("安装包包含清单之外的文件，已停止安装。");
        }
    }

    private static string GetSafeOutputPath(string root, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            Path.IsPathRooted(relativePath) ||
            relativePath.IndexOfAny([Path.AltDirectorySeparatorChar, ':']) >= 0)
        {
            throw new InvalidDataException("安装包包含不安全的文件路径。");
        }

        var outputPath = Path.GetFullPath(Path.Combine(root, relativePath));
        if (!outputPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("安装包中的文件试图写出安装范围。");
        }

        return outputPath;
    }

    private static void VerifyDirectoryChain(string root, string directory)
    {
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var fullDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        if (!string.Equals(fullDirectory, fullRoot, StringComparison.OrdinalIgnoreCase) &&
            !fullDirectory.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("安装包路径超出了安全目录范围。");
        }

        var current = fullRoot;
        var relative = Path.GetRelativePath(fullRoot, fullDirectory);
        if (relative == ".") return;
        foreach (var part in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("安装包试图通过快捷链接或目录联接写出安全目录。");
            }
        }
    }
}
