using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using NingRan.Core;

namespace NingRan.Windows;

/// <summary>
/// 记录交给 Windows 默认程序的明文临时文件。文件只在当前程序运行期间保留，
/// 关闭时会检查大小和哈希，必要时交给主窗口写回加密包。
/// </summary>
internal sealed class DefaultProgramOpenTracker
{
    private readonly List<DefaultProgramOpenFile> _files = [];

    public IReadOnlyList<DefaultProgramOpenFile> Files => _files;

    public async Task<DefaultProgramOpenFile> ExportAndOpenAsync(
        SecureArchiveSession session,
        SecureArchiveEntry entry,
        CancellationToken cancellationToken = default)
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            $".ningran-default-open-{Guid.NewGuid():N}.part");
        Directory.CreateDirectory(directory);
        try
        {
            var exported = await session.ExportSelectionAsync(
                entry.RelativePath,
                directory,
                entry.Name,
                progress: null,
                cancellationToken: cancellationToken).ConfigureAwait(true);
            var temporaryPath = exported.OutputPath;
            var originalLength = new FileInfo(temporaryPath).Length;
            var originalHash = ComputeHash(temporaryPath);
            // ShellExecute 交给已经运行的单实例程序（例如 PotPlayer）时，Windows
            // 可能已经成功把文件交给目标程序，却不会返回 Process 对象。
            // 这里不能把 null 当成失败，否则 catch 会马上删除临时文件，目标程序
            // 随后只能显示“找不到文件”。真正的启动失败会通过 Win32Exception 抛出。
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = temporaryPath,
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(temporaryPath) ?? directory,
            });

            var tracked = new DefaultProgramOpenFile(
                session,
                session.ArchivePath,
                entry.RelativePath,
                temporaryPath,
                directory,
                originalLength,
                originalHash,
                process);
            _files.Add(tracked);
            return tracked;
        }
        catch
        {
            TryDeleteDirectory(directory);
            throw;
        }
    }

    public IReadOnlyList<DefaultProgramOpenFile> GetChangedFiles()
    {
        var changed = new List<DefaultProgramOpenFile>();
        foreach (var file in _files)
        {
            try
            {
                if (!File.Exists(file.TemporaryPath)) continue;
                var info = new FileInfo(file.TemporaryPath);
                if (info.Length != file.OriginalLength ||
                    !CryptographicOperations.FixedTimeEquals(file.OriginalHash, ComputeHash(file.TemporaryPath)))
                {
                    changed.Add(file);
                }
            }
            catch
            {
                // 无法读取时不能静默丢弃外部程序的修改；交给关闭流程提示并重试。
                changed.Add(file);
            }
        }

        return changed;
    }

    public void Cleanup()
    {
        foreach (var file in _files)
        {
            try
            {
                if (file.Process is not null && !file.Process.HasExited)
                {
                    file.Process.CloseMainWindow();
                    file.Process.WaitForExit(2_000);
                }
            }
            catch { }
            finally
            {
                file.Process?.Dispose();
            }

            TryDeleteDirectory(file.TemporaryDirectory);
        }

        _files.Clear();
    }

    private static byte[] ComputeHash(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            128 * 1024, FileOptions.SequentialScan);
        return SHA256.HashData(input);
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch
        {
            // 下次启动时由系统临时目录或用户清理；当前关闭流程继续进行。
        }
    }
}

internal sealed record DefaultProgramOpenFile(
    SecureArchiveSession Session,
    string ArchivePath,
    string RelativePath,
    string TemporaryPath,
    string TemporaryDirectory,
    long OriginalLength,
    byte[] OriginalHash,
    Process? Process);
