namespace NingRan.Setup;

public static class SafeDirectoryTree
{
    public static UserDataInventory Inspect(string path, CancellationToken cancellationToken = default)
    {
        var fullPath = Path.GetFullPath(path);
        if (!Directory.Exists(fullPath))
        {
            return new UserDataInventory(0, 0, 0);
        }

        long fileCount = 0;
        long directoryCount = 0;
        long totalBytes = 0;
        var pending = new Stack<string>();
        pending.Push(fullPath);
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = pending.Pop();
            foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    if (entry is DirectoryInfo)
                    {
                        directoryCount++;
                    }
                    else
                    {
                        fileCount++;
                        totalBytes = checked(totalBytes + ((FileInfo)entry).Length);
                    }

                    continue;
                }

                if (entry is DirectoryInfo directory)
                {
                    directoryCount++;
                    pending.Push(directory.FullName);
                }
                else if (entry is FileInfo file)
                {
                    fileCount++;
                    totalBytes = checked(totalBytes + file.Length);
                }
            }
        }

        return new UserDataInventory(fileCount, directoryCount, totalBytes);
    }

    public static void DeleteUserData(string path)
    {
        var expected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.UserDataPath));
        var actual = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("个人数据删除位置不正确，已拒绝删除。");
        }

        Delete(actual);
    }

    public static void Delete(string path)
    {
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!Directory.Exists(fullPath))
        {
            return;
        }

        DeleteDirectory(fullPath);
    }

    private static void DeleteDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
        {
            return;
        }

        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            directory.Delete(recursive: false);
            return;
        }

        foreach (var entry in directory.EnumerateFileSystemInfos())
        {
            if (entry is DirectoryInfo childDirectory)
            {
                DeleteDirectory(childDirectory.FullName);
            }
            else
            {
                entry.Attributes &= ~FileAttributes.ReadOnly;
                entry.Delete();
            }
        }

        directory.Attributes &= ~FileAttributes.ReadOnly;
        directory.Delete(recursive: false);
    }
}
