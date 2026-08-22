using NingRan.Core.Internal;

namespace NingRan.Core;

public static class NingRanRuntime
{
    public static bool IsProcessElevated() => WindowsFileSystemSafety.IsProcessElevated();
}
