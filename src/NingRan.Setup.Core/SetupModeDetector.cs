namespace NingRan.Setup;

public static class SetupModeDetector
{
    public static bool ShouldUninstall(IEnumerable<string> arguments, string executableDirectory)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentException.ThrowIfNullOrWhiteSpace(executableDirectory);
        if (arguments.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        return InstallState.TryLoad(Path.GetFullPath(executableDirectory)) is not null;
    }
}
