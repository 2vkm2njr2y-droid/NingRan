using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace NingRan.NativeBootstrap;

internal static class Program
{
    private const string PublicLaunchArgument = "--ningran-launch";
    private const string InternalElevationArgument = "--ningran-internal-elevated";
    private const string InternalSetupArgument = "--ningran-setup-elevated";
#if NINGRAN_MEDIA_PLAYER
    private const string SetupProductName = "凝然媒体播放器";
    private const string SecurityLauncherName = "NingRan.SecurityLauncher.exe";
    private const string MainExecutableName = "NingRan.MediaPlayer.exe";
    private const string StrictMonitorName = "NingRan.StrictMonitor.exe";
    private const string InstallDirectoryName = "凝然媒体播放器";
#else
    private const string SetupProductName = "凝然加密";
    private const string SecurityLauncherName = "NingRan.SecurityLauncher.exe";
    private const string MainExecutableName = "NingRan.exe";
    private const string StrictMonitorName = "NingRan.StrictMonitor.exe";
    private const string InstallDirectoryName = "凝然加密";
#endif
    private const string RelayPrefix = "NingRan.Elevation.";
    private const int CancelledExitCode = 1223;
    private static readonly byte[] BundleMagic = Encoding.ASCII.GetBytes("NRSETUP1");

    private static int Main(string[] args)
    {
        SanitizeDotNetEnvironment();
        try
        {
            if (args.Length == 1 && args[0] == "--self-test-sanitize")
                return RunSanitizationSelfTest();

            var selfPath = Path.GetFullPath(Environment.ProcessPath
                ?? throw new InvalidOperationException("Windows did not provide the bootstrap path."));
            using var selfStream = OpenLockedOrdinaryFile(selfPath);
            var bundle = TryReadBundle(selfStream);
            if (args.Length == 1 && args[0] == "--self-test-overlay")
                return bundle is not null && VerifyBundlePayload(selfStream, bundle) ? 0 : 2;

            return bundle is null
                ? RunSecurityLauncher(selfPath, args)
                : RunSetupBootstrap(selfPath, selfStream, bundle, args);
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == CancelledExitCode)
        {
            WriteStatus("NINGRAN_CANCELLED");
            return CancelledExitCode;
        }
        catch (Exception exception)
        {
            WriteStatus("NINGRAN_ERROR=" + exception.GetType().Name);
            ShowStartupError(exception);
            return 2;
        }
    }

    private static void ShowStartupError(Exception exception)
    {
        try
        {
            var message = "安装程序无法启动。请重新运行安装包。";
            if (!string.IsNullOrWhiteSpace(exception.Message))
            {
                message += "\n\n" + exception.Message;
            }

            _ = MessageBoxW(
                nint.Zero,
                message,
                $"{SetupProductName}安装程序",
                MessageBoxTypeError | MessageBoxTypeOk);
        }
        catch
        {
            // A desktop notification is best-effort; the status line remains
            // available to diagnostics when no interactive desktop exists.
        }
    }

    private static int RunSecurityLauncher(string selfPath, IReadOnlyList<string> args)
    {
        if (!PathsEqual(selfPath, GetInstalledPath(SecurityLauncherName)) || !IsOrdinaryPath(selfPath))
            throw new UnauthorizedAccessException("The security launcher is outside the protected installation.");

        if (args.Count > 0 && args[0] == InternalElevationArgument)
            return RunElevatedSecurityRequest(selfPath, args);

        var request = ParseSecurityRequest(args);
        using var caller = OpenAndVerifyActualParent(GetInstalledPath(MainExecutableName));
        return IsProcessElevated()
            ? RunSecurityTarget(request, null, CreateNonce())
            : RelaySecurityElevation(selfPath, request);
    }

    private static int RelaySecurityElevation(string selfPath, SecurityRequest request)
    {
        var requesterPid = Environment.ProcessId;
        var nonce = CreateNonce();
        var pipeName = RelayPrefix + requesterPid.ToString(CultureInfo.InvariantCulture) + "." + nonce;
        using var server = new NamedPipeServerStream(pipeName, PipeDirection.In, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var info = new ProcessStartInfo(selfPath)
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Path.GetDirectoryName(selfPath),
        };
        foreach (var value in new[]
                 {
                     InternalElevationArgument,
                     requesterPid.ToString(CultureInfo.InvariantCulture),
                     pipeName,
                     nonce,
                     request.Mode,
                 })
            info.ArgumentList.Add(value);
        foreach (var value in request.BusinessArguments) info.ArgumentList.Add(value);

        using var elevated = Process.Start(info)
            ?? throw new InvalidOperationException("Windows did not start the elevated native launcher.");
        var childPid = WaitForAuthenticatedRelay(server, elevated, nonce);
        WriteStatus("NINGRAN_CHILD_PID=" + childPid.ToString(CultureInfo.InvariantCulture));
        elevated.WaitForExit();
        return elevated.ExitCode;
    }

    private static int RunElevatedSecurityRequest(string selfPath, IReadOnlyList<string> args)
    {
        if (!IsProcessElevated() || args.Count < 5 ||
            !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out var requesterPid) ||
            requesterPid <= 0 || !IsCanonicalNonce(args[3]))
            throw new UnauthorizedAccessException("The elevated native request is invalid.");

        var expectedPipe = RelayPrefix + requesterPid.ToString(CultureInfo.InvariantCulture) + "." + args[3];
        if (args[2] != expectedPipe) throw new UnauthorizedAccessException("The relay binding is invalid.");
        using var requester = Process.GetProcessById(requesterPid);
        if (requester.HasExited || !PathsEqual(GetProcessImagePath(requester), selfPath))
            throw new UnauthorizedAccessException("The requester is no longer the installed native launcher.");
        using var caller = OpenAndVerifyParentOf(requester, GetInstalledPath(MainExecutableName));

        var publicArgs = new List<string> { PublicLaunchArgument, args[4] };
        for (var index = 5; index < args.Count; index++) publicArgs.Add(args[index]);
        return RunSecurityTarget(ParseSecurityRequest(publicArgs), args[2], args[3]);
    }

    private static int RunSecurityTarget(SecurityRequest request, string? relayPipeName, string relayNonce)
    {
        using var runtimeDirectory = ProtectedRuntimeDirectory.Create("NingRan.Runtime-");
        ConfigureManagedChildEnvironment(runtimeDirectory.Path);
        var targetName = request.Mode == Modes.StrictMonitor ? StrictMonitorName : MainExecutableName;
        var targetPath = GetInstalledPath(targetName);
        if (!IsOrdinaryPath(targetPath))
            throw new UnauthorizedAccessException("The managed security target is missing or linked.");

        var info = new ProcessStartInfo(targetPath)
        {
            UseShellExecute = false,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        };
        foreach (var value in request.BusinessArguments) info.ArgumentList.Add(value);
        info.ArgumentList.Add("--ningran-native-parent");
        info.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
        info.ArgumentList.Add("--ningran-native-nonce");
        info.ArgumentList.Add(relayNonce);
        info.ArgumentList.Add("--ningran-native-mode");
        info.ArgumentList.Add(request.Mode);

        using var child = Process.Start(info)
            ?? throw new InvalidOperationException("Windows did not start the managed security component.");
        try
        {
            if (relayPipeName is not null)
            {
                using var client = new NamedPipeClientStream(".", relayPipeName, PipeDirection.Out);
                client.Connect(TimeSpan.FromSeconds(20));
                using var writer = new StreamWriter(client, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
                writer.WriteLine(relayNonce + "|" + child.Id.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                WriteStatus("NINGRAN_CHILD_PID=" + child.Id.ToString(CultureInfo.InvariantCulture));
            }
        }
        catch
        {
            TryTerminate(child);
            throw;
        }
        child.WaitForExit();
        return child.ExitCode;
    }

    private static SecurityRequest ParseSecurityRequest(IReadOnlyList<string> args)
    {
        if (args.Count < 2 || args[0] != PublicLaunchArgument)
            throw new ArgumentException("The native elevation mode is missing.");
        var mode = args[1];
        var business = args.Skip(2).ToArray();
        var valid = mode switch
        {
            Modes.HighSecurity => business.Length == 2 && business[0] == "--high-security-open" &&
                                  IsExistingArchive(business[1]),
            Modes.StrictSettings => business.Length == 1 && business[0] == "--manage-strict-protection",
            Modes.TrustedContact => business.Length == 7 && business[0] == "--trusted-contact-request" &&
                                    business.All(value => value.Length is > 0 and <= 4096),
            Modes.StrictMonitor => business.Length == 4 && business[0] == "--pipe" &&
                                   business[1].StartsWith("NingRan.StrictMonitor.", StringComparison.Ordinal) &&
                                   business[1].Length <= 256 && business[2] == "--target" &&
                                   int.TryParse(business[3], NumberStyles.None, CultureInfo.InvariantCulture,
                                       out var targetPid) && targetPid > 0,
            _ => false,
        };
        return valid ? new SecurityRequest(mode, business)
            : throw new ArgumentException("The native elevation request is malformed.");
    }

    private static int RunSetupBootstrap(string selfPath, FileStream selfStream, BundleInfo bundle,
        IReadOnlyList<string> args)
    {
        if (!VerifyBundlePayload(selfStream, bundle))
            throw new InvalidDataException("The embedded setup payload is damaged.");
        if (args.Count > 0 && args[0] == InternalSetupArgument)
        {
            if (!IsProcessElevated() || args.Count < 2 || !IsCanonicalNonce(args[1]))
                throw new UnauthorizedAccessException("The elevated setup request is invalid.");
            return RunSetupWorker(selfPath, selfStream, bundle, args.Skip(2).ToArray());
        }
        if (IsProcessElevated()) return RunSetupWorker(selfPath, selfStream, bundle, args);

        var info = new ProcessStartInfo(selfPath)
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Path.GetDirectoryName(selfPath),
        };
        info.ArgumentList.Add(InternalSetupArgument);
        info.ArgumentList.Add(CreateNonce());
        foreach (var value in args) info.ArgumentList.Add(value);
        using var elevated = Process.Start(info)
            ?? throw new InvalidOperationException("Windows did not start the elevated setup bootstrap.");
        elevated.WaitForExit();
        return elevated.ExitCode;
    }

    private static int RunSetupWorker(string selfPath, FileStream selfStream, BundleInfo bundle,
        IReadOnlyList<string> businessArguments)
    {
        using var runtimeDirectory = ProtectedRuntimeDirectory.Create("NingRan.SetupRuntime-");
        ConfigureManagedChildEnvironment(runtimeDirectory.Path);
        var workerPath = Path.Combine(runtimeDirectory.Path, "NingRanSetup.Worker.exe");
        ExtractBundlePayload(selfStream, bundle, workerPath);
        var info = new ProcessStartInfo(workerPath)
        {
            UseShellExecute = false,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        };
        foreach (var value in businessArguments) info.ArgumentList.Add(value);
        info.ArgumentList.Add("--ningran-bootstrap-origin");
        info.ArgumentList.Add(selfPath);
        info.ArgumentList.Add("--ningran-bootstrap-parent");
        info.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
        info.ArgumentList.Add("--ningran-bootstrap-payload-sha256");
        info.ArgumentList.Add(Convert.ToHexString(bundle.PayloadSha256));
        using var worker = Process.Start(info)
            ?? throw new InvalidOperationException("Windows did not start the managed setup worker.");
        worker.WaitForExit();
        return worker.ExitCode;
    }

    private static int WaitForAuthenticatedRelay(NamedPipeServerStream server, Process elevated, string nonce)
    {
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (DateTime.UtcNow < deadline)
        {
            if (elevated.HasExited) throw new IOException("The elevated launcher exited before relaying its child.");
            server.WaitForConnectionAsync().WaitAsync(deadline - DateTime.UtcNow).GetAwaiter().GetResult();
            if (GetNamedPipeClientProcessId(server.SafePipeHandle, out var clientPid) && clientPid == (uint)elevated.Id)
            {
                using var reader = new StreamReader(server, Encoding.UTF8, leaveOpen: true);
                var line = reader.ReadLine();
                var prefix = nonce + "|";
                if (line is not null && line.StartsWith(prefix, StringComparison.Ordinal) &&
                    int.TryParse(line.AsSpan(prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture,
                        out var childPid) && childPid > 0) return childPid;
                throw new InvalidDataException("The native relay response is invalid.");
            }
            server.Disconnect();
        }
        throw new TimeoutException("Timed out waiting for the elevated native launcher.");
    }

    private static Process OpenAndVerifyActualParent(string expectedPath)
    {
        using var current = Process.GetCurrentProcess();
        var parent = Process.GetProcessById(GetActualParentProcessId(current));
        if (!parent.HasExited && PathsEqual(GetProcessImagePath(parent), expectedPath)) return parent;
        parent.Dispose();
        throw new UnauthorizedAccessException("The native launcher was not started by NingRan.exe.");
    }

    private static Process OpenAndVerifyParentOf(Process process, string expectedPath)
    {
        var parent = Process.GetProcessById(GetActualParentProcessId(process));
        if (!parent.HasExited && PathsEqual(GetProcessImagePath(parent), expectedPath)) return parent;
        parent.Dispose();
        throw new UnauthorizedAccessException("The requester was not started by NingRan.exe.");
    }

    private static int GetActualParentProcessId(Process process)
    {
        var status = NtQueryInformationProcess(process.Handle, 0, out var information,
            Marshal.SizeOf<ProcessBasicInformation>(), out _);
        var value = information.InheritedFromUniqueProcessId.ToInt64();
        if (status != 0 || value is <= 0 or > int.MaxValue)
            throw new Win32Exception(status, "Windows did not provide the real parent process.");
        return (int)value;
    }

    private static string GetProcessImagePath(Process process) => Path.GetFullPath(process.MainModule?.FileName
        ?? throw new InvalidOperationException("Windows did not provide a process image path."));

    private static string GetInstalledPath(string name) => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), InstallDirectoryName, name));

    private static bool IsExistingArchive(string path)
    {
        try
        {
            return Path.IsPathFullyQualified(path) && File.Exists(path) &&
                   string.Equals(Path.GetExtension(path), ".nrenc", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static bool IsOrdinaryPath(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) return false;
            var root = Path.GetPathRoot(full);
            if (string.IsNullOrWhiteSpace(root)) return false;
            var current = Path.TrimEndingDirectorySeparator(root);
            foreach (var segment in Path.GetRelativePath(root, Path.GetDirectoryName(full)!).Split(
                         [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, segment);
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
            }
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                             ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static FileStream OpenLockedOrdinaryFile(string path)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024,
            FileOptions.SequentialScan);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0) return stream;
        stream.Dispose();
        throw new UnauthorizedAccessException("The native bootstrap cannot run through a file link.");
    }

    private static BundleInfo? TryReadBundle(FileStream stream)
    {
        const int footerSize = 48;
        if (stream.Length <= footerSize) return null;
        Span<byte> footer = stackalloc byte[footerSize];
        stream.Position = stream.Length - footerSize;
        stream.ReadExactly(footer);
        if (!footer[..8].SequenceEqual(BundleMagic)) return null;
        var payloadLength = BitConverter.ToInt64(footer.Slice(8, 8));
        var payloadOffset = stream.Length - footerSize - payloadLength;
        if (payloadLength <= 0 || payloadOffset <= 0) throw new InvalidDataException("Invalid setup footer.");
        return new BundleInfo(payloadOffset, payloadLength, footer.Slice(16, 32).ToArray());
    }

    private static bool VerifyBundlePayload(FileStream stream, BundleInfo bundle)
    {
        stream.Position = bundle.PayloadOffset;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        var remaining = bundle.PayloadLength;
        while (remaining > 0)
        {
            var count = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (count <= 0) return false;
            hash.AppendData(buffer, 0, count);
            remaining -= count;
        }
        return CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), bundle.PayloadSha256);
    }

    private static void ExtractBundlePayload(FileStream source, BundleInfo bundle, string destination)
    {
        source.Position = bundle.PayloadOffset;
        using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
            1024 * 1024, FileOptions.SequentialScan | FileOptions.WriteThrough);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        var remaining = bundle.PayloadLength;
        while (remaining > 0)
        {
            var count = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (count <= 0) throw new EndOfStreamException("Embedded setup ended early.");
            output.Write(buffer, 0, count);
            hash.AppendData(buffer, 0, count);
            remaining -= count;
        }
        output.Flush(true);
        if (!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), bundle.PayloadSha256))
            throw new InvalidDataException("Extracted setup hash mismatch.");
    }

    private static void SanitizeDotNetEnvironment()
    {
        foreach (var name in Environment.GetEnvironmentVariables().Keys.Cast<object>()
                     .Select(value => value.ToString()).Where(value => !string.IsNullOrWhiteSpace(value)).Cast<string>()
                     .Where(IsDangerousEnvironmentName).ToArray())
            Environment.SetEnvironmentVariable(name, null);
        Environment.SetEnvironmentVariable("DOTNET_EnableDiagnostics", "0");
        Environment.SetEnvironmentVariable("DOTNET_EnableDiagnostics_IPC", "0");
        Environment.SetEnvironmentVariable("DOTNET_EnableDiagnostics_Debugger", "0");
        Environment.SetEnvironmentVariable("DOTNET_EnableDiagnostics_Profiler", "0");
        Environment.SetEnvironmentVariable("CORECLR_ENABLE_PROFILING", "0");
        Environment.SetEnvironmentVariable("COR_ENABLE_PROFILING", "0");
    }

    private static bool IsDangerousEnvironmentName(string name) =>
        name.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("CORECLR_", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("COMPLUS_", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("COR_", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("STARTUP_HOOK", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("PROFILER", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("__COMPAT_LAYER", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("SEE_MASK_NOZONECHECKS", StringComparison.OrdinalIgnoreCase);

    private static void ConfigureManagedChildEnvironment(string protectedTemporaryDirectory)
    {
        SanitizeDotNetEnvironment();
        Environment.SetEnvironmentVariable("DOTNET_BUNDLE_EXTRACT_BASE_DIR", protectedTemporaryDirectory);
        Environment.SetEnvironmentVariable("TEMP", protectedTemporaryDirectory);
        Environment.SetEnvironmentVariable("TMP", protectedTemporaryDirectory);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Environment.SetEnvironmentVariable("PATH", string.Join(';', Path.Combine(windows, "System32"), windows,
            Path.Combine(windows, "System32", "Wbem"),
            Path.Combine(windows, "System32", "WindowsPowerShell", "v1.0")));
    }

    private static int RunSanitizationSelfTest()
    {
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            var name = entry.Key?.ToString() ?? string.Empty;
            var value = entry.Value?.ToString();
            if (!IsDangerousEnvironmentName(name)) continue;
            var permitted = value == "0" && new[]
            {
                "DOTNET_EnableDiagnostics", "DOTNET_EnableDiagnostics_IPC", "DOTNET_EnableDiagnostics_Debugger",
                "DOTNET_EnableDiagnostics_Profiler", "CORECLR_ENABLE_PROFILING", "COR_ENABLE_PROFILING",
            }.Contains(name, StringComparer.OrdinalIgnoreCase);
            if (!permitted) return 2;
        }
        WriteStatus("NINGRAN_SANITIZED");
        return 0;
    }

    private static bool IsProcessElevated()
    {
        // Asking for an explicit token access mask can throw SecurityException
        // for a normal desktop token under NativeAOT. The default identity
        // query is sufficient for the administrator-role check and works for
        // both the unelevated launcher and the UAC-elevated child.
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string CreateNonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private static bool IsCanonicalNonce(string? value) => value is not null && value.Length == 64 &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool PathsEqual(string left, string right)
    {
        try { return string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }
    private static void TryTerminate(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch { }
    }
    private static void WriteStatus(string value)
    {
        try { Console.Out.WriteLine(value); Console.Out.Flush(); }
        catch (IOException) { }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public nint Reserved1, PebBaseAddress, Reserved2_0, Reserved2_1, UniqueProcessId,
            InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(nint processHandle, int informationClass,
        out ProcessBasicInformation information, int informationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,
        out uint clientProcessId);

    private const uint MessageBoxTypeOk = 0x00000000;
    private const uint MessageBoxTypeError = 0x00000010;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBoxW(nint hWnd, string text, string caption, uint type);

    private sealed record SecurityRequest(string Mode, IReadOnlyList<string> BusinessArguments);
    private sealed record BundleInfo(long PayloadOffset, long PayloadLength, byte[] PayloadSha256);
    private static class Modes
    {
        public const string HighSecurity = "high-security";
        public const string StrictSettings = "strict-settings";
        public const string TrustedContact = "trusted-contact";
        public const string StrictMonitor = "strict-monitor";
    }

    private sealed class ProtectedRuntimeDirectory : IDisposable
    {
        private const uint MoveFileDelayUntilReboot = 4;
        private ProtectedRuntimeDirectory(string path) => Path = path;
        public string Path { get; }

        public static ProtectedRuntimeDirectory Create(string prefix)
        {
            if (!IsProcessElevated()) throw new UnauthorizedAccessException("Elevation is required.");
            var programData = System.IO.Path.GetFullPath(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData));
            if (!Directory.Exists(programData) ||
                (File.GetAttributes(programData) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("ProgramData is unavailable or linked.");
            var path = System.IO.Path.Combine(programData, prefix + Guid.NewGuid().ToString("N"));
            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(administrators);
            AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            AddFullControl(security, administrators);
            new DirectoryInfo(path).Create(security);
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("The runtime directory was linked.");
            return new ProtectedRuntimeDirectory(path);
        }

        public void Dispose()
        {
            try { DeleteTree(Path); }
            catch
            {
                try
                {
                    foreach (var entry in new DirectoryInfo(Path).EnumerateFileSystemInfos())
                        _ = MoveFileExW(entry.FullName, null, MoveFileDelayUntilReboot);
                    _ = MoveFileExW(Path, null, MoveFileDelayUntilReboot);
                }
                catch { }
            }
        }

        private static void AddFullControl(DirectorySecurity security, SecurityIdentifier identity) =>
            security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
                AccessControlType.Allow));

        private static void DeleteTree(string path)
        {
            if (!Directory.Exists(path)) return;
            foreach (var entry in new DirectoryInfo(path).EnumerateFileSystemInfos())
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0 || entry is FileInfo) entry.Delete();
                else DeleteTree(entry.FullName);
            }
            Directory.Delete(path, false);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileExW(string existingFileName, string? newFileName, uint flags);
    }
}
