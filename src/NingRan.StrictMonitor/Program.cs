using System.ComponentModel;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using NingRan.Security;

if (!NativeElevationBinding.TryConsume(args, out var applicationArguments, out var elevationBinding, out _) ||
    elevationBinding?.IsMode(NativeElevationBinding.Modes.StrictMonitor) != true)
{
    return;
}

using var nativeElevationBinding = elevationBinding;
args = applicationArguments.ToArray();

if (!TryReadArguments(args, out var pipeName, out var targetProcessId))
{
    return;
}

using var shutdown = new CancellationTokenSource();
try
{
    await using var client = new NamedPipeClientStream(
        ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    await client.ConnectAsync(TimeSpan.FromSeconds(20), shutdown.Token).ConfigureAwait(false);
    if (!NamedPipeProcessIdentity.IsServerProcess(client.SafePipeHandle, targetProcessId))
    {
        return;
    }

    using var reader = new StreamReader(client, leaveOpen: true);
    await using var writer = new StreamWriter(client, leaveOpen: true) { AutoFlush = true };

    await writer.WriteLineAsync(JsonSerializer.Serialize(new MonitorMessage("hello"))).ConfigureAwait(false);
    var configurationLine = await reader.ReadLineAsync(shutdown.Token).ConfigureAwait(false);
    var configuration = JsonSerializer.Deserialize<MonitorConfiguration>(configurationLine ?? string.Empty);
    if (configuration is null || !configuration.Targets.Any(target => target.ProcessId == targetProcessId))
    {
        return;
    }

    await writer.WriteLineAsync(JsonSerializer.Serialize(new MonitorMessage("ready"))).ConfigureAwait(false);
    var controlTask = reader.ReadLineAsync(shutdown.Token).AsTask();
    var reported = new HashSet<string>(StringComparer.Ordinal);
    var protectedTargets = configuration.Targets
        .Where(target => target.ProcessId > 0)
        .Append(new ProtectedProcess(Environment.ProcessId, MonitorText.T("严格防护监控程序")))
        .DistinctBy(target => target.ProcessId)
        .ToArray();
    while (!shutdown.IsCancellationRequested && IsRunning(targetProcessId))
    {
        var controlCompleted = await Task.WhenAny(controlTask, Task.Delay(TimeSpan.FromSeconds(1), shutdown.Token))
            .ConfigureAwait(false);
        if (controlCompleted == controlTask)
        {
            var controlMessage = await controlTask.ConfigureAwait(false);
            if (controlMessage is null || string.Equals(controlMessage, "stop", StringComparison.Ordinal))
            {
                return;
            }

            controlTask = reader.ReadLineAsync(shutdown.Token).AsTask();
        }

        foreach (var target in protectedTargets.Where(target => IsRunning(target.ProcessId)))
        {
            IReadOnlyList<ProcessHandleAccess> accesses;
            try
            {
                accesses = ProcessHandleScanner.FindMemoryReaders(target.ProcessId);
            }
            catch (Exception exception) when (exception is InvalidOperationException or OutOfMemoryException or OverflowException)
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(new MonitorMessage(
                    "health-failed",
                    TargetComponent: target.Component,
                    FailureReason: MonitorText.T("Windows 无法完成系统句柄检查，严格防护已按失效保护停止。")))).ConfigureAwait(false);
                return;
            }

            foreach (var access in accesses)
            {
                var key = $"{target.ProcessId}:{access.ProcessId}:{access.HandleValue}:{access.AccessMask:X8}";
                if (!reported.Add(key))
                {
                    continue;
                }

                await writer.WriteLineAsync(JsonSerializer.Serialize(new MonitorMessage(
                    "alert", access.ProcessId, ProcessAllowList.GetImagePath(access.ProcessId), access.AccessMask,
                    DateTimeOffset.UtcNow, TargetComponent: target.Component))).ConfigureAwait(false);
            }
        }

        await writer.WriteLineAsync(JsonSerializer.Serialize(new MonitorMessage(
            "health-ok", OccurredAtUtc: DateTimeOffset.UtcNow))).ConfigureAwait(false);
    }
}
catch (OperationCanceledException)
{
}
catch (IOException)
{
}

static bool TryReadArguments(string[] arguments, out string pipeName, out int targetProcessId)
{
    pipeName = string.Empty;
    targetProcessId = 0;
    for (var index = 0; index + 1 < arguments.Length; index += 2)
    {
        if (string.Equals(arguments[index], "--pipe", StringComparison.Ordinal)) pipeName = arguments[index + 1];
        if (string.Equals(arguments[index], "--target", StringComparison.Ordinal) &&
            !int.TryParse(arguments[index + 1], out targetProcessId)) return false;
    }

    return arguments.Length == 4 &&
           pipeName.StartsWith("NingRan.StrictMonitor.", StringComparison.Ordinal) &&
           targetProcessId > 0;
}

static bool IsRunning(int processId)
{
    try
    {
        using var process = Process.GetProcessById(processId);
        return !process.HasExited;
    }
    catch (ArgumentException)
    {
        return false;
    }
}

internal sealed record ProtectedProcess(int ProcessId, string Component);
internal sealed record MonitorConfiguration(IReadOnlyList<ProtectedProcess> Targets,
    IReadOnlyList<AllowedProcessIdentity> AllowedProcesses);
internal sealed record AllowedProcessIdentity(string Path, string Sha256);
internal sealed record MonitorMessage(string Kind, int ProcessId = 0, string? ProcessPath = null,
    uint AccessMask = 0, DateTimeOffset? OccurredAtUtc = null, string? TargetComponent = null,
    string? FailureReason = null);

internal static class NamedPipeProcessIdentity
{
    public static bool IsServerProcess(SafePipeHandle pipe, int expectedProcessId) =>
        expectedProcessId > 0 &&
        GetNamedPipeServerProcessId(pipe, out var serverProcessId) &&
        serverProcessId == (uint)expectedProcessId;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe,
        out uint serverProcessId);
}

internal sealed record ProcessHandleAccess(int ProcessId, nint HandleValue, uint AccessMask);

internal static class ProcessHandleScanner
{
    private const int SystemExtendedHandleInformation = 64;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessDuplicate = 0x0040;
    private const uint ProcessCreateThread = 0x0002;
    private const uint SuspiciousAccess = ProcessVmOperation | ProcessVmRead | ProcessVmWrite |
                                          ProcessDuplicate | ProcessCreateThread;

    public static IReadOnlyList<ProcessHandleAccess> FindMemoryReaders(int targetProcessId)
    {
        // Keep a real handle to the protected process for the entire snapshot. Its kernel
        // object address lets us discard unrelated protected/PPL processes before trying
        // to duplicate anything, while preventing PID/object reuse during this scan.
        var target = OpenProcess(ProcessQueryLimitedInformation, false, targetProcessId);
        if (target == 0)
        {
            throw new InvalidOperationException(
                $"无法锁定受保护进程 {targetProcessId}（Windows 错误 {Marshal.GetLastWin32Error()}）。");
        }

        var size = 64 * 1024;
        nint buffer = 0;
        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(size);
                var status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, size, out var required);
                if (status == 0) break;
                Marshal.FreeHGlobal(buffer);
                buffer = 0;
                if (status != StatusInfoLengthMismatch || required <= size || required > 256 * 1024 * 1024)
                {
                    throw new InvalidOperationException(
                        $"Windows 系统句柄查询失败（状态 0x{unchecked((uint)status):X8}）。");
                }

                size = checked(required + 64 * 1024);
            }

            var count = Marshal.ReadIntPtr(buffer).ToInt64();
            if (count is < 0 or > 4_000_000)
            {
                throw new InvalidOperationException(MonitorText.T("Windows 返回了无效的系统句柄数量。"));
            }
            var itemSize = Marshal.SizeOf<SystemHandleTableEntryInfoEx>();
            var pointer = buffer + (IntPtr.Size * 2);
            var ownProcess = GetCurrentProcess();
            nint targetObject = 0;
            var ownProcessId = Environment.ProcessId;
            for (long index = 0; index < count; index++, pointer += itemSize)
            {
                var entry = Marshal.PtrToStructure<SystemHandleTableEntryInfoEx>(pointer);
                if (entry.UniqueProcessId.ToInt64() == ownProcessId && entry.HandleValue == target)
                {
                    targetObject = entry.Object;
                    break;
                }
            }

            if (targetObject == 0)
            {
                throw new InvalidOperationException(MonitorText.T("Windows 未返回受保护进程的可靠对象标识。"));
            }

            pointer = buffer + (IntPtr.Size * 2);
            var results = new List<ProcessHandleAccess>();
            for (long index = 0; index < count; index++, pointer += itemSize)
            {
                var entry = Marshal.PtrToStructure<SystemHandleTableEntryInfoEx>(pointer);
                var ownerProcessId = entry.UniqueProcessId.ToInt64();
                if (entry.Object != targetObject || ownerProcessId is <= 0 or > int.MaxValue ||
                    ownerProcessId == targetProcessId || ownerProcessId == ownProcessId ||
                    (entry.GrantedAccess & SuspiciousAccess) == 0)
                {
                    continue;
                }

                var owner = OpenProcess(ProcessDuplicateHandle, false, (int)ownerProcessId);
                if (owner == 0)
                {
                    throw new InvalidOperationException(
                        $"无法检查持有受保护进程句柄的进程 {ownerProcessId}（Windows 错误 {Marshal.GetLastWin32Error()}）。");
                }

                try
                {
                    if (!DuplicateHandle(owner, entry.HandleValue, ownProcess, out var copy, 0, false, DuplicateSameAccess))
                    {
                        throw new InvalidOperationException(
                            $"无法核验进程 {ownerProcessId} 持有的受保护句柄（Windows 错误 {Marshal.GetLastWin32Error()}）。");
                    }

                    try
                    {
                        if (GetProcessId(copy) != targetProcessId)
                        {
                            throw new InvalidOperationException(MonitorText.T("Windows 句柄快照在核验期间发生不一致。"));
                        }

                        results.Add(new ProcessHandleAccess((int)ownerProcessId, entry.HandleValue, entry.GrantedAccess));
                    }
                    finally
                    {
                        CloseHandle(copy);
                    }
                }
                finally
                {
                    CloseHandle(owner);
                }
            }

            return results;
        }
        finally
        {
            if (buffer != 0) Marshal.FreeHGlobal(buffer);
            CloseHandle(target);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemHandleTableEntryInfoEx
    {
        public nint Object;
        public nint UniqueProcessId;
        public nint HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass, nint information, int informationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(nint sourceProcessHandle, nint sourceHandle, nint targetProcessHandle,
        out nint targetHandle, uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern int GetProcessId(nint process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}

internal static class ProcessAllowList
{
    private static readonly HashSet<string> BuiltInAntivirusNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe", "SecurityHealthSystray.exe",
        "MpDefenderCoreService.exe", "MsSense.exe",
    };
    private static readonly ConcurrentDictionary<string, bool> SignatureChecks = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, string> ProcessImageHashes = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> MicrosoftPublisherNames = new(StringComparer.Ordinal)
    {
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
    };
    private static readonly string[] DefenderDirectories =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender Advanced Threat Protection"),
    ];

    public static bool IsAllowed(int processId, IReadOnlyList<AllowedProcessIdentity> allowedProcesses)
    {
        // Deliberately no automatic or custom allow-list. A process can retain
        // a legitimate image path and signature after suspended-process
        // replacement or injection, so those properties are not an identity
        // proof for a running memory reader.
        return false;
    }

    private static bool IsConfiguredProcessAllowed(
        int processId,
        string actualPath,
        IReadOnlyList<AllowedProcessIdentity> allowedProcesses)
    {
        var expected = allowedProcesses.FirstOrDefault(item =>
            string.Equals(Normalize(item.Path), actualPath, StringComparison.OrdinalIgnoreCase));
        if (expected is null || expected.Sha256.Length != 64 || !expected.Sha256.All(Uri.IsHexDigit))
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            var cacheKey = string.Concat(
                processId.ToString(System.Globalization.CultureInfo.InvariantCulture), "\0",
                process.StartTime.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture), "\0",
                actualPath);
            var actualHash = ProcessImageHashes.GetOrAdd(cacheKey, _ => ComputeSha256(actualPath));
            return actualHash.Length == 64 &&
                   string.Equals(actualHash, expected.Sha256, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or Win32Exception or InvalidOperationException or
                                             IOException or UnauthorizedAccessException or CryptographicException)
        {
            return false;
        }
    }

    private static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Delete, 128 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    public static string? GetImagePath(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return Normalize(process.MainModule?.FileName);
        }
        catch (Exception exception) when (exception is ArgumentException or Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }

    private static string? Normalize(string? path)
    {
        try { return string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    private static bool IsBuiltInAntivirusPath(string path)
    {
        var fileName = Path.GetFileName(path);
        if (string.Equals(fileName, "SecurityHealthService.exe", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fileName, "SecurityHealthSystray.exe", StringComparison.OrdinalIgnoreCase))
        {
            var systemDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            return IsDirectChildOfDirectory(path, systemDirectory);
        }

        return DefenderDirectories.Any(directory => IsWithinDirectory(path, directory));
    }

    private static bool IsMicrosoftSystemServiceHost(string path)
    {
        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "svchost.exe");
        if (!string.Equals(path, expected, StringComparison.OrdinalIgnoreCase)) return false;
        return IsTrustedMicrosoftBinary(path);
    }

    private static bool IsTrustedMicrosoftBinary(string path)
    {
        try
        {
            var file = new FileInfo(path);
            var cacheKey = string.Concat(path, "\0", file.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "\0", file.LastWriteTimeUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
            return SignatureChecks.GetOrAdd(cacheKey, _ => HasValidMicrosoftAuthenticodeSignature(path));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool HasValidMicrosoftAuthenticodeSignature(string path)
    {
        try
        {
            if (!VerifyAuthenticodeSignature(path)) return false;
#pragma warning disable SYSLIB0057 // Windows 的 Authenticode 签名需要从已签名 EXE 中读取证书。
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            var publisher = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            var subjectParts = certificate.SubjectName
                .Decode(X500DistinguishedNameFlags.UseNewLines)
                .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return MicrosoftPublisherNames.Contains(publisher) &&
                   subjectParts.Contains("O=Microsoft Corporation", StringComparer.Ordinal);
        }
        catch (Exception exception) when (exception is CryptographicException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private static bool VerifyAuthenticodeSignature(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = path,
        };
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
            var trustData = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2, // WTD_UI_NONE
                RevocationChecks = 0, // WTD_REVOKE_NONE；由 Windows 的 Authenticode 策略完成其余链验证。
                UnionChoice = 1, // WTD_CHOICE_FILE
                FileInfo = fileInfoPointer,
                StateAction = 0, // WTD_STATEACTION_IGNORE
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            return WinVerifyTrust(new nint(-1), ref action, ref trustData) == 0;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
        }
    }

    private static bool IsDirectChildOfDirectory(string path, string directory)
    {
        var normalizedPath = Normalize(path);
        var normalizedDirectory = Normalize(directory);
        return normalizedPath is not null && normalizedDirectory is not null &&
               string.Equals(Path.GetDirectoryName(normalizedPath),
                   Path.TrimEndingDirectorySeparator(normalizedDirectory),
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWithinDirectory(string path, string directory)
    {
        var normalizedPath = Normalize(path);
        var normalizedDirectory = Normalize(directory);
        if (normalizedPath is null || normalizedDirectory is null) return false;
        var relative = Path.GetRelativePath(normalizedDirectory, normalizedPath);
        return !Path.IsPathRooted(relative) &&
               !string.Equals(relative, "..", StringComparison.Ordinal) &&
               !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
               !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public nint FileHandle;
        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public nint FileInfo;
        public uint StateAction;
        public nint StateData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(
        nint windowHandle,
        ref Guid action,
        ref WinTrustData trustData);
}

internal static class MonitorText
{
    private static readonly Dictionary<string, string> English = new(StringComparer.Ordinal)
    {
        ["严格防护监控程序"] = "NingRan Strict Protection Monitor",
        ["Windows 无法完成系统句柄检查，严格防护已按失效保护停止。"] = "Windows could not complete the system-handle check. Strict Protection stopped in fail-safe mode.",
        ["Windows 返回了无效的系统句柄数量。"] = "Windows returned an invalid system-handle count.",
        ["Windows 未返回受保护进程的可靠对象标识。"] = "Windows did not return a reliable object identifier for the protected process.",
        ["Windows 句柄快照在核验期间发生不一致。"] = "The Windows handle snapshot changed during verification.",
    };

    public static string T(string value)
    {
        try
        {
            var marker = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath) ?? string.Empty, "language.txt");
            if (string.Equals(File.ReadAllText(marker).Trim(), "en", StringComparison.OrdinalIgnoreCase) &&
                English.TryGetValue(value, out var translated))
            {
                return translated;
            }
        }
        catch { }

        return value;
    }
}
