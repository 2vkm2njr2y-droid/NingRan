using System.ComponentModel;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Text.Json;

if (!TryReadArguments(args, out var pipeName, out var targetProcessId, out var pipeToken))
{
    return;
}

using var shutdown = new CancellationTokenSource();
try
{
    await using var client = new NamedPipeClientStream(
        ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    await client.ConnectAsync(TimeSpan.FromSeconds(20), shutdown.Token).ConfigureAwait(false);
    using var reader = new StreamReader(client, leaveOpen: true);
    await using var writer = new StreamWriter(client, leaveOpen: true) { AutoFlush = true };

    await writer.WriteLineAsync(JsonSerializer.Serialize(new MonitorMessage("hello", Token: pipeToken))).ConfigureAwait(false);
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
        .Append(new ProtectedProcess(Environment.ProcessId, "严格防护监控程序"))
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
            foreach (var access in ProcessHandleScanner.FindMemoryReaders(target.ProcessId))
            {
                if (ProcessAllowList.IsAllowed(access.ProcessId, configuration.AllowedProcessPaths))
                {
                    continue;
                }

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
    }
}
catch (OperationCanceledException)
{
}
catch (IOException)
{
}

static bool TryReadArguments(string[] arguments, out string pipeName, out int targetProcessId, out string pipeToken)
{
    pipeName = string.Empty;
    targetProcessId = 0;
    pipeToken = string.Empty;
    for (var index = 0; index + 1 < arguments.Length; index += 2)
    {
        if (string.Equals(arguments[index], "--pipe", StringComparison.Ordinal)) pipeName = arguments[index + 1];
        if (string.Equals(arguments[index], "--target", StringComparison.Ordinal) &&
            !int.TryParse(arguments[index + 1], out targetProcessId)) return false;
        if (string.Equals(arguments[index], "--token", StringComparison.Ordinal)) pipeToken = arguments[index + 1];
    }

    return pipeName.StartsWith("NingRan.StrictMonitor.", StringComparison.Ordinal) && targetProcessId > 0 && pipeToken.Length == 64;
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
internal sealed record MonitorConfiguration(IReadOnlyList<ProtectedProcess> Targets, IReadOnlyList<string> AllowedProcessPaths);
internal sealed record MonitorMessage(string Kind, int ProcessId = 0, string? ProcessPath = null,
    uint AccessMask = 0, DateTimeOffset? OccurredAtUtc = null, string? Token = null, string? TargetComponent = null);

internal sealed record ProcessHandleAccess(int ProcessId, nint HandleValue, uint AccessMask);

internal static class ProcessHandleScanner
{
    private const int SystemExtendedHandleInformation = 64;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const uint ProcessDuplicateHandle = 0x0040;
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
                    return [];
                }

                size = checked(required + 64 * 1024);
            }

            var count = Marshal.ReadIntPtr(buffer).ToInt64();
            if (count is < 0 or > 4_000_000) return [];
            var itemSize = Marshal.SizeOf<SystemHandleTableEntryInfoEx>();
            var pointer = buffer + (IntPtr.Size * 2);
            var ownProcess = GetCurrentProcess();
            var results = new List<ProcessHandleAccess>();
            for (long index = 0; index < count; index++, pointer += itemSize)
            {
                var entry = Marshal.PtrToStructure<SystemHandleTableEntryInfoEx>(pointer);
                var ownerProcessId = entry.UniqueProcessId.ToInt64();
                if (ownerProcessId is <= 0 or > int.MaxValue || ownerProcessId == targetProcessId ||
                    ownerProcessId == Environment.ProcessId || (entry.GrantedAccess & SuspiciousAccess) == 0)
                {
                    continue;
                }

                var owner = OpenProcess(ProcessDuplicateHandle, false, (int)ownerProcessId);
                if (owner == 0) continue;
                try
                {
                    if (!DuplicateHandle(owner, entry.HandleValue, ownProcess, out var copy, 0, false, DuplicateSameAccess))
                    {
                        continue;
                    }

                    try
                    {
                        if (GetProcessId(copy) == targetProcessId)
                        {
                            results.Add(new ProcessHandleAccess((int)ownerProcessId, entry.HandleValue, entry.GrantedAccess));
                        }
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
        catch (OutOfMemoryException)
        {
            return [];
        }
        finally
        {
            if (buffer != 0) Marshal.FreeHGlobal(buffer);
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

    public static bool IsAllowed(int processId, IReadOnlyList<string> allowedProcessPaths)
    {
        var normalized = allowedProcessPaths.Select(Normalize).Where(path => path is not null)
            .Cast<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var relatedProcessId in GetRelatedProcessIds(processId))
        {
            var path = GetImagePath(relatedProcessId);
            if (path is null) continue;
            if (normalized.Contains(path)) return true;
            if (IsMicrosoftSystemServiceHost(path)) return true;
            if (BuiltInAntivirusNames.Contains(Path.GetFileName(path)) && IsBuiltInAntivirusPath(path))
            {
                return true;
            }
        }

        return false;
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

    private static IEnumerable<int> GetRelatedProcessIds(int processId)
    {
        var parents = GetParentMap();
        var children = parents.GroupBy(item => item.Value).ToDictionary(group => group.Key, group => group.Select(item => item.Key));
        var pending = new Queue<int>();
        var seen = new HashSet<int>();
        pending.Enqueue(processId);
        while (pending.Count > 0 && seen.Count < 128)
        {
            var current = pending.Dequeue();
            if (!seen.Add(current)) continue;
            yield return current;
            if (parents.TryGetValue(current, out var parent)) pending.Enqueue(parent);
            if (children.TryGetValue(current, out var descendants))
            {
                foreach (var child in descendants) pending.Enqueue(child);
            }
        }
    }

    private static Dictionary<int, int> GetParentMap()
    {
        var map = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(0x00000002, 0);
        if (snapshot == -1) return map;
        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!Process32First(snapshot, ref entry)) return map;
            do
            {
                map[(int)entry.ProcessId] = (int)entry.ParentProcessId;
                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            } while (Process32Next(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return map;
    }

    private static string? Normalize(string? path)
    {
        try { return string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    private static bool IsBuiltInAntivirusPath(string path)
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var defenderPlatform = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender");
        return path.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(defenderPlatform, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsMicrosoftSystemServiceHost(string path)
    {
        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "svchost.exe");
        if (!string.Equals(path, expected, StringComparison.OrdinalIgnoreCase)) return false;
        return SignatureChecks.GetOrAdd(path, IsMicrosoftSigned);
    }

    private static bool IsMicrosoftSigned(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // Windows 的 Authenticode 签名需要从已签名 EXE 中读取证书。
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            if (!certificate.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) return false;
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(certificate)) return false;
            return chain.ChainElements.Count > 0 && chain.ChainElements[^1].Certificate.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is CryptographicException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public nint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExecutableFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);
}
