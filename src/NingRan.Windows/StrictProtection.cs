using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using NingRan.Core;

namespace NingRan.Windows;

internal sealed class StrictProtectionSettings
{
    public const string ManagementArgument = "--manage-strict-protection";
    // Keep the protected key directly below HKLM\SOFTWARE so no product-owned
    // intermediate key can be weakened to delete or replace this child.
    private const string RegistryPath = @"SOFTWARE\NingRan.StrictProtection";
    private const int CurrentSchemaVersion = 1;
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier BuiltinUsers = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public bool Enabled { get; init; }
    public IReadOnlyList<string> AllowedProcessPaths { get; init; } = [];
    [JsonIgnore]
    public IReadOnlyList<StrictAllowedProcessIdentity> AllowedProcesses { get; init; } = [];
    [JsonIgnore]
    public string? LoadFailureReason { get; init; }

    public static StrictProtectionSettings Load()
    {
        try
        {
            using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = localMachine.OpenSubKey(RegistryPath, writable: false);
            if (key is null)
            {
                // Until an administrator explicitly saves a choice, fail safe: strict
                // protection starts with no third-party allow-list entries.
                return new StrictProtectionSettings { Enabled = true };
            }

            VerifyProtectedKey(key);
            if (key.GetValue("SchemaVersion") is not int schemaVersion || schemaVersion != CurrentSchemaVersion ||
                key.GetValue("Enabled") is not int enabledValue || enabledValue is not (0 or 1))
            {
                throw new InvalidDataException("严格防护设置的格式不正确。");
            }

            var paths = key.GetValue("AllowedProcessPaths", Array.Empty<string>(),
                RegistryValueOptions.DoNotExpandEnvironmentNames) as string[] ?? [];
            var hashes = key.GetValue("AllowedProcessSha256", Array.Empty<string>(),
                RegistryValueOptions.DoNotExpandEnvironmentNames) as string[] ?? [];
            if (paths.Length != 0 || hashes.Length != 0)
            {
                throw new InvalidDataException("旧版严格防护允许名单已停用，需要管理员重新确认设置。");
            }

            return new StrictProtectionSettings
            {
                Enabled = enabledValue == 1,
            };
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or
                                             System.Security.SecurityException or ArgumentException)
        {
            return FailClosed(exception.Message);
        }
    }

    public void Save()
    {
        if (!NingRanRuntime.IsProcessElevated())
        {
            throw new UnauthorizedAccessException("严格防护设置只能在 Windows 管理员确认后保存。");
        }

        if (AllowedProcessPaths.Count != 0)
        {
            throw new InvalidDataException("严格防护不再支持可被进程注入绕过的自定义允许名单。");
        }

        using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var existingIsUnsafe = false;
        using (var existing = localMachine.OpenSubKey(RegistryPath, writable: true))
        {
            if (existing is not null)
            {
                try { VerifyProtectedKey(existing); }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                                    System.Security.SecurityException or InvalidDataException)
                {
                    existingIsUnsafe = true;
                }
            }
        }

        if (existingIsUnsafe)
        {
            // Recreate the registry object instead of merely tightening its ACL.
            // Handles opened under an old weak ACL keep their previously granted
            // rights, but they cannot modify the newly created key object.
            localMachine.DeleteSubKeyTree(RegistryPath, throwOnMissingSubKey: false);
        }

        var security = CreateProtectedKeySecurity();
        using (var key = localMachine.CreateSubKey(
                   RegistryPath,
                   RegistryKeyPermissionCheck.ReadWriteSubTree,
                   RegistryOptions.None,
                   security) ?? throw new IOException("Windows 未能建立严格防护设置存储。"))
        {
            key.SetAccessControl(security);
            key.SetValue("SchemaVersion", CurrentSchemaVersion, RegistryValueKind.DWord);
            key.SetValue("Enabled", Enabled ? 1 : 0, RegistryValueKind.DWord);
            key.SetValue("AllowedProcessPaths", Array.Empty<string>(), RegistryValueKind.MultiString);
            key.SetValue("AllowedProcessSha256", Array.Empty<string>(), RegistryValueKind.MultiString);
            key.Flush();
        }

        using var verification = localMachine.OpenSubKey(RegistryPath, writable: false)
            ?? throw new IOException("严格防护设置保存后无法重新读取。");
        VerifyProtectedKey(verification);
    }

    public static bool IsManagementArgumentPresent(IReadOnlyList<string> arguments) =>
        arguments.Any(argument => string.Equals(argument, ManagementArgument, StringComparison.Ordinal));

    public static async Task<bool> OpenProtectedEditorAsync()
    {
        var executablePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executablePath) ||
            !HighSecurityLaunch.IsTrustedInstalledComponent(executablePath, "NingRan.exe"))
        {
            throw new InvalidOperationException("严格防护设置只能由正式安装位置中的凝然加密修改。");
        }

        using var process = await NativeElevationLauncher.StartAsync(
            NingRan.Security.NativeElevationBinding.Modes.StrictSettings,
            [ManagementArgument]).ConfigureAwait(true);
        await process.WaitForExitAsync().ConfigureAwait(true);
        return process.ExitCode == 0;
    }

    private static StrictProtectionSettings FailClosed(string reason) => new()
    {
        Enabled = true,
        LoadFailureReason = string.IsNullOrWhiteSpace(reason)
            ? "受保护设置无法读取；已按最严格模式运行。"
            : $"受保护设置无法读取：{reason} 已按最严格模式运行，且未采用任何自定义允许项。",
    };

    private static StrictAllowedProcessIdentity CreateAllowedIdentity(string value)
    {
        var path = Path.GetFullPath(value);
        if (!Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
        {
            throw new FileNotFoundException("允许的软件已不存在或不是程序文件，请重新选择。", path);
        }

        if (!IsProtectedInstalledExecutable(path))
        {
            throw new UnauthorizedAccessException(
                "只允许添加安装在 Windows 或 Program Files 受保护目录、且普通账户不能替换的程序。请先正式安装该软件再添加。");
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 128 * 1024, FileOptions.SequentialScan);
        return new StrictAllowedProcessIdentity(path, Convert.ToHexString(SHA256.HashData(stream)));
    }

    private static bool IsProtectedInstalledExecutable(string path)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        }.Where(root => !string.IsNullOrWhiteSpace(root))
         .Select(Path.GetFullPath)
         .Distinct(StringComparer.OrdinalIgnoreCase)
         .ToArray();
        var root = roots.FirstOrDefault(candidate => IsWithinOrEqual(path, candidate));
        if (root is null)
        {
            return false;
        }

        var current = new FileInfo(path) as FileSystemInfo;
        while (current is not null)
        {
            current.Refresh();
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0 ||
                !HasProtectedFileSystemAcl(current))
            {
                return false;
            }

            if (string.Equals(Path.TrimEndingDirectorySeparator(current.FullName),
                    Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            current = current switch
            {
                FileInfo file => file.Directory,
                DirectoryInfo directory => directory.Parent,
                _ => null,
            };
        }

        return false;
    }

    private static bool HasProtectedFileSystemAcl(FileSystemInfo entry)
    {
        FileSystemSecurity security = entry switch
        {
            FileInfo file => file.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            DirectoryInfo directory => directory.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            _ => throw new InvalidOperationException("无法读取允许程序的 Windows 权限。"),
        };
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || (!owner.Equals(Administrators) && !owner.Equals(LocalSystem) &&
                              !owner.Equals(TrustedInstaller)))
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        var ordinaryTokenSids = new HashSet<SecurityIdentifier>();
        if (identity.User is not null) ordinaryTokenSids.Add(identity.User);
        if (identity.Groups is not null)
        {
            foreach (var group in identity.Groups.OfType<SecurityIdentifier>()) ordinaryTokenSids.Add(group);
        }
        ordinaryTokenSids.Add(new SecurityIdentifier(WellKnownSidType.WorldSid, null));
        ordinaryTokenSids.Add(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null));
        ordinaryTokenSids.Add(BuiltinUsers);

        const FileSystemRights mutationRights =
            FileSystemRights.WriteData | FileSystemRights.AppendData |
            FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
            (FileSystemRights)0x10000000 | // GENERIC_ALL
            (FileSystemRights)0x40000000;  // GENERIC_WRITE
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                rule.IdentityReference is not SecurityIdentifier sid ||
                rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly) ||
                sid.Equals(Administrators) || sid.Equals(LocalSystem) || sid.Equals(TrustedInstaller))
            {
                continue;
            }

            if (ordinaryTokenSids.Contains(sid) && (rule.FileSystemRights & mutationRights) != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsWithinOrEqual(string path, string directory)
    {
        var relative = Path.GetRelativePath(directory, path);
        return string.Equals(relative, ".", StringComparison.Ordinal) ||
               (!Path.IsPathRooted(relative) &&
                !string.Equals(relative, "..", StringComparison.Ordinal) &&
                !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
                !relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal));
    }

    private static RegistrySecurity CreateProtectedKeySecurity()
    {
        var security = new RegistrySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        const InheritanceFlags inheritance = InheritanceFlags.ContainerInherit;
        security.AddAccessRule(new RegistryAccessRule(Administrators, RegistryRights.FullControl,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new RegistryAccessRule(LocalSystem, RegistryRights.FullControl,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new RegistryAccessRule(BuiltinUsers, RegistryRights.ReadKey,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private static void VerifyProtectedKey(RegistryKey key)
    {
        var security = key.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || (!owner.Equals(Administrators) && !owner.Equals(LocalSystem)) ||
            !security.AreAccessRulesProtected)
        {
            throw new InvalidDataException("严格防护设置的 Windows 权限保护不正确。");
        }

        const RegistryRights mutationRights = RegistryRights.SetValue | RegistryRights.CreateSubKey |
                                               RegistryRights.CreateLink | RegistryRights.Delete |
                                               RegistryRights.ChangePermissions | RegistryRights.TakeOwnership;
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (RegistryAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                rule.IdentityReference is not SecurityIdentifier sid)
            {
                continue;
            }

            if (sid.Equals(Administrators) || sid.Equals(LocalSystem))
            {
                continue;
            }

            if (sid.Equals(BuiltinUsers) && (rule.RegistryRights & mutationRights) == 0)
            {
                continue;
            }

            throw new InvalidDataException("严格防护设置允许了未经批准的账户修改或访问。");
        }
    }
}

internal sealed record StrictAllowedProcessIdentity(string Path, string Sha256);

internal sealed record StrictProtectionAlert(int ProcessId, string? ProcessPath, uint AccessMask, DateTimeOffset OccurredAtUtc,
    string TargetComponent);

internal sealed class StrictProtectionHealthFailureEventArgs(string reason) : EventArgs
{
    public string Reason { get; } = reason;
}

internal sealed class SecurityEventLog
{
    public static void Append(StrictProtectionAlert alert)
    {
        if (NingRanRuntime.IsProcessElevated()) return;

        var directory = DirectoryPath;
        Directory.CreateDirectory(directory);
        var entry = new SecurityLogEntry(alert.OccurredAtUtc, "检测到其他程序仍持有受保护内存读取权限",
            alert.ProcessId, alert.ProcessPath, alert.TargetComponent, $"0x{alert.AccessMask:X8}", "已停止操作并请求清理临时明文");
        File.AppendAllText(LogPath, JsonSerializer.Serialize(entry, SettingsJsonContext.Default.SecurityLogEntry) + Environment.NewLine);
    }

    public static void AppendStartupFailure(string reason)
    {
        if (NingRanRuntime.IsProcessElevated()) return;

        var directory = DirectoryPath;
        Directory.CreateDirectory(directory);
        var entry = new SecurityLogEntry(DateTimeOffset.UtcNow, "严格防护监控未能启动", 0, null, "严格防护监控程序", string.Empty,
            $"未启动：{reason}");
        File.AppendAllText(LogPath, JsonSerializer.Serialize(entry, SettingsJsonContext.Default.SecurityLogEntry) + Environment.NewLine);
    }

    public static void AppendRuntimeFailure(string reason)
    {
        if (NingRanRuntime.IsProcessElevated()) return;

        var directory = DirectoryPath;
        Directory.CreateDirectory(directory);
        var entry = new SecurityLogEntry(DateTimeOffset.UtcNow, "严格防护监控意外停止", 0, null, "严格防护监控程序", string.Empty,
            $"已按失效保护停止操作并清理：{reason}");
        File.AppendAllText(LogPath, JsonSerializer.Serialize(entry, SettingsJsonContext.Default.SecurityLogEntry) + Environment.NewLine);
    }

    public static bool HasEntries => File.Exists(LogPath) && new FileInfo(LogPath).Length > 0;

    public static void Export(string destination)
    {
        if (!HasEntries) throw new InvalidOperationException("暂时没有可导出的严格防护日志。");
        File.Copy(LogPath, destination, overwrite: false);
    }

    private static string DirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NingRan", "SecurityLogs");
    private static string LogPath => Path.Combine(DirectoryPath, "strict-protection.jsonl");
}

internal sealed record SecurityLogEntry(DateTimeOffset OccurredAtUtc, string Event, int ProcessId,
    string? ProcessPath, string TargetComponent, string AccessMask, string Action);

internal sealed class StrictProtectionCoordinator : IAsyncDisposable
{
    private static readonly TimeSpan MonitorHeartbeatTimeout = TimeSpan.FromSeconds(15);
    private readonly object _sync = new();
    private CancellationTokenSource? _cancellation;
    private NamedPipeServerStream? _server;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private Task? _listener;
    private int _monitorProcessId;
    private bool _running;

    public event EventHandler<StrictProtectionAlert>? AlertRaised;
    public event EventHandler<StrictProtectionHealthFailureEventArgs>? HealthFailed;
    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                return _running;
            }
        }
    }
    public string? LastFailureReason { get; private set; }

    public async Task<bool> StartAsync(StrictProtectionSettings settings, CancellationToken cancellationToken = default)
    {
        await StopAsync().ConfigureAwait(false);
        LastFailureReason = null;
        var helperPath = Path.Combine(AppContext.BaseDirectory, "NingRan.StrictMonitor.exe");
        if (!HighSecurityLaunch.IsTrustedInstalledComponent(helperPath, "NingRan.StrictMonitor.exe"))
        {
            return Fail($"监控程序不在受保护的正式安装位置：{helperPath}");
        }

        var pipeName = $"NingRan.StrictMonitor.{Environment.ProcessId}.{Guid.NewGuid():N}";
        var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            // 管理员监控与普通主窗口处于不同权限层级时，CurrentUserOnly 在部分 Windows 配置中会拒绝连接。
            // 不依赖可从命令行读取的口令；下面会使用 Windows 返回的真实客户端进程编号确认连接者。
            PipeOptions.Asynchronous);
        var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Process? monitorProcess = null;
        NativeElevatedProcess? elevatedLaunch = null;
        int monitorProcessId;
        try
        {
            elevatedLaunch = await NativeElevationLauncher.StartAsync(
                NingRan.Security.NativeElevationBinding.Modes.StrictMonitor,
                [
                    "--pipe",
                    pipeName,
                    "--target",
                    Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ],
                cancellation.Token).ConfigureAwait(false);
            monitorProcess = elevatedLaunch.Child;
            monitorProcessId = monitorProcess.Id;
        }
        catch (Exception exception)
        {
            server.Dispose();
            cancellation.Dispose();
            elevatedLaunch?.Dispose();
            return Fail(DescribeStartException(exception));
        }

        try
        {
            // 管理员确认有时会被其他窗口遮住；保留足够的确认时间，而不是把未及时确认误报为启动失败。
            // 抢先连接或无法证明身份的程序只会被断开，服务器会继续等待刚刚由本程序启动的监控进程。
            await WaitForMonitorConnectionAsync(server, monitorProcess, TimeSpan.FromSeconds(90), cancellation.Token)
                .ConfigureAwait(false);
            var writer = new StreamWriter(server, leaveOpen: true) { AutoFlush = true };
            var reader = new StreamReader(server, leaveOpen: true);
            var helloLine = await reader.ReadLineAsync(cancellation.Token).ConfigureAwait(false);
            var hello = JsonSerializer.Deserialize<StrictMonitorMessage>(helloLine ?? string.Empty);
            if (hello is null || !string.Equals(hello.Kind, "hello", StringComparison.Ordinal))
            {
                writer.Dispose();
                reader.Dispose();
                return Fail("监控程序的安全连接验证没有通过。");
            }
            await writer.WriteLineAsync(JsonSerializer.Serialize(
                new StrictMonitorConfiguration(
                    [new StrictProtectedProcess(Environment.ProcessId, "主窗口、内嵌播放器和预览画面")],
                    []))).ConfigureAwait(false);
            var ready = await reader.ReadLineAsync(cancellation.Token).ConfigureAwait(false);
            var message = JsonSerializer.Deserialize<StrictMonitorMessage>(ready ?? string.Empty);
            if (!string.Equals(message?.Kind, "ready", StringComparison.Ordinal))
            {
                writer.Dispose();
                return Fail("监控程序已启动，但没有完成安全握手。");
            }

            lock (_sync)
            {
                _server = server;
                _reader = reader;
                _writer = writer;
                _cancellation = cancellation;
                _monitorProcessId = monitorProcessId;
                _running = true;
                _listener = ListenAsync(reader, cancellation.Token);
            }
            return true;
        }
        catch (Exception exception)
        {
            server.Dispose();
            cancellation.Dispose();
            return Fail(DescribeStartException(exception));
        }
        finally
        {
            elevatedLaunch?.Dispose();
        }
    }

    public async Task StopAsync()
    {
        StreamWriter? writer;
        StreamReader? reader;
        Task? listener;
        CancellationTokenSource? cancellation;
        NamedPipeServerStream? server;
        int monitorProcessId;
        lock (_sync)
        {
            writer = _writer;
            reader = _reader;
            listener = _listener;
            cancellation = _cancellation;
            server = _server;
            monitorProcessId = _monitorProcessId;
            _writer = null;
            _reader = null;
            _listener = null;
            _cancellation = null;
            _server = null;
            _monitorProcessId = 0;
            _running = false;
        }

        try
        {
            if (writer is not null && server is not null && monitorProcessId > 0 &&
                GetNamedPipeClientProcessId(server.SafePipeHandle, out var connectedProcessId) &&
                connectedProcessId == (uint)monitorProcessId)
            {
                await writer.WriteLineAsync("stop").ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
        }
        cancellation?.Cancel();
        if (listener is not null)
        {
            try { await listener.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch (Exception) { }
        }

        writer?.Dispose();
        reader?.Dispose();
        server?.Dispose();
        cancellation?.Dispose();
    }

    public ValueTask DisposeAsync() => new(StopAsync());

    private async Task ListenAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(cancellationToken).AsTask()
                    .WaitAsync(MonitorHeartbeatTimeout, cancellationToken).ConfigureAwait(false);
                if (line is null)
                {
                    HandleMonitorFailure(reader, "严格防护监控连接意外关闭。为避免在没有监控时继续处理明文，当前操作已停止。");
                    return;
                }

                var message = JsonSerializer.Deserialize<StrictMonitorMessage>(line);
                if (message is { Kind: "health-failed" })
                {
                    var reason = string.IsNullOrWhiteSpace(message.FailureReason)
                        ? "严格防护监控无法继续检查系统状态。"
                        : message.FailureReason;
                    HandleMonitorFailure(reader, reason);
                    return;
                }

                if (message is { Kind: "health-ok" })
                {
                    continue;
                }

                if (message is not { Kind: "alert", OccurredAtUtc: { } occurredAtUtc })
                {
                    HandleMonitorFailure(reader, "严格防护监控返回了无法识别的状态数据。为避免误报为仍在保护，当前操作已停止。");
                    return;
                }

                AlertRaised?.Invoke(this, new StrictProtectionAlert(
                    message.ProcessId, message.ProcessPath, message.AccessMask, occurredAtUtc,
                    message.TargetComponent ?? "受保护组件"));
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception) when (
            !cancellationToken.IsCancellationRequested &&
            exception is IOException or JsonException or ObjectDisposedException or InvalidDataException or TimeoutException)
        {
            HandleMonitorFailure(reader, "严格防护监控连接或状态数据发生错误。为避免在没有可靠监控时继续处理明文，当前操作已停止。");
        }
    }

    private void HandleMonitorFailure(StreamReader reader, string reason)
    {
        var raiseEvent = false;
        lock (_sync)
        {
            // A listener from a previous StartAsync may finish after a new monitor has
            // already connected. Only the currently registered reader may change state.
            if (_running && ReferenceEquals(_reader, reader))
            {
                _running = false;
                LastFailureReason = reason;
                raiseEvent = true;
            }
        }

        if (raiseEvent)
        {
            HealthFailed?.Invoke(this, new StrictProtectionHealthFailureEventArgs(reason));
        }
    }

    private static IReadOnlyList<StrictAllowedProcessIdentity> NormalizeAllowedProcesses(
        IReadOnlyList<StrictAllowedProcessIdentity> entries) => entries
        .Select(entry =>
        {
            try
            {
                var path = Path.GetFullPath(entry.Path);
                return File.Exists(path) && entry.Sha256.Length == 64 && entry.Sha256.All(Uri.IsHexDigit)
                    ? new StrictAllowedProcessIdentity(path, entry.Sha256.ToUpperInvariant())
                    : null;
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        })
        .Where(entry => entry is not null)
        .Cast<StrictAllowedProcessIdentity>()
        .DistinctBy(entry => entry.Path, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static async Task WaitForMonitorConnectionAsync(
        NamedPipeServerStream server,
        Process expectedProcess,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                throw new TimeoutException();
            }

            if (expectedProcess.HasExited)
            {
                throw new IOException("严格防护监控程序在建立安全连接前已经退出。");
            }

            await server.WaitForConnectionAsync(cancellationToken).WaitAsync(remaining, cancellationToken)
                .ConfigureAwait(false);
            if (GetNamedPipeClientProcessId(server.SafePipeHandle, out var connectedProcessId) &&
                connectedProcessId == (uint)expectedProcess.Id &&
                !expectedProcess.HasExited)
            {
                return;
            }

            try
            {
                server.Disconnect();
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException)
            {
                // 对方可能恰好在身份检查时退出；下一轮仍继续等待真正的监控进程。
            }
        }
    }

    private bool Fail(string reason)
    {
        LastFailureReason = reason;
        try { SecurityEventLog.AppendStartupFailure(reason); } catch { /* 无法写日志时仍把原因交给界面显示。 */ }
        return false;
    }

    private static string DescribeStartException(Exception exception) => exception switch
    {
        TimeoutException => "等待管理员确认或监控程序连接超过 90 秒。请确认 Windows 的管理员确认窗口已选择“是”。",
        OperationCanceledException => "监控程序启动过程被取消。",
        UnauthorizedAccessException => "Windows 拒绝了监控程序的启动或连接权限。请重新确认管理员授权。",
        IOException => "监控程序的安全连接意外中断。请重新开启严格防护；若仍失败，请导出安全日志。",
        JsonException => "监控程序返回的数据不完整。请重新安装最新版程序后再试。",
        _ => $"{exception.GetType().Name}：{exception.Message}",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);
}

internal sealed record StrictProtectedProcess(int ProcessId, string Component);
internal sealed record StrictMonitorConfiguration(IReadOnlyList<StrictProtectedProcess> Targets,
    IReadOnlyList<StrictAllowedProcessIdentity> AllowedProcesses);
internal sealed record StrictMonitorMessage(string Kind, int ProcessId = 0, string? ProcessPath = null,
    uint AccessMask = 0, DateTimeOffset? OccurredAtUtc = null, string? TargetComponent = null,
    string? FailureReason = null);

internal sealed class StrictProtectionDialog : Window
{
    private readonly CheckBox _enabled = new() { Content = UiLanguage.Translate("开启严格防护监控（下次启动会自动请求管理员确认）"), Margin = new Thickness(0, 0, 0, 10) };
    private readonly StrictProtectionSettings _original;

    public StrictProtectionDialog(StrictProtectionSettings settings)
    {
        _original = settings;
        Title = UiLanguage.Translate("严格防护设置");
        Width = 650;
        Height = 470;
        MinWidth = 560;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _enabled.IsChecked = settings.Enabled;
        var export = new Button { Content = UiLanguage.Translate("导出安全日志"), Margin = new Thickness(0, 16, 8, 0), Padding = new Thickness(12, 5, 12, 5) };
        export.Click += Export_Click;
        var save = new Button { Content = UiLanguage.Translate("保存"), IsDefault = true, Margin = new Thickness(0, 16, 8, 0), Padding = new Thickness(18, 6, 18, 6) };
        save.Click += (_, _) => { Settings = BuildSettings(); DialogResult = true; };
        var cancel = new Button { Content = UiLanguage.Translate("取消"), IsCancel = true, Margin = new Thickness(0, 16, 0, 0), Padding = new Thickness(18, 6, 18, 6) };

        Content = new Border
        {
            Padding = new Thickness(22),
            Child = new StackPanel
            {
                Children =
                {
                    new TextBlock { Text = UiLanguage.Translate("严格防护"), FontSize = 19, FontWeight = FontWeights.SemiBold },
                    new TextBlock
                    {
                        Text = UiLanguage.Translate("监控程序单独申请管理员权限，并定期检查主窗口、内嵌播放器、预览画面和自身。发现不在允许名单内的软件仍持有读取权限时，会记录事件、停止当前操作并清理临时明文。它用于发现和缩短风险，不能保证拦截一次极短的读取。"),
                        TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 14)
                    },
                    _enabled,
                    new TextBlock { Text = UiLanguage.Translate("安全说明"), FontWeight = FontWeights.SemiBold },
                    new TextBlock { Text = UiLanguage.Translate("为防止恶意程序伪装成合法软件，严格防护不会自动或手动放行任何外部进程。安全软件或辅助工具若读取受保护内存，也会触发提醒。"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) },
                    new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { export, save, cancel } },
                }
            }
        };
    }

    public StrictProtectionSettings Settings { get; private set; } = new();

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = UiLanguage.Translate("导出严格防护日志"),
            FileName = UiLanguage.IsEnglish ? $"NingRan-StrictProtection-{DateTime.Now:yyyyMMdd}.jsonl" : $"凝然严格防护日志-{DateTime.Now:yyyyMMdd}.jsonl",
            Filter = UiLanguage.Translate("日志文件|*.jsonl"),
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            SecurityEventLog.Export(dialog.FileName);
            MessageBox.Show(this, "安全日志已经导出。日志不包含密码、密匙或文件内容。", "凝然加密", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "无法导出安全日志", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private StrictProtectionSettings BuildSettings() => new()
    {
        Enabled = _enabled.IsChecked == true,
        AllowedProcessPaths = [],
    };
}

[System.Text.Json.Serialization.JsonSerializable(typeof(StrictProtectionSettings))]
[System.Text.Json.Serialization.JsonSerializable(typeof(SecurityLogEntry))]
[System.Text.Json.Serialization.JsonSourceGenerationOptions(WriteIndented = true)]
internal partial class SettingsJsonContext : JsonSerializerContext;
