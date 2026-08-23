using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace NingRan.Windows;

internal sealed class StrictProtectionSettings
{
    public bool Enabled { get; init; }
    public IReadOnlyList<string> AllowedProcessPaths { get; init; } = [];

    public static StrictProtectionSettings Load()
    {
        try
        {
            var path = SettingsPath;
            if (!File.Exists(path)) return new StrictProtectionSettings();
            return JsonSerializer.Deserialize<StrictProtectionSettings>(File.ReadAllText(path)) ?? new StrictProtectionSettings();
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            return new StrictProtectionSettings();
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
        File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, SettingsJsonContext.Default.StrictProtectionSettings));
    }

    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan", "strict-protection.json");
}

internal sealed record StrictProtectionAlert(int ProcessId, string? ProcessPath, uint AccessMask, DateTimeOffset OccurredAtUtc,
    string TargetComponent);

internal sealed class SecurityEventLog
{
    public static void Append(StrictProtectionAlert alert)
    {
        var directory = DirectoryPath;
        Directory.CreateDirectory(directory);
        var entry = new SecurityLogEntry(alert.OccurredAtUtc, "检测到其他程序尝试读取受保护内存",
            alert.ProcessId, alert.ProcessPath, alert.TargetComponent, $"0x{alert.AccessMask:X8}", "已停止操作并请求清理临时明文");
        File.AppendAllText(LogPath, JsonSerializer.Serialize(entry, SettingsJsonContext.Default.SecurityLogEntry) + Environment.NewLine);
    }

    public static void AppendStartupFailure(string reason)
    {
        var directory = DirectoryPath;
        Directory.CreateDirectory(directory);
        var entry = new SecurityLogEntry(DateTimeOffset.UtcNow, "严格防护监控未能启动", 0, null, "严格防护监控程序", string.Empty,
            $"未启动：{reason}");
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
    private readonly object _sync = new();
    private CancellationTokenSource? _cancellation;
    private NamedPipeServerStream? _server;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private Task? _listener;
    private bool _running;

    public event EventHandler<StrictProtectionAlert>? AlertRaised;
    public bool IsRunning => _running;
    public string? LastFailureReason { get; private set; }

    public async Task<bool> StartAsync(StrictProtectionSettings settings, CancellationToken cancellationToken = default)
    {
        await StopAsync().ConfigureAwait(false);
        LastFailureReason = null;
        var helperPath = Path.Combine(AppContext.BaseDirectory, "NingRan.StrictMonitor.exe");
        if (!File.Exists(helperPath))
        {
            return Fail($"没有找到监控程序：{helperPath}");
        }

        var pipeName = $"NingRan.StrictMonitor.{Environment.ProcessId}.{Guid.NewGuid():N}";
        var pipeToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            // 管理员监控与普通主窗口处于不同权限层级时，CurrentUserOnly 在部分 Windows 配置中会拒绝连接。
            // 管道名与下面的一次性随机口令均不可预测；未通过口令验证前不发送任何监控配置。
            PipeOptions.Asynchronous);
        var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = helperPath,
                UseShellExecute = true,
                Verb = "runas",
                Arguments = $"--pipe {pipeName} --target {Environment.ProcessId} --token {pipeToken}",
            })?.Dispose();
        }
        catch (Exception exception)
        {
            server.Dispose();
            cancellation.Dispose();
            return Fail(DescribeStartException(exception));
        }

        try
        {
            // 管理员确认有时会被其他窗口遮住；保留足够的确认时间，而不是把未及时确认误报为启动失败。
            await server.WaitForConnectionAsync(cancellation.Token).WaitAsync(TimeSpan.FromSeconds(90), cancellation.Token)
                .ConfigureAwait(false);
            var writer = new StreamWriter(server, leaveOpen: true) { AutoFlush = true };
            var reader = new StreamReader(server, leaveOpen: true);
            var helloLine = await reader.ReadLineAsync(cancellation.Token).ConfigureAwait(false);
            var hello = JsonSerializer.Deserialize<StrictMonitorMessage>(helloLine ?? string.Empty);
            if (hello is null || !string.Equals(hello.Kind, "hello", StringComparison.Ordinal) || !TokenMatches(pipeToken, hello.Token))
            {
                writer.Dispose();
                reader.Dispose();
                return Fail("监控程序的安全连接验证没有通过。");
            }
            await writer.WriteLineAsync(JsonSerializer.Serialize(
                new StrictMonitorConfiguration(
                    [new StrictProtectedProcess(Environment.ProcessId, "主窗口、内嵌播放器和预览画面")],
                    NormalizeAllowedPaths(settings.AllowedProcessPaths)))).ConfigureAwait(false);
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
    }

    public async Task StopAsync()
    {
        StreamWriter? writer;
        StreamReader? reader;
        Task? listener;
        CancellationTokenSource? cancellation;
        NamedPipeServerStream? server;
        lock (_sync)
        {
            writer = _writer;
            reader = _reader;
            listener = _listener;
            cancellation = _cancellation;
            server = _server;
            _writer = null;
            _reader = null;
            _listener = null;
            _cancellation = null;
            _server = null;
            _running = false;
        }

        try { if (writer is not null) await writer.WriteLineAsync("stop").ConfigureAwait(false); } catch (IOException) { }
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
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (line is null) return;
                var message = JsonSerializer.Deserialize<StrictMonitorMessage>(line);
                if (message is not { Kind: "alert", OccurredAtUtc: { } occurredAtUtc })
                {
                    continue;
                }

                AlertRaised?.Invoke(this, new StrictProtectionAlert(
                    message.ProcessId, message.ProcessPath, message.AccessMask, occurredAtUtc,
                    message.TargetComponent ?? "受保护组件"));
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
        }
    }

    private static IReadOnlyList<string> NormalizeAllowedPaths(IReadOnlyList<string> paths) => paths
        .Select(path =>
        {
            try { return Path.GetFullPath(path); }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        })
        .Where(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path))
        .Cast<string>()
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

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

    private static bool TokenMatches(string expected, string? supplied)
    {
        if (string.IsNullOrWhiteSpace(supplied)) return false;
        var expectedBytes = System.Text.Encoding.UTF8.GetBytes(expected);
        var suppliedBytes = System.Text.Encoding.UTF8.GetBytes(supplied);
        try { return CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes); }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedBytes);
            CryptographicOperations.ZeroMemory(suppliedBytes);
        }
    }
}

internal sealed record StrictProtectedProcess(int ProcessId, string Component);
internal sealed record StrictMonitorConfiguration(IReadOnlyList<StrictProtectedProcess> Targets, IReadOnlyList<string> AllowedProcessPaths);
internal sealed record StrictMonitorMessage(string Kind, int ProcessId = 0, string? ProcessPath = null,
    uint AccessMask = 0, DateTimeOffset? OccurredAtUtc = null, string? Token = null, string? TargetComponent = null);

internal sealed class StrictProtectionDialog : Window
{
    private readonly CheckBox _enabled = new() { Content = "开启严格防护（下次启动会自动请求管理员确认）", Margin = new Thickness(0, 0, 0, 10) };
    private readonly ListBox _allowed = new() { MinHeight = 135 };
    private readonly StrictProtectionSettings _original;

    public StrictProtectionDialog(StrictProtectionSettings settings)
    {
        _original = settings;
        Title = "严格防护设置";
        Width = 650;
        Height = 470;
        MinWidth = 560;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _enabled.IsChecked = settings.Enabled;
        _allowed.ItemsSource = settings.AllowedProcessPaths.ToList();

        var add = new Button { Content = "添加允许的软件", Margin = new Thickness(0, 8, 8, 0), Padding = new Thickness(12, 5, 12, 5) };
        add.Click += AddAllowed_Click;
        var remove = new Button { Content = "移除选中项", Margin = new Thickness(0, 8, 0, 0), Padding = new Thickness(12, 5, 12, 5) };
        remove.Click += (_, _) => RemoveSelected();
        var export = new Button { Content = "导出安全日志", Margin = new Thickness(0, 16, 8, 0), Padding = new Thickness(12, 5, 12, 5) };
        export.Click += Export_Click;
        var save = new Button { Content = "保存", IsDefault = true, Margin = new Thickness(0, 16, 8, 0), Padding = new Thickness(18, 6, 18, 6) };
        save.Click += (_, _) => { Settings = BuildSettings(); DialogResult = true; };
        var cancel = new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 16, 0, 0), Padding = new Thickness(18, 6, 18, 6) };

        Content = new Border
        {
            Padding = new Thickness(22),
            Child = new StackPanel
            {
                Children =
                {
                    new TextBlock { Text = "严格防护", FontSize = 19, FontWeight = FontWeights.SemiBold },
                    new TextBlock
                    {
                        Text = "监控程序单独申请管理员权限。它会保护主窗口、内嵌播放器、预览画面和自身；发现不在允许名单内的软件读取内存时，会记录事件、停止当前操作并清理临时明文。",
                        TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 14)
                    },
                    _enabled,
                    new TextBlock { Text = "允许的软件（其父进程和子进程也会被允许）", FontWeight = FontWeights.SemiBold },
                    _allowed,
                    new StackPanel { Orientation = Orientation.Horizontal, Children = { add, remove } },
                    new TextBlock { Text = "Windows 自带安全软件会自动允许。不要添加来源不明的软件。", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) },
                    new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { export, save, cancel } },
                }
            }
        };
    }

    public StrictProtectionSettings Settings { get; private set; } = new();

    private void AddAllowed_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "选择要允许的程序", Filter = "程序文件|*.exe|所有文件|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        var items = (_allowed.ItemsSource as List<string>) ?? [];
        var path = Path.GetFullPath(dialog.FileName);
        if (!items.Contains(path, StringComparer.OrdinalIgnoreCase)) items.Add(path);
        _allowed.ItemsSource = null;
        _allowed.ItemsSource = items;
    }

    private void RemoveSelected()
    {
        if (_allowed.SelectedItem is not string selected) return;
        var items = ((_allowed.ItemsSource as List<string>) ?? []).Where(path => !string.Equals(path, selected, StringComparison.OrdinalIgnoreCase)).ToList();
        _allowed.ItemsSource = null;
        _allowed.ItemsSource = items;
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = "导出严格防护日志", FileName = $"凝然严格防护日志-{DateTime.Now:yyyyMMdd}.jsonl", Filter = "日志文件|*.jsonl" };
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
        AllowedProcessPaths = ((_allowed.ItemsSource as List<string>) ?? [])
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
    };
}

[System.Text.Json.Serialization.JsonSerializable(typeof(StrictProtectionSettings))]
[System.Text.Json.Serialization.JsonSerializable(typeof(SecurityLogEntry))]
[System.Text.Json.Serialization.JsonSourceGenerationOptions(WriteIndented = true)]
internal partial class SettingsJsonContext : JsonSerializerContext;
