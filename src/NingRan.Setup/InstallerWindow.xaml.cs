using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using NingRan.Setup;

namespace NingRan.Setup.Windows;

public partial class InstallerWindow : Window
{
    private readonly InstallerEngine _engine = new();
    private readonly bool _isUninstall;
    private readonly string? _uninstallPath;
    private InstallerStage _stage;
    private bool _isBusy;
    private bool _uninstallCleanupScheduled;
    private string? _installedExecutable;
    private UserDataInventory _userDataInventory = new(0, 0, 0);

    public InstallerWindow(bool isUninstall, string? uninstallPath)
    {
        InitializeComponent();
        VersionText.Text = $"版本 {SetupProduct.Version} · Windows x64";
        _isUninstall = isUninstall;
        _uninstallPath = uninstallPath is null
            ? null
            : Path.TrimEndingDirectorySeparator(Path.GetFullPath(uninstallPath));
        var existingPath = ShellIntegration.FindInstalledPath();
        InstallPathInput.Text = SetupProduct.DefaultInstallPath;
        if (existingPath is not null)
        {
            OptionsTitle.Text = "升级或调整安装方式";
        }

        if (_isUninstall)
        {
            ConfigureUninstallMode();
            Loaded += InstallerWindow_Loaded;
        }
        else
        {
            ShowStage(InstallerStage.Welcome);
        }

        Closing += InstallerWindow_Closing;
    }

    private async void InstallerWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _userDataInventory = await Task.Run(() => SafeDirectoryTree.Inspect(SetupProduct.UserDataPath));
            UserDataInventoryText.Text = _userDataInventory.IsEmpty
                ? "没有发现本机个人数据。"
                : $"将涉及：{_userDataInventory.FileCount:N0} 个文件、{_userDataInventory.DirectoryCount:N0} 个文件夹，共 {FormatByteSize(_userDataInventory.TotalBytes)}。\n不勾选时这些内容全部保留。";
        }
        catch (Exception exception)
        {
            UserDataInventoryText.Text = $"无法完整统计个人数据：{exception.Message}\n为安全起见，当前不能选择删除个人数据。";
            DeleteUserDataCheck.IsEnabled = false;
        }
    }

    private void ConfigureUninstallMode()
    {
        Title = "凝然加密卸载程序";
        LeftModeText.Text = "安全卸载";
        WindowCaption.Text = "凝然加密卸载程序";
        StepOneText.Text = "01  确认卸载";
        StepTwoText.Text = "02  清理程序";
        StepThreeText.Text = "03  卸载完成";
        UninstallPathText.Text = _uninstallPath;
        ShowStage(InstallerStage.Uninstall);
    }

    private void ShowStage(InstallerStage stage)
    {
        _stage = stage;
        WelcomePanel.Visibility = stage == InstallerStage.Welcome ? Visibility.Visible : Visibility.Collapsed;
        OptionsPanel.Visibility = stage == InstallerStage.Options ? Visibility.Visible : Visibility.Collapsed;
        ProgressPanel.Visibility = stage == InstallerStage.Progress ? Visibility.Visible : Visibility.Collapsed;
        UninstallPanel.Visibility = stage == InstallerStage.Uninstall ? Visibility.Visible : Visibility.Collapsed;
        FinishPanel.Visibility = stage == InstallerStage.Finish ? Visibility.Visible : Visibility.Collapsed;

        BackButton.Visibility = stage == InstallerStage.Options ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = stage == InstallerStage.Finish ? Visibility.Collapsed : Visibility.Visible;
        NextButton.Content = stage switch
        {
            InstallerStage.Options => "开始安装",
            InstallerStage.Uninstall => "开始卸载",
            InstallerStage.Finish => "完成",
            _ => "继续",
        };
        NextButton.IsEnabled = !_isBusy && stage switch
        {
            InstallerStage.Welcome => AcceptNoticeCheck.IsChecked == true,
            InstallerStage.Progress => false,
            _ => true,
        };

        StepOneText.Foreground = stage is InstallerStage.Welcome or InstallerStage.Uninstall
            ? System.Windows.Media.Brushes.White
            : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(169, 215, 199));
        StepTwoText.Foreground = stage is InstallerStage.Options or InstallerStage.Progress
            ? System.Windows.Media.Brushes.White
            : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(169, 215, 199));
        StepThreeText.Foreground = stage == InstallerStage.Finish
            ? System.Windows.Media.Brushes.White
            : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(169, 215, 199));
    }

    private async void NextButton_Click(object sender, RoutedEventArgs e)
    {
        switch (_stage)
        {
            case InstallerStage.Welcome:
                ShowStage(InstallerStage.Options);
                break;
            case InstallerStage.Options:
                await InstallAsync();
                break;
            case InstallerStage.Uninstall:
                await UninstallAsync();
                break;
            case InstallerStage.Finish:
                FinishAndClose();
                break;
        }
    }

    private async Task InstallAsync()
    {
        SetupOptions options;
        try
        {
            var installPath = SetupPathSafety.ValidateInstallPath(
                InstallPathInput.Text,
                allowExistingInstall: SetupPathSafety.IsSecureExistingInstall(InstallPathInput.Text));
            options = new SetupOptions(
                installPath,
                DesktopShortcutCheck.IsChecked == true,
                StartMenuShortcutCheck.IsChecked == true,
                FileAssociationsCheck.IsChecked == true);
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "安装位置不可用", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SetBusy(true);
        ProgressTitle.Text = "正在安装凝然加密";
        ProgressMessage.Text = "正在检查离线安装包…";
        InstallProgressBar.Value = 0;
        ShowStage(InstallerStage.Progress);
        try
        {
            await using var payload = App.OpenPayload();
            var progress = new Progress<SetupProgress>(value =>
            {
                InstallProgressBar.Value = value.Percentage;
                ProgressMessage.Text = value.Message;
            });
            var state = await _engine.InstallAsync(
                options,
                payload,
                Environment.ProcessPath ?? throw new InvalidOperationException("无法确定安装程序位置。"),
                progress);
            _installedExecutable = Path.Combine(state.InstallPath, SetupProduct.MainExecutableName);
            FinishTitle.Text = "凝然加密安装完成";
            FinishMessage.Text = $"凝然加密 {SetupProduct.Version} 已完整安装。身份、设置和已有数据均未被覆盖。";
            RunAfterInstallCheck.Visibility = Visibility.Visible;
            SetBusy(false);
            ShowStage(InstallerStage.Finish);
        }
        catch (Exception exception)
        {
            SetBusy(false);
            ShowStage(InstallerStage.Options);
            MessageBox.Show(
                this,
                $"安装没有完成，旧版本和个人数据会尽量保持原样。\n\n{exception.Message}",
                "安装失败",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private async Task UninstallAsync()
    {
        var deleteUserData = DeleteUserDataCheck.IsChecked == true;
        var inventoryText = _userDataInventory.IsEmpty
            ? "没有发现个人数据。"
            : $"个人数据清单：{_userDataInventory.FileCount:N0} 个文件、{_userDataInventory.DirectoryCount:N0} 个文件夹，共 {FormatByteSize(_userDataInventory.TotalBytes)}。";
        var choice = MessageBox.Show(
            this,
            deleteUserData
                ? $"将删除凝然加密程序。\n\n{inventoryText}\n\n您还勾选了删除全部个人数据。是否继续？"
                : $"将删除凝然加密程序。\n\n{inventoryText}\n\n个人数据将全部保留。是否继续？",
            "确认卸载",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (choice != MessageBoxResult.Yes)
        {
            return;
        }

        if (deleteUserData && MessageBox.Show(
                this,
                $"最后确认：即将永久删除上面列出的个人数据。身份、联系人和设备登记删除后不能从程序内恢复。\n\n{inventoryText}\n\n确定永久删除吗？",
                "再次确认删除个人数据",
                MessageBoxButton.YesNo,
                MessageBoxImage.Stop,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        SetBusy(true);
        ProgressTitle.Text = "正在卸载凝然加密";
        ProgressMessage.Text = deleteUserData ? "正在删除程序和已确认的个人数据…" : "正在删除程序，个人数据会保留…";
        InstallProgressBar.IsIndeterminate = true;
        ShowStage(InstallerStage.Progress);
        try
        {
            await Task.Run(() => _engine.PrepareUninstall(
                _uninstallPath ?? throw new InvalidOperationException("无法确定卸载位置。"),
                deleteUserData));
            CleanupScheduler.ScheduleInstalledDirectoryCleanup(_uninstallPath!);
            _uninstallCleanupScheduled = true;
            FinishTitle.Text = "凝然加密已卸载";
            FinishMessage.Text = deleteUserData
                ? "程序和经过您两次确认的个人数据已经删除。关闭窗口后将完成最后清理。"
                : "程序已经删除；身份、联系人、设备登记和设置均已保留。关闭窗口后将完成最后清理。";
            RunAfterInstallCheck.Visibility = Visibility.Collapsed;
            InstallProgressBar.IsIndeterminate = false;
            SetBusy(false);
            ShowStage(InstallerStage.Finish);
        }
        catch (Exception exception)
        {
            InstallProgressBar.IsIndeterminate = false;
            SetBusy(false);
            ShowStage(InstallerStage.Uninstall);
            MessageBox.Show(this, exception.Message, "卸载未完成", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void FinishAndClose()
    {
        if (!_isUninstall && RunAfterInstallCheck.IsChecked == true && File.Exists(_installedExecutable))
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = _installedExecutable,
                    UseShellExecute = true,
                    WorkingDirectory = Path.GetDirectoryName(_installedExecutable),
                })?.Dispose();
            }
            catch (Exception exception)
            {
                MessageBox.Show(this, $"程序已经安装，但暂时无法自动启动：\n\n{exception.Message}",
                    "无法自动启动", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        Close();
    }

    private void BackButton_Click(object sender, RoutedEventArgs e) => ShowStage(InstallerStage.Welcome);

    private void CancelButton_Click(object sender, RoutedEventArgs e) => Close();

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private void AcceptNoticeChanged(object sender, RoutedEventArgs e)
    {
        if (_stage == InstallerStage.Welcome)
        {
            NextButton.IsEnabled = AcceptNoticeCheck.IsChecked == true;
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            DragMove();
        }
    }

    private void SetBusy(bool busy)
    {
        _isBusy = busy;
        NextButton.IsEnabled = !busy;
        BackButton.IsEnabled = !busy;
        CancelButton.IsEnabled = !busy;
    }

    private void InstallerWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (_isBusy)
        {
            e.Cancel = true;
            MessageBox.Show(this, "正在处理程序文件，请等待当前操作完成。", "凝然加密",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else if (_isUninstall && _stage == InstallerStage.Finish && !_uninstallCleanupScheduled)
        {
            e.Cancel = true;
        }
    }

    private static string FormatByteSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(bytes, 0);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.##} {units[unit]}";
    }

    private enum InstallerStage
    {
        Welcome,
        Options,
        Progress,
        Uninstall,
        Finish,
    }
}
