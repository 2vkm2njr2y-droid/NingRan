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
    private InstallerTexts _texts = InstallerTextCatalog.Chinese;

    private string DisplayProductName => _texts == InstallerTextCatalog.English
        ? (SetupProduct.IsMediaPlayer ? "NingRan Media Player" : "NingRan Encryption")
        : SetupProduct.Name;

    public InstallerWindow(bool isUninstall, string? uninstallPath)
    {
        InitializeComponent();
        _isUninstall = isUninstall;
        _uninstallPath = uninstallPath is null
            ? null
            : Path.TrimEndingDirectorySeparator(Path.GetFullPath(uninstallPath));
        var installedLanguage = _uninstallPath is null ? null : InstallState.TryLoad(_uninstallPath)?.Language;
        LanguageCombo.SelectedIndex = string.Equals(installedLanguage, "en", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        ConfigureProductText();
        VersionText.Text = string.Format(_texts.VersionFormat, SetupProduct.Version);
        var existingPath = ShellIntegration.FindInstalledPath();
        InstallPathInput.Text = SetupProduct.DefaultInstallPath;
        if (existingPath is not null)
        {
            OptionsTitle.Text = _texts == InstallerTextCatalog.English ? "Upgrade or adjust installation" : "升级或调整安装方式";
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
            if (!SetupProduct.HasUserData)
            {
                return;
            }

            _userDataInventory = await Task.Run(() => SafeDirectoryTree.Inspect(SetupProduct.UserDataPath));
            var english = _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer;
            UserDataInventoryText.Text = _userDataInventory.IsEmpty
                ? english ? "No personal data was found." : "没有发现本机个人数据。"
                : english
                    ? $"This includes {_userDataInventory.FileCount:N0} files and {_userDataInventory.DirectoryCount:N0} folders, {FormatByteSize(_userDataInventory.TotalBytes)} total.\nThese items are kept when the checkbox is cleared."
                    : $"将涉及：{_userDataInventory.FileCount:N0} 个文件、{_userDataInventory.DirectoryCount:N0} 个文件夹，共 {FormatByteSize(_userDataInventory.TotalBytes)}。\n不勾选时这些内容全部保留。";
        }
        catch (Exception exception)
        {
            UserDataInventoryText.Text = _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer
                ? $"Personal data could not be fully counted: {exception.Message}\nFor safety, deletion cannot be selected right now."
                : $"无法完整统计个人数据：{exception.Message}\n为安全起见，当前不能选择删除个人数据。";
            DeleteUserDataCheck.IsEnabled = false;
        }
    }

    private void ConfigureUninstallMode()
    {
        Title = _texts.UninstallTitle;
        LeftModeText.Text = _texts.ProductMode;
        WindowCaption.Text = _texts.UninstallTitle;
        StepOneText.Text = _texts.StepOne;
        StepTwoText.Text = _texts.StepTwo;
        StepThreeText.Text = _texts.StepThree;
        UninstallPathText.Text = _uninstallPath;
        ShowStage(InstallerStage.Uninstall);
    }

    private void ConfigureProductText()
    {
        var productName = SetupProduct.Name;
        var displayName = _texts == InstallerTextCatalog.English
            ? (SetupProduct.IsMediaPlayer ? "NingRan Media Player" : "NingRan Encryption")
            : productName;
        SidebarColumn.Width = new GridLength(_texts == InstallerTextCatalog.English ? 300 : 270);
        ProductNameText.FontSize = _texts == InstallerTextCatalog.English ? 23 : 27;
        ApplyTexts();
        Title = _texts.InstallerTitle;
        ProductNameText.Text = displayName;
        WindowCaption.Text = _texts.InstallerTitle;
        WelcomeTitle.Text = _texts.WelcomeTitle.Replace("凝然", displayName, StringComparison.Ordinal);
        ProgressTitle.Text = _texts.ProgressTitle.Replace("凝然", displayName, StringComparison.Ordinal);
        UninstallTitle.Text = _texts.UninstallTitle.Replace("凝然", displayName, StringComparison.Ordinal);
        RunAfterInstallCheck.Content = _texts.RunAfterInstall.Replace("凝然", displayName, StringComparison.Ordinal);

        if (SetupProduct.IsMediaPlayer)
        {
            LeftModeText.Text = "独立媒体播放";
            WelcomeDescription.Text = "可独立播放本地音频和视频；安装凝然加密后，也可由安全查看模式打开加密媒体。";
            NoticeTitle.Text = "播放器安装说明";
            NoticeText.Text = "1. 本地播放：凝然媒体播放器直接在本机读取并播放受支持的音频和视频文件。\n\n" +
                "2. 安全查看：同时安装凝然加密后，凝然加密会在验证后调用播放器读取加密媒体；不会把加密内容另存为普通媒体文件。\n\n" +
                "3. 文件关联：默认勾选后，播放器会注册 MP3、WAV、M4A、AAC、FLAC、OGG、WMA 及 MP4、M4V、MOV、AVI、WMV、WEBM、MKV、MPEG、MPG、3GP、TS、MPV。Windows 可能保留已有的默认播放器，您仍可在系统设置中选择凝然媒体播放器。\n\n" +
                "4. 卸载范围：卸载只删除播放器、快捷方式和属于播放器的文件关联，不会删除您的普通媒体文件。";
            AcceptNoticeCheck.Content = "我已阅读并理解播放器的本地播放、安全查看、文件关联和卸载范围";
            OptionsDescription.Text = "播放器安装在受保护的系统位置；默认注册已支持的音频和视频格式。";
            FileAssociationsCheck.IsChecked = true;
            FileAssociationsCheck.Visibility = Visibility.Visible;
            FileAssociationsCheck.Content = "用凝然媒体播放器打开已支持的音频和视频文件";
            FileAssociationDescription.Visibility = Visibility.Visible;
            FileAssociationDescription.Text = "包含 7 种音频格式和 12 种视频格式；可取消勾选以不注册关联。";
            DeleteUserDataPanel.Visibility = Visibility.Collapsed;
            UninstallDescription.Text = "卸载只删除播放器、快捷方式和属于播放器的文件关联，不会删除普通媒体文件。";
            return;
        }

        if (SetupProduct.SupportsFileAssociations)
        {
            WelcomeDescription.Text = _texts.WelcomeDescription;
            OptionsDescription.Text = _texts.OptionsDescription;
            UninstallDescription.Text = _texts.UninstallDescription;
            return;
        }

    }

    private void ApplyTexts()
    {
        var t = _texts;
        LeftModeText.Text = t.ProductMode;
        StepOneText.Text = t.StepOne;
        StepTwoText.Text = t.StepTwo;
        StepThreeText.Text = t.StepThree;
        AdminRequiredText.Text = t.AdminRequired;
        WindowCaption.Text = t.InstallerTitle;
        WelcomeTitle.Text = t.WelcomeTitle;
        WelcomeDescription.Text = t.WelcomeDescription;
        NoticeTitle.Text = t.NoticeTitle;
        NoticeText.Text = t.NoticeText;
        AcceptNoticeCheck.Content = t.AcceptNotice;
        OptionsTitle.Text = t.OptionsTitle;
        OptionsDescription.Text = t.OptionsDescription;
        InstallLocationLabel.Text = t.InstallLocation;
        DesktopShortcutCheck.Content = t.CreateDesktopShortcut;
        StartMenuShortcutCheck.Content = t.CreateStartMenuShortcut;
        FileAssociationsCheck.Content = t.AssociateFiles;
        FileAssociationDescription.Text = t.AssociationDescription;
        BackButton.Content = t.Back;
        CancelButton.Content = t.Cancel;
        NextButton.Content = t.Continue;
        ProgressTitle.Text = t.ProgressTitle;
        ProgressMessage.Text = t.Preparing;
        FinishTitle.Text = t.FinishTitle;
        FinishMessage.Text = t.FinishMessage;
        RunAfterInstallCheck.Content = t.RunAfterInstall;
        LanguageLabel.Text = t.Language;
        VersionText.Text = string.Format(t.VersionFormat, SetupProduct.Version);
        UninstallTitle.Text = t.UninstallTitle;
        UninstallDescription.Text = t.UninstallDescription;
        ProgramLocationLabel.Text = t.ProgramLocation;
        DeleteUserDataCheck.Content = t.DeleteUserData;
        UserDataInventoryText.Text = t.UserDataCounting;
    }

    private void LanguageCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (LanguageCombo.SelectedItem is not System.Windows.Controls.ComboBoxItem item)
        {
            return;
        }

        _texts = string.Equals(item.Tag?.ToString(), "en", StringComparison.OrdinalIgnoreCase)
            ? InstallerTextCatalog.English
            : InstallerTextCatalog.Chinese;
        if (IsInitialized)
        {
            ApplyTexts();
            ConfigureProductText();
        }
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
                allowExistingInstall: true,
                verifyExistingPermissions: false);

            var existingState = InstallState.TryLoad(installPath);
            if (existingState is not null)
            {
                try
                {
                    SetupPathSafety.VerifyInstallDirectoryPermissions(installPath);
                }
                catch (InvalidOperationException exception)
                {
                    var choice = MessageBox.Show(
                        this,
                        _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer
                            ? $"The existing NingRan Encryption install directory has unsafe permissions.\n\n{exception.Message}\n\nThe installer must secure this directory first. Existing programs and personal data will be kept. Continue the upgrade?"
                            : $"检测到现有{SetupProduct.Name}安装目录的权限不安全：\n\n{exception.Message}\n\n安装程序需要先收紧该目录权限。现有程序和个人数据会保留，是否继续升级？",
                        _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer ? "Install directory permission repair required" : "需要修复安装目录权限",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning,
                        MessageBoxResult.No);
                    if (choice != MessageBoxResult.Yes)
                    {
                        return;
                    }

                    SetupPathSafety.HardenInstallDirectory(installPath);
                }
            }

            options = new SetupOptions(
                installPath,
                DesktopShortcutCheck.IsChecked == true,
                StartMenuShortcutCheck.IsChecked == true,
                FileAssociationsCheck.IsChecked == true,
                string.Equals(
                    LanguageCombo.SelectedItem is System.Windows.Controls.ComboBoxItem item
                        ? item.Tag?.ToString()
                        : null,
                    "en",
                    StringComparison.OrdinalIgnoreCase)
                    ? "en"
                    : "zh");
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message,
                _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer ? "Installation location unavailable" : "安装位置不可用",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SetBusy(true);
        var englishInstall = _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer;
        ProgressTitle.Text = englishInstall ? "Installing NingRan Encryption" : $"正在安装{SetupProduct.Name}";
        ProgressMessage.Text = englishInstall ? "Checking offline package…" : "正在检查离线安装包…";
        InstallProgressBar.Value = 0;
        ShowStage(InstallerStage.Progress);
        try
        {
            await using var payload = App.OpenPayload();
            var progress = new Progress<SetupProgress>(value =>
            {
                InstallProgressBar.Value = value.Percentage;
                ProgressMessage.Text = TranslateProgress(value.Message, englishInstall);
            });
            var state = await _engine.InstallAsync(
                options,
                payload,
                SetupBootstrap.CopyAuthenticatedOriginTo,
                progress);
            File.WriteAllText(Path.Combine(state.InstallPath, "language.txt"),
                string.Equals(LanguageCombo.SelectedItem is System.Windows.Controls.ComboBoxItem item ? item.Tag?.ToString() : null, "en", StringComparison.OrdinalIgnoreCase)
                    ? "en"
                    : "zh");
            _installedExecutable = Path.Combine(state.InstallPath, SetupProduct.MainExecutableName);
            FinishTitle.Text = _texts == InstallerTextCatalog.English
                ? "NingRan Encryption installation complete"
                : $"{SetupProduct.Name}安装完成";
            FinishMessage.Text = SetupProduct.IsMediaPlayer
                ? (_texts == InstallerTextCatalog.English
                    ? $"NingRan Media Player {SetupProduct.Version} is installed. Supported audio and video associations were registered as selected."
                    : $"{SetupProduct.Name} {SetupProduct.Version} 已完整安装。已按您的选择注册受支持的音频和视频格式。")
                : (_texts == InstallerTextCatalog.English
                    ? $"NingRan Encryption {SetupProduct.Version} is installed. Identities, settings, and existing data were not overwritten."
                    : $"{SetupProduct.Name} {SetupProduct.Version} 已完整安装。身份、设置和已有数据均未被覆盖。");
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
                _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer
                    ? $"Installation did not complete. The previous version and personal data were kept as far as possible.\n\n{exception.Message}"
                    : $"安装没有完成，旧版本和个人数据会尽量保持原样。\n\n{exception.Message}",
                _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer ? "Installation failed" : "安装失败",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private async Task UninstallAsync()
    {
        var english = _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer;
        var deleteUserData = SetupProduct.HasUserData && DeleteUserDataCheck.IsChecked == true;
        var inventoryText = _userDataInventory.IsEmpty
            ? english ? "No personal data was found." : "没有发现个人数据。"
            : english
                ? $"Personal data inventory: {_userDataInventory.FileCount:N0} files, {_userDataInventory.DirectoryCount:N0} folders, {FormatByteSize(_userDataInventory.TotalBytes)} total."
                : $"个人数据清单：{_userDataInventory.FileCount:N0} 个文件、{_userDataInventory.DirectoryCount:N0} 个文件夹，共 {FormatByteSize(_userDataInventory.TotalBytes)}。";
        var uninstallMessage = SetupProduct.IsMediaPlayer
            ? $"将删除{SetupProduct.Name}程序、快捷方式和属于播放器的文件关联。\n\n不会删除普通媒体文件。是否继续？"
            : deleteUserData
                ? english
                    ? $"NingRan Encryption will be removed.\n\n{inventoryText}\n\nYou selected deletion of all personal data. Continue?"
                    : $"将删除{SetupProduct.Name}程序。\n\n{inventoryText}\n\n您还勾选了删除全部个人数据。是否继续？"
                : english
                    ? $"NingRan Encryption will be removed.\n\n{inventoryText}\n\nPersonal data will be kept. Continue?"
                    : $"将删除{SetupProduct.Name}程序。\n\n{inventoryText}\n\n个人数据将全部保留。是否继续？";
        var choice = MessageBox.Show(
            this,
            uninstallMessage,
            english ? "Confirm uninstall" : "确认卸载",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (choice != MessageBoxResult.Yes)
        {
            return;
        }

        if (deleteUserData && MessageBox.Show(
                this,
                english
                    ? $"Final confirmation: the personal data listed above will be permanently deleted. Identities, contacts, and device registrations cannot be restored from the program after deletion.\n\n{inventoryText}\n\nPermanently delete now?"
                    : $"最后确认：即将永久删除上面列出的个人数据。身份、联系人和设备登记删除后不能从程序内恢复。\n\n{inventoryText}\n\n确定永久删除吗？",
                english ? "Confirm personal data deletion" : "再次确认删除个人数据",
                MessageBoxButton.YesNo,
                MessageBoxImage.Stop,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        SetBusy(true);
        ProgressTitle.Text = english ? "Uninstalling NingRan Encryption" : $"正在卸载{SetupProduct.Name}";
        ProgressMessage.Text = SetupProduct.IsMediaPlayer
            ? "正在删除播放器、快捷方式和文件关联…"
            : english
                ? (deleteUserData ? "Removing the program and confirmed personal data…" : "Removing the program; personal data will be kept…")
                : deleteUserData ? "正在删除程序和已确认的个人数据…" : "正在删除程序，个人数据会保留…";
        InstallProgressBar.IsIndeterminate = true;
        ShowStage(InstallerStage.Progress);
        try
        {
            _ = await Task.Run(() => _engine.PrepareUninstall(
                _uninstallPath ?? throw new InvalidOperationException("无法确定卸载位置。"),
                deleteUserData));
            CleanupScheduler.ScheduleInstalledDirectoryCleanup(_uninstallPath!);
            _uninstallCleanupScheduled = true;
            FinishTitle.Text = english ? "NingRan Encryption uninstalled" : $"{SetupProduct.Name}已卸载";
            FinishMessage.Text = SetupProduct.IsMediaPlayer
                ? "播放器、快捷方式和属于播放器的文件关联已经删除。关闭窗口后将完成最后清理。"
                : english
                    ? (deleteUserData
                        ? "The program and the personal data you confirmed twice were deleted. Final cleanup will finish after this window closes."
                        : "The program was removed; identities, contacts, device registrations, and settings were kept. Final cleanup will finish after this window closes.")
                    : deleteUserData
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
            MessageBox.Show(this, exception.Message,
                _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer ? "Uninstall incomplete" : "卸载未完成",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void FinishAndClose()
    {
        if (!_isUninstall && RunAfterInstallCheck.IsChecked == true && File.Exists(_installedExecutable))
        {
            try
            {
                var explorer = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "explorer.exe");
                Process.Start(new ProcessStartInfo
                {
                    FileName = explorer,
                    UseShellExecute = true,
                    Arguments = $"\"{_installedExecutable}\"",
                })?.Dispose();
            }
            catch (Exception exception)
            {
                var english = _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer;
                MessageBox.Show(this,
                    english ? $"The program was installed, but it could not be started automatically.\n\n{exception.Message}" : $"程序已经安装，但暂时无法自动启动：\n\n{exception.Message}",
                    english ? "Could not start automatically" : "无法自动启动", MessageBoxButton.OK, MessageBoxImage.Warning);
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
            var english = _texts == InstallerTextCatalog.English && !SetupProduct.IsMediaPlayer;
            MessageBox.Show(this, english ? "Program files are still being processed. Please wait for the current operation to finish." : "正在处理程序文件，请等待当前操作完成。", english ? "NingRan Encryption" : SetupProduct.Name,
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

    private static string TranslateProgress(string message, bool english) =>
        !english ? message : message switch
        {
            "正在检查离线安装包…" => "Checking offline package…",
            "正在更新程序文件…" => "Updating program files…",
            "正在创建快捷方式和文件关联…" => "Creating shortcuts and file associations…",
            "正在创建快捷方式…" => "Creating shortcuts…",
            "安装完成" => "Installation complete",
            _ => message,
        };

    private enum InstallerStage
    {
        Welcome,
        Options,
        Progress,
        Uninstall,
        Finish,
    }
}
