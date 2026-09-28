using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using NingRan.Core;

namespace NingRan.Windows;

public partial class VaultWindow : Window
{
    private readonly NrVaultService _vaultService;
    private readonly NrArchiveService _archiveService;
    private readonly NrKeyFileService _keyFileService;
    private readonly NrPhysicalDeviceService _physicalDeviceService;
    private readonly VaultWindowMode _windowMode;
    private readonly List<string> _sourcePaths = [];
    private readonly List<string> _hiddenSourcePaths = [];
    private VaultSession? _vaultSession;
    private VaultDriveMount? _vaultDrive;
    private VaultWorkspaceWindow? _workspaceWindow;
    private bool _busy;
    private bool _closing;
    private bool _vaultArchiveExportInProgress;
    private CancellationTokenSource? _operationCancellation;
    private readonly System.Windows.Threading.DispatcherTimer _idleTimer = new() { Interval = TimeSpan.FromSeconds(30) };
    private const uint LockAfterIdleMilliseconds = 15 * 60 * 1000;
    private bool _syncingWindowState;
    private Window? _stateOwner;

    public VaultWindow(
        NrVaultService vaultService,
        NrArchiveService archiveService,
        NrKeyFileService keyFileService,
        NrPhysicalDeviceService physicalDeviceService,
        VaultWindowMode windowMode = VaultWindowMode.Create)
    {
        InitializeComponent();
        _vaultService = vaultService;
        _archiveService = archiveService;
        _keyFileService = keyFileService;
        _physicalDeviceService = physicalDeviceService;
        _windowMode = windowMode;
        RefreshPhysicalDevices();
        ApplyLanguage();
        ApplyWindowMode();
        _idleTimer.Tick += IdleTimer_Tick;
        SystemEvents.SessionSwitch += SystemEvents_SessionSwitch;
        SystemEvents.PowerModeChanged += SystemEvents_PowerModeChanged;
        Loaded += VaultWindow_Loaded;
        Closed += VaultWindow_Closed;
    }

    private void VaultWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _stateOwner = Owner;
        if (_stateOwner is not null) _stateOwner.StateChanged += Owner_StateChanged;
    }

    private void VaultWindow_Closed(object? sender, EventArgs e)
    {
        if (_stateOwner is not null) _stateOwner.StateChanged -= Owner_StateChanged;
        _stateOwner = null;
    }

    private void Owner_StateChanged(object? sender, EventArgs e)
    {
        if (_syncingWindowState || _stateOwner is null || WindowState == _stateOwner.WindowState) return;
        try
        {
            _syncingWindowState = true;
            WindowState = _stateOwner.WindowState;
        }
        finally { _syncingWindowState = false; }
    }

    private void VaultWindow_StateChanged(object? sender, EventArgs e)
    {
        if (_syncingWindowState || Owner is null || Owner.WindowState == WindowState) return;
        try
        {
            _syncingWindowState = true;
            Owner.WindowState = WindowState;
        }
        finally { _syncingWindowState = false; }
    }

    private bool IsEnglish => UiLanguage.IsEnglish;

    private void ApplyLanguage()
    {
        if (!IsEnglish) return;
        TitleText.Text = "NingRan Vault";
        SubtitleText.Text = "Fixed-capacity vaults support an everyday space and an optional private space; either password opens its own content from the same entry point.";
        LocationTitle.Text = "Vault location"; ChooseLocationButton.Content = "Choose location"; VaultNameLabel.Text = "Vault name";
        VaultNameInput.Text = "My Vault"; SelectedSourcesText.Text = "No files or folders selected.";
        AddFilesButton.Content = "Add files"; AddFolderButton.Content = "Add folder"; ClearSourcesButton.Content = "Clear selection";
        HiddenSourcesTitle.Text = "Initial private-space sources (optional)";
        HiddenSourcesHint.Text = "These sources appear only in the space opened by the second password.";
        AddHiddenFilesButton.Content = "Add files"; AddHiddenFolderButton.Content = "Add folder"; ClearHiddenSourcesButton.Content = "Clear selection";
        ProtectionTitle.Text = "Protection"; PasswordLabel.Text = "Password"; ConfirmPasswordLabel.Text = "Confirm password";
        KeyFileLabel.Text = "Key file"; ChooseKeyButton.Content = "Choose"; PhysicalLabel.Text = "Authorized physical devices";
        PhysicalHint.Text = "All selected devices are required during creation. Lost devices cannot be recovered.";
        SizeProtectionLabel.Text = "Size protection"; CapacityLabel.Text = "Fixed capacity";
        CapacityHintText.Text = "The total capacity cannot be changed after creation. Unused space is filled with random data.";
        CreateHiddenSpaceCheckBox.Content = "Create a private space";
        HiddenSpaceOptionHint.Text = "The same vault can open two independent spaces with different passwords. This reduces direct disclosure in the interface, but cannot guarantee that every forensic method will be unable to infer its existence.";
        HiddenSpaceTitle.Text = "Second password and space capacities";
        HiddenPasswordLabel.Text = "Second password"; ConfirmHiddenPasswordLabel.Text = "Confirm second password";
        DailyCapacityLabel.Text = "Everyday-space capacity (GB)"; HiddenCapacityLabel.Text = "Private-space capacity (GB)";
        HiddenSpaceWarning.Text = "The second password uses password-only protection. A forgotten password cannot be recovered, and the two capacities cannot be changed after creation.";
        LocationNavButton.Content = "Vault location"; ProtectionNavButton.Content = "Protection";
        ActionsTitle.Text = "Vault actions"; CreateButton.Content = "Create and open vault";
        OpenButton.Content = "Open existing vault"; UpgradeButton.Content = "Upgrade legacy vault"; ExistingVaultLabel.Text = "Existing vault path"; ChooseExistingButton.Content = "Choose file"; ChooseLegacyButton.Content = "Legacy folder";
        StatusText.Text = "Vault is not unlocked."; AppendButton.Content = "Add sources"; ImportButton.Content = "Import .nrenc";
        AppendFilesMenuItem.Header = "Add files..."; AppendFolderMenuItem.Header = "Add folder...";
        ExportButton.Content = "Export as .nrenc"; VerifyButton.Content = "Full check"; HistoryButton.Content = "History"; LockButton.Content = "Lock and remove drive";
        InternalBrowseButton.Content = "Browse inside app";
        SafetyNoticeText.Text = "Security notice: third-party software may leave recent-file records, recovery files, thumbnails, or cloud-sync copies. This preview cannot prevent those copies and is not a backup.";
        HistorySettingsTitle.Text = "History settings for this vault";
        HistorySettingsHint.Text = "These settings apply only to the currently unlocked vault, not to other vaults or the whole app.";
        HistoryDaysLabel.Text = "Retention days";
        HistoryBytesLabel.Text = "Space limit (bytes; 0 = unlimited)";
        SaveHistorySettingsButton.Content = "Save vault settings";
        CancelOperationButton.Content = "Cancel current operation";
        CreateActionHint.Text = "Review the previous pages, then create the vault. It will be mounted as a temporary drive when ready.";
        OpenHintText.Text = "Choose a vault and enter its password. It will be mounted and opened in File Explorer.";
        OpenPasswordLabel.Text = "Vault password";
        OpenKeyFileLabel.Text = "Original key file";
        OpenKeyHintText.Text = "Choose this for an everyday space that originally used a key file. It is not needed when the second password opens the other space.";
        ChooseOpenKeyButton.Content = "Choose";
        OpenButton.Content = "Mount and open";
        UpgradeCapacityLabel.Text = "Fixed capacity after upgrade";
        if (ModeCombo.Items.Count == 3)
        {
            ((ComboBoxItem)ModeCombo.Items[0]).Content = "Password";
            ((ComboBoxItem)ModeCombo.Items[1]).Content = "Password + key file";
            ((ComboBoxItem)ModeCombo.Items[2]).Content = "Password + physical device";
            ((ComboBoxItem)SizeProtectionCombo.Items[0]).Content = "Save space";
            ((ComboBoxItem)SizeProtectionCombo.Items[1]).Content = "Hide exact size (recommended)";
            ((ComboBoxItem)CapacityCombo.Items[4]).Content = "Custom";
            ((ComboBoxItem)UpgradeCapacityCombo.Items[4]).Content = "Custom";
        }
    }

    private void ApplyWindowMode()
    {
        var creating = _windowMode == VaultWindowMode.Create;
        Title = IsEnglish
            ? (creating ? "Create a vault" : "Open a vault")
            : (creating ? "创建保险箱" : "打开保险箱");
        TitleText.Text = Title;
        SubtitleText.Text = IsEnglish
            ? (creating
                ? "Set up a new fixed-capacity vault. Creation settings are kept separate from opening an existing vault."
                : "Choose an existing vault and mount the space selected by its password as a temporary drive.")
            : (creating
                ? "建立新的固定容量保险箱；创建设置与打开已有保险箱完全分开。"
                : "选择已有保险箱，并把该密码对应的空间挂载为临时磁盘。");
        LocationNavButton.Visibility = creating ? Visibility.Visible : Visibility.Collapsed;
        ProtectionNavButton.Visibility = creating ? Visibility.Visible : Visibility.Collapsed;
        ActionsNavButton.Content = IsEnglish
            ? (creating ? "Finish creation" : "Open vault")
            : (creating ? "完成创建" : "打开保险箱");
        CreateSetupPanel.Visibility = creating ? Visibility.Visible : Visibility.Collapsed;
        OpenSetupPanel.Visibility = creating ? Visibility.Collapsed : Visibility.Visible;
        ActionsTitle.Text = IsEnglish
            ? (creating ? "Finish creation" : "Open vault")
            : (creating ? "完成创建" : "打开保险箱");
        if (creating) ShowPage(LocationPage, LocationNavButton);
        else ShowPage(ActionsPage, ActionsNavButton);
    }

    private void ChooseLocation_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = IsEnglish ? "Choose the parent folder" : "选择保险箱保存位置" };
        if (dialog.ShowDialog(this) == true)
        {
            VaultLocationInput.Text = dialog.FolderName;
            UpdateCapacityHint();
        }
    }

    private async void ChooseExisting_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = IsEnglish ? "Choose an existing NingRan vault file" : "选择已有的凝然保险箱文件", Filter = IsEnglish ? "NingRan vault files|*" : "凝然保险箱文件|*" };
        if (dialog.ShowDialog(this) == true)
        {
            ExistingVaultInput.Text = dialog.FileName;
            await RefreshOpenRequirementsAsync(dialog.FileName);
        }
    }

    private async void ChooseLegacy_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = IsEnglish ? "Choose a legacy .nrvault folder" : "选择旧版 .nrvault 保险箱文件夹" };
        if (dialog.ShowDialog(this) == true)
        {
            ExistingVaultInput.Text = dialog.FolderName;
            await RefreshOpenRequirementsAsync(dialog.FolderName);
        }
    }

    private void ChooseOpenKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = IsEnglish ? "Choose the original key file" : "选择原密匙文件", Filter = "All files|*.*|NingRan key files|*.nrkey", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) OpenKeyFileInput.Text = dialog.FileName;
    }

    private async Task<VaultInfo?> RefreshOpenRequirementsAsync(string path, bool showErrors = true)
    {
        try
        {
            var info = await _vaultService.InspectAsync(path);
            OpenKeyPanel.Visibility = info.Mode == EncryptionMode.Advanced ? Visibility.Visible : Visibility.Collapsed;
            var canUpgrade = info.FormatVersion < 2 && File.Exists(path);
            OpenUpgradePanel.Visibility = canUpgrade ? Visibility.Visible : Visibility.Collapsed;
            UpgradeButton.Visibility = canUpgrade ? Visibility.Visible : Visibility.Collapsed;
            return info;
        }
        catch (Exception exception)
        {
            OpenKeyPanel.Visibility = Visibility.Collapsed;
            OpenUpgradePanel.Visibility = Visibility.Collapsed;
            UpgradeButton.Visibility = Visibility.Collapsed;
            if (showErrors) ShowError(IsEnglish ? "Could not read the vault" : "无法读取保险箱", exception);
            return null;
        }
    }

    private void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = IsEnglish ? "Choose files" : "选择要加入保险箱的文件", Filter = "All files|*.*", Multiselect = true, CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) AddSources(dialog.FileNames);
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = IsEnglish ? "Choose a folder" : "选择要加入保险箱的文件夹" };
        if (dialog.ShowDialog(this) == true) AddSources([dialog.FolderName]);
    }

    private void ClearSources_Click(object sender, RoutedEventArgs e)
    {
        _sourcePaths.Clear();
        RefreshSourceList();
    }

    private void AddHiddenFiles_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = IsEnglish ? "Choose private-space files" : "选择要加入隐蔽空间的文件", Filter = "All files|*.*", Multiselect = true, CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) AddHiddenSources(dialog.FileNames);
    }

    private void AddHiddenFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = IsEnglish ? "Choose a private-space folder" : "选择要加入隐蔽空间的文件夹" };
        if (dialog.ShowDialog(this) == true) AddHiddenSources([dialog.FolderName]);
    }

    private void ClearHiddenSources_Click(object sender, RoutedEventArgs e)
    {
        _hiddenSourcePaths.Clear();
        RefreshHiddenSourceList();
    }

    private void AddSources(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            var full = Path.GetFullPath(path);
            if (!_sourcePaths.Contains(full, StringComparer.OrdinalIgnoreCase)) _sourcePaths.Add(full);
        }
        RefreshSourceList();
    }

    private void AddHiddenSources(IEnumerable<string> paths)
    {
        foreach (var path in paths)
        {
            var full = Path.GetFullPath(path);
            if (!_hiddenSourcePaths.Contains(full, StringComparer.OrdinalIgnoreCase)) _hiddenSourcePaths.Add(full);
        }
        RefreshHiddenSourceList();
    }

    private void RefreshSourceList()
    {
        SourceList.ItemsSource = null;
        SourceList.ItemsSource = _sourcePaths.ToArray();
        SelectedSourcesText.Text = _sourcePaths.Count == 0
            ? (IsEnglish ? "No files or folders selected." : "尚未选择加入保险箱的资料。")
            : (IsEnglish ? $"Selected {_sourcePaths.Count:N0} source(s)." : $"已选择 {_sourcePaths.Count:N0} 个文件或文件夹。");
    }

    private void RefreshHiddenSourceList()
    {
        HiddenSourceList.ItemsSource = null;
        HiddenSourceList.ItemsSource = _hiddenSourcePaths.ToArray();
    }

    private void RefreshPhysicalDevices()
    {
        try { PhysicalList.ItemsSource = _physicalDeviceService.ListRegisteredDevices(); }
        catch { PhysicalList.ItemsSource = Array.Empty<PhysicalDeviceDescriptor>(); }
    }

    private void ModeCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (KeyPanel is null) return;
        if (CreateHiddenSpaceCheckBox?.IsChecked == true && ModeCombo.SelectedIndex == 2)
        {
            ModeCombo.SelectedIndex = 0;
        }
        KeyPanel.Visibility = ModeCombo.SelectedIndex == 1 ? Visibility.Visible : Visibility.Collapsed;
        PhysicalPanel.Visibility = ModeCombo.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void CreateHiddenSpace_Changed(object sender, RoutedEventArgs e)
    {
        if (HiddenSpacePanel is null || HiddenSourcesPanel is null || ModeCombo is null) return;
        var enabled = CreateHiddenSpaceCheckBox.IsChecked == true;
        HiddenSpacePanel.Visibility = enabled ? Visibility.Visible : Visibility.Collapsed;
        HiddenSourcesPanel.Visibility = enabled ? Visibility.Visible : Visibility.Collapsed;
        if (ModeCombo.Items.Count > 2 && ModeCombo.Items[2] is ComboBoxItem physical)
            physical.IsEnabled = !enabled;
        if (enabled && ModeCombo.SelectedIndex == 2) ModeCombo.SelectedIndex = 0;
        if (enabled) SetRecommendedWorkspaceCapacities();
    }

    private void CapacityCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CustomCapacityInput is null) return;
        CustomCapacityInput.Visibility = CapacityCombo.SelectedIndex == 4 ? Visibility.Visible : Visibility.Collapsed;
        UpdateCapacityHint();
        if (CreateHiddenSpaceCheckBox?.IsChecked == true) SetRecommendedWorkspaceCapacities();
    }

    private void CustomCapacityInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (CapacityCombo is null || CapacityCombo.SelectedIndex != 4) return;
        UpdateCapacityHint();
        if (CreateHiddenSpaceCheckBox?.IsChecked == true) SetRecommendedWorkspaceCapacities();
    }

    private void UpgradeCapacityCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (UpgradeCustomCapacityInput is null) return;
        UpgradeCustomCapacityInput.Visibility = UpgradeCapacityCombo.SelectedIndex == 4
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void UpdateCapacityHint()
    {
        if (CapacityHintText is null || CapacityCombo is null) return;
        if (!TryGetSelectedCapacity(out var capacity))
        {
            CapacityHintText.Text = IsEnglish ? "Enter a valid custom capacity in GB." : "请输入有效的自定义 GB 容量。";
            return;
        }
        var freeText = "";
        try
        {
            if (!string.IsNullOrWhiteSpace(VaultLocationInput?.Text))
            {
                var root = Path.GetPathRoot(VaultLocationInput.Text);
                if (!string.IsNullOrEmpty(root)) freeText = IsEnglish
                    ? $" Free on disk: {FormatBytes(new DriveInfo(root).AvailableFreeSpace)}."
                    : $" 保存磁盘剩余：{FormatBytes(new DriveInfo(root).AvailableFreeSpace)}。";
            }
        }
        catch { }
        var estimated = TimeSpan.FromSeconds(Math.Max(1, capacity / (250d * 1024 * 1024)));
        CapacityHintText.Text = IsEnglish
            ? $"Final file: {FormatBytes(capacity)}.{freeText} Estimated initialization: about {Math.Ceiling(estimated.TotalMinutes):0} minute(s). Capacity cannot be changed later."
            : $"最终文件：{FormatBytes(capacity)}。{freeText}预计初始化约 {Math.Ceiling(estimated.TotalMinutes):0} 分钟；创建后不能调整。";
    }

    private bool TryGetSelectedCapacity(out long capacity)
    {
        capacity = 0;
        double gib;
        if (CapacityCombo.SelectedIndex == 4)
        {
            if (!double.TryParse(CustomCapacityInput.Text, out gib)) return false;
        }
        else if (CapacityCombo.SelectedItem is ComboBoxItem item && double.TryParse(item.Tag?.ToString(), out var selected))
        {
            gib = selected;
        }
        else return false;
        if (gib < 0.125 || gib > 16 * 1024) return false;
        capacity = checked((long)(gib * 1024 * 1024 * 1024));
        return true;
    }

    private bool TryGetUpgradeCapacity(out long capacity)
    {
        capacity = 0;
        double gib;
        if (UpgradeCapacityCombo.SelectedIndex == 4)
        {
            if (!double.TryParse(UpgradeCustomCapacityInput.Text, out gib)) return false;
        }
        else if (UpgradeCapacityCombo.SelectedItem is ComboBoxItem item &&
                 double.TryParse(item.Tag?.ToString(), out var selected))
        {
            gib = selected;
        }
        else return false;
        if (gib < 0.125 || gib > 16 * 1024) return false;
        capacity = checked((long)(gib * 1024 * 1024 * 1024));
        return true;
    }

    private void SetRecommendedWorkspaceCapacities()
    {
        if (DailyCapacityInput is null || HiddenCapacityInput is null || !TryGetSelectedCapacity(out var total)) return;
        var totalGib = total / (1024d * 1024 * 1024);
        DailyCapacityInput.Text = (totalGib * 0.55).ToString("0.###");
        HiddenCapacityInput.Text = (totalGib * 0.35).ToString("0.###");
    }

    private bool TryGetWorkspaceCapacities(long totalCapacity, out long dailyCapacity, out long hiddenCapacity)
    {
        dailyCapacity = 0;
        hiddenCapacity = 0;
        if (!double.TryParse(DailyCapacityInput.Text, out var dailyGib) ||
            !double.TryParse(HiddenCapacityInput.Text, out var hiddenGib) ||
            dailyGib <= 0 || hiddenGib <= 0)
            return false;
        try
        {
            dailyCapacity = checked((long)(dailyGib * 1024 * 1024 * 1024));
            hiddenCapacity = checked((long)(hiddenGib * 1024 * 1024 * 1024));
        }
        catch (OverflowException) { return false; }
        return dailyCapacity >= 1024 * 1024 && hiddenCapacity >= 1024 * 1024 &&
               dailyCapacity <= totalCapacity && hiddenCapacity <= totalCapacity - dailyCapacity;
    }

    private void ChooseKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = IsEnglish ? "Choose key file" : "选择密匙文件", Filter = "All files|*.*|NingRan key files|*.nrkey", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) KeyFileInput.Text = dialog.FileName;
    }

    private async void Create_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _vaultSession is not null) return;
        if (string.IsNullOrWhiteSpace(VaultLocationInput.Text) || string.IsNullOrWhiteSpace(VaultNameInput.Text))
        {
            ShowInfo(IsEnglish ? "Choose a location and enter a vault name." : "请先选择保存位置并填写保险箱名称。", MessageBoxImage.Warning); return;
        }
        var createHiddenSpace = CreateHiddenSpaceCheckBox.IsChecked == true;
        using var password = ReadPassword(PasswordInput);
        using var confirmation = ReadPassword(ConfirmPasswordInput);
        using var hiddenPassword = createHiddenSpace ? ReadPassword(HiddenPasswordInput) : SensitivePassword.FromString(string.Empty);
        using var hiddenConfirmation = createHiddenSpace ? ReadPassword(ConfirmHiddenPasswordInput) : SensitivePassword.FromString(string.Empty);
        if (password.IsEmpty || confirmation.IsEmpty || !password.FixedTimeEquals(confirmation))
        {
            ShowInfo(IsEnglish ? "Enter the same non-empty password twice." : "请两次输入相同且非空的保险箱密码。", MessageBoxImage.Warning); return;
        }
        try { PasswordRules.ValidateForCreation(password); }
        catch (ArgumentException exception) { ShowInfo(exception.Message, MessageBoxImage.Warning); return; }
        if (createHiddenSpace)
        {
            if (hiddenPassword.IsEmpty || hiddenConfirmation.IsEmpty || !hiddenPassword.FixedTimeEquals(hiddenConfirmation))
            {
                ShowInfo(IsEnglish ? "Enter the same non-empty second password twice." : "请两次输入相同且非空的秘密密码。", MessageBoxImage.Warning); return;
            }
            try { PasswordRules.ValidateForCreation(hiddenPassword); }
            catch (ArgumentException exception) { ShowInfo(exception.Message, MessageBoxImage.Warning); return; }
            if (password.FixedTimeEquals(hiddenPassword))
            {
                ShowInfo(IsEnglish ? "The two passwords must be clearly different." : "日常密码和秘密密码必须明显不同。", MessageBoxImage.Warning); return;
            }
        }
        if (ModeCombo.SelectedIndex == 1 && !File.Exists(KeyFileInput.Text))
        {
            ShowInfo(IsEnglish ? "Choose a valid key file." : "密码加密匙方式必须选择有效的密匙文件。", MessageBoxImage.Warning); return;
        }
        var devices = PhysicalList.SelectedItems.Cast<PhysicalDeviceDescriptor>().ToArray();
        if (ModeCombo.SelectedIndex == 2 && devices.Length == 0)
        {
            ShowInfo(IsEnglish ? "Select at least one physical device." : "密码加物理设备方式至少选择一个已登记设备。", MessageBoxImage.Warning); return;
        }
        if (!TryGetSelectedCapacity(out var fixedCapacity))
        {
            ShowInfo(IsEnglish ? "Choose a valid fixed capacity." : "请选择有效的固定总容量。", MessageBoxImage.Warning); return;
        }
        long dailyCapacity = 0;
        long hiddenCapacity = 0;
        if (createHiddenSpace && !TryGetWorkspaceCapacities(fixedCapacity, out dailyCapacity, out hiddenCapacity))
        {
            ShowInfo(IsEnglish
                ? "Enter valid everyday and private capacities. Each must be at least 1 MB and their sum cannot exceed the total capacity."
                : "请填写有效的日常空间和隐蔽空间容量。每个至少 1 MB，合计不能超过固定总容量。", MessageBoxImage.Warning);
            return;
        }
        if (createHiddenSpace)
        {
            var boundaryConfirmation = MessageBox.Show(this,
                IsEnglish
                    ? "Before creating:\n\n• A forgotten password cannot be recovered.\n• Private-space use cannot resist every forensic or long-term observation method.\n• Exporting or opening plaintext in other programs may leave Windows or app records.\n• The total and two space capacities cannot be changed after creation.\n\nCreate the vault?"
                    : "创建前请确认：\n\n• 忘记任一密码都无法恢复对应内容。\n• 隐蔽功能不能抵抗所有专业取证和长期观察。\n• 导出明文或交给外部程序打开，可能留下 Windows 或软件记录。\n• 创建后不能调整总容量和两个空间的容量。\n\n是否继续创建？",
                IsEnglish ? "Confirm privacy boundaries" : "确认隐蔽功能边界",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (boundaryConfirmation != MessageBoxResult.Yes) return;
        }
        var vaultPath = Path.Combine(VaultLocationInput.Text, VaultNameInput.Text.Trim());
        try
        {
            SetBusy(true);
            _operationCancellation = new CancellationTokenSource();
            CancelOperationButton.IsEnabled = true;
            ProgressPanel.Visibility = Visibility.Visible;
            OperationProgress.Value = 0;
            ProgressStageText.Text = IsEnglish ? "Preparing vault…" : "正在准备保险箱…";
            ProgressPercentText.Text = "0%";
            var progress = new Progress<CryptoProgress>(value =>
            {
                var text = FormatProgressText(value);
                StatusText.Text = text;
                ProgressStageText.Text = text;
                var percent = value.Fraction * 100;
                OperationProgress.Value = percent;
                ProgressPercentText.Text = $"{percent:0}%";
            });
            var dailyMode = ModeCombo.SelectedIndex switch
            {
                1 => EncryptionMode.Advanced,
                2 => EncryptionMode.PhysicalDevice,
                _ => EncryptionMode.Standard,
            };
            if (createHiddenSpace)
            {
                using var request = new CreateDualVaultRequest(
                    vaultPath,
                    password,
                    hiddenPassword,
                    dailyMode,
                    dailyMode == EncryptionMode.Advanced ? KeyFileInput.Text : null,
                    _sourcePaths,
                    _hiddenSourcePaths,
                    SizeProtectionCombo.SelectedIndex == 1 ? VaultSizeProtection.HideExactSize : VaultSizeProtection.SaveSpace,
                    new System.Windows.Interop.WindowInteropHelper(this).Handle,
                    fixedCapacity,
                    dailyCapacity,
                    hiddenCapacity);
                await _vaultService.CreateDualAsync(request, progress, _operationCancellation.Token);
                HiddenPasswordInput.Clear();
                ConfirmHiddenPasswordInput.Clear();
            }
            else
            {
                using var request = new CreateVaultRequest(
                    vaultPath,
                    password,
                    dailyMode,
                    dailyMode == EncryptionMode.Advanced ? KeyFileInput.Text : null,
                    devices,
                    _sourcePaths,
                    SizeProtectionCombo.SelectedIndex == 1 ? VaultSizeProtection.HideExactSize : VaultSizeProtection.SaveSpace,
                    new System.Windows.Interop.WindowInteropHelper(this).Handle,
                    fixedCapacity);
                await _vaultService.CreateAsync(request, progress, _operationCancellation.Token);
            }
            StatusText.Text = IsEnglish ? "Vault created. Unlocking…" : "保险箱已创建，正在打开…";
            ExistingVaultInput.Text = vaultPath;
            using var unlockPassword = ReadPassword(PasswordInput);
            await UnlockPathAsync(
                ExistingVaultInput.Text,
                unlockPassword,
                dailyMode == EncryptionMode.Advanced ? KeyFileInput.Text : null);
        }
        catch (OperationCanceledException) { StatusText.Text = IsEnglish ? "Creation was cancelled. The incomplete vault was removed." : "创建已取消，未完成的保险箱已经清理。"; }
        catch (Exception exception) { ShowError(IsEnglish ? "Could not create the vault" : "无法创建保险箱", exception); }
        finally { _operationCancellation?.Dispose(); _operationCancellation = null; SetBusy(false); ProgressPanel.Visibility = Visibility.Collapsed; }
    }

    private async void Upgrade_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _vaultSession is not null) return;
        var sourcePath = ExistingVaultInput.Text;
        if (!File.Exists(sourcePath))
        {
            ShowInfo(IsEnglish ? "Choose a legacy single-file vault first." : "请先选择旧版单文件保险箱。", MessageBoxImage.Warning);
            return;
        }
        VaultInfo info;
        try
        {
            info = await _vaultService.InspectAsync(sourcePath);
            if (info.FormatVersion >= 2)
            {
                ShowInfo(IsEnglish ? "This vault already uses the new format." : "这个保险箱已经是新版格式，不需要升级。", MessageBoxImage.Information);
                return;
            }
        }
        catch (Exception exception)
        {
            ShowError(IsEnglish ? "Could not read the legacy vault" : "无法读取旧保险箱", exception);
            return;
        }
        using var password = ReadPassword(OpenPasswordInput);
        if (password.IsEmpty)
        {
            ShowInfo(IsEnglish ? "Enter the legacy vault password." : "请输入旧保险箱密码。", MessageBoxImage.Warning);
            return;
        }
        if (info.Mode == EncryptionMode.Advanced && !File.Exists(OpenKeyFileInput.Text))
        {
            ShowInfo(IsEnglish ? "Choose the original key file." : "请选择旧保险箱原来使用的密匙文件。", MessageBoxImage.Warning);
            return;
        }
        if (!TryGetUpgradeCapacity(out var capacity))
        {
            ShowInfo(IsEnglish ? "Choose a valid fixed capacity." : "请选择有效的新版固定总容量。", MessageBoxImage.Warning);
            return;
        }
        var save = new SaveFileDialog
        {
            Title = IsEnglish ? "Save the upgraded vault" : "保存升级后的新版保险箱",
            Filter = IsEnglish ? "NingRan vault files|*" : "凝然保险箱文件|*",
            FileName = Path.GetFileName(sourcePath) + (IsEnglish ? " (new)" : "（新版）"),
            InitialDirectory = Path.GetDirectoryName(sourcePath),
            AddExtension = false,
        };
        if (save.ShowDialog(this) != true) return;
        var confirmation = MessageBox.Show(this,
            IsEnglish
                ? "A separate new-format vault will be created. The original vault will not be changed or deleted. Continue?"
                : "程序会另外生成一个新版保险箱，原保险箱不会被修改或删除。是否继续？",
            IsEnglish ? "Upgrade legacy vault" : "升级旧保险箱",
            MessageBoxButton.YesNo,
            MessageBoxImage.Information);
        if (confirmation != MessageBoxResult.Yes) return;

        try
        {
            SetBusy(true);
            _operationCancellation = new CancellationTokenSource();
            CancelOperationButton.IsEnabled = true;
            ProgressPanel.Visibility = Visibility.Visible;
            OperationProgress.Value = 0;
            ProgressPercentText.Text = "0%";
            ProgressStageText.Text = IsEnglish ? "Preparing upgrade…" : "正在准备升级…";
            using var request = new UpgradeVaultRequest(
                sourcePath,
                save.FileName,
                password,
                info.Mode == EncryptionMode.Advanced ? OpenKeyFileInput.Text : null,
                new System.Windows.Interop.WindowInteropHelper(this).Handle,
                capacity);
            var progress = new Progress<CryptoProgress>(value =>
            {
                var text = FormatProgressText(value);
                StatusText.Text = text;
                ProgressStageText.Text = text;
                OperationProgress.Value = value.Fraction * 100;
                ProgressPercentText.Text = $"{value.Fraction * 100:0}%";
            });
            var result = await _vaultService.UpgradeLegacyAsync(
                request, progress, _operationCancellation.Token);
            ExistingVaultInput.Text = result.UpgradedInfo.VaultPath;
            await RefreshOpenRequirementsAsync(result.UpgradedInfo.VaultPath, showErrors: false);
            StatusText.Text = IsEnglish
                ? $"Upgrade completed. The original vault remains unchanged. New capacity: {FormatBytes(result.UpgradedInfo.CapacityBytes)}."
                : $"升级完成，原保险箱保持不变。新版固定容量：{FormatBytes(result.UpgradedInfo.CapacityBytes)}。";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = IsEnglish ? "Upgrade was cancelled. The incomplete new vault was removed." : "升级已取消，未完成的新版保险箱已经清理，原保险箱没有改变。";
        }
        catch (Exception exception) { ShowError(IsEnglish ? "Could not upgrade the vault" : "无法升级旧保险箱", exception); }
        finally
        {
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            SetBusy(false);
            ProgressPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void CancelOperation_Click(object sender, RoutedEventArgs e)
    {
        CancelOperationButton.IsEnabled = false;
        ProgressStageText.Text = IsEnglish ? "Cancelling and cleaning incomplete data…" : "正在取消并清理未完成内容…";
        _operationCancellation?.Cancel();
    }

    private async void Open_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _vaultSession is not null) return;
        var path = ExistingVaultInput.Text;
        if (!NrVaultService.IsVaultFolder(path) && !NrVaultService.IsVaultFile(path))
        {
            ShowInfo(IsEnglish ? "Choose a valid NingRan vault file or legacy vault folder first." : "请先选择有效的凝然保险箱文件或旧版保险箱文件夹。", MessageBoxImage.Warning); return;
        }
        var info = await RefreshOpenRequirementsAsync(path, showErrors: true);
        if (info is null) return;
        using var password = ReadPassword(OpenPasswordInput);
        if (password.IsEmpty) { ShowInfo(IsEnglish ? "Enter the vault password." : "请输入保险箱密码。", MessageBoxImage.Warning); return; }
        try
        {
            SetBusy(true);
            var keyFilePath = info.Mode == EncryptionMode.Advanced && File.Exists(OpenKeyFileInput.Text)
                ? OpenKeyFileInput.Text
                : null;
            await UnlockPathAsync(path, password, keyFilePath);
            OpenPasswordInput.Clear();
        }
        catch (Exception exception) { ShowError(IsEnglish ? "Could not unlock the vault" : "无法解锁保险箱", exception); }
        finally { SetBusy(false); }
    }

    private async Task UnlockPathAsync(string path, SensitivePassword password, string? keyFilePath)
    {
        using var request = new UnlockVaultRequest(path, password,
            keyFilePath,
            new System.Windows.Interop.WindowInteropHelper(this).Handle);
        var session = await _vaultService.UnlockAsync(request);
        VaultDriveMount? drive = null;
        Exception? mountFailure = null;
        try
        {
            drive = VaultDriveService.Mount(session);
        }
        catch (Exception exception)
        {
            mountFailure = exception;
        }
        _vaultSession = session;
        _vaultDrive = drive;
        if (session.Mode == EncryptionMode.PhysicalDevice)
        {
            _ = WatchPhysicalDeviceAsync(session);
        }
        ExistingVaultInput.Text = session.VaultPath;
        OpenSetupPanel.Visibility = Visibility.Collapsed;
        CreateSetupPanel.Visibility = Visibility.Collapsed;
        ActionsTitle.Text = IsEnglish ? "Vault opened" : "保险箱已打开";
        DriveText.Text = drive is not null
            ? (IsEnglish ? $"Temporary drive: {drive.MountPoint}" : $"临时磁盘：{drive.MountPoint}")
            : (IsEnglish ? "Mounting failed. The vault is open in the in-app fallback browser." : "临时磁盘挂载失败，已改用软件内备用查看。" );
        StatusText.Text = IsEnglish
            ? $"Unlocked. {session.Entries.Count:N0} entries, {FormatBytes(session.ContentBytes)} content, current-space capacity {FormatBytes(session.WorkspaceCapacityBytes)}."
            : $"已解锁。共 {session.Entries.Count:N0} 项内容，资料大小 {FormatBytes(session.ContentBytes)}，当前空间容量 {FormatBytes(session.WorkspaceCapacityBytes)}。";
        UnlockedActionsPanel.Visibility = Visibility.Visible;
        InternalBrowseButton.Visibility = drive is null ? Visibility.Visible : Visibility.Collapsed;
        ExportButton.Visibility = drive is null ? Visibility.Collapsed : Visibility.Visible;
        LockButton.Content = drive is null
            ? (IsEnglish ? "Lock vault" : "锁定保险箱")
            : (IsEnglish ? "Lock and remove drive" : "锁定并卸载磁盘");
        HistoryDaysInput.Text = session.HistoryRetentionDays.ToString();
        HistoryBytesInput.Text = session.HistoryMaximumBytes.ToString();
        var supportsHistory = session.Info.FormatVersion < 2;
        HistoryButton.IsEnabled = supportsHistory;
        HistorySettingsPanel.Visibility = supportsHistory ? Visibility.Visible : Visibility.Collapsed;
        HistoryDaysInput.IsEnabled = HistoryBytesInput.IsEnabled = SaveHistorySettingsButton.IsEnabled = supportsHistory;
        SidebarStatusText.Text = IsEnglish ? "Unlocked" : "已解锁";
        SidebarDriveText.Text = drive is not null
            ? (IsEnglish ? $"Temporary drive: {drive.MountPoint}" : $"临时磁盘：{drive.MountPoint}")
            : (IsEnglish ? "In-app fallback browsing" : "软件内备用查看");
        SidebarSpaceText.Text = IsEnglish ? $"Content: {FormatBytes(session.ContentBytes)}" : $"资料大小：{FormatBytes(session.ContentBytes)}";
        ShowPage(ActionsPage, ActionsNavButton);
        CreateButton.IsEnabled = false; OpenButton.IsEnabled = false; UpgradeButton.IsEnabled = false;
        _idleTimer.Start();
        if (drive is not null)
        {
            OpenMountedDrive(drive.MountPoint);
        }
        else
        {
            OpenInternalWorkspace();
            ShowInfo(IsEnglish
                ? $"The temporary drive could not be mounted, so the in-app fallback browser was opened.\n\nReason: {mountFailure?.Message}"
                : $"临时磁盘没有成功挂载，因此已经打开软件内备用查看。\n\n原因：{mountFailure?.Message}",
                MessageBoxImage.Warning);
        }
    }

    private void OpenMountedDrive(string mountPoint)
    {
        try
        {
            var root = mountPoint.TrimEnd('\\') + "\\";
            Process.Start(new ProcessStartInfo("explorer.exe", root) { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            ShowInfo(IsEnglish
                ? $"The temporary drive is mounted at {mountPoint}, but File Explorer could not be opened automatically.\n\n{exception.Message}"
                : $"临时磁盘已经挂载到 {mountPoint}，但资源管理器没有自动打开。你可以从“此电脑”进入该盘符。\n\n{exception.Message}",
                MessageBoxImage.Information);
        }
    }

    private void InternalBrowse_Click(object sender, RoutedEventArgs e) => OpenInternalWorkspace();

    private void OpenInternalWorkspace()
    {
        if (_vaultSession is null || _vaultDrive is not null) return;
        if (_workspaceWindow is { IsVisible: true })
        {
            _workspaceWindow.Activate();
            return;
        }
        var window = new VaultWorkspaceWindow(_vaultService, _vaultSession) { Owner = this };
        window.Closed += (_, _) =>
        {
            if (ReferenceEquals(_workspaceWindow, window)) _workspaceWindow = null;
        };
        _workspaceWindow = window;
        window.Show();
    }

    private void Append_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        if (AppendButton.ContextMenu is { } menu)
        {
            menu.PlacementTarget = AppendButton;
            menu.IsOpen = true;
        }
    }

    private async void History_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        var items = _vaultSession.History;
        var list = new ListBox { ItemsSource = items, DisplayMemberPath = nameof(VaultHistoryEntry.RelativePath), MinWidth = 520, MinHeight = 260, Margin = new Thickness(12) };
        var daysInput = new TextBox { Text = _vaultSession.HistoryRetentionDays.ToString(), Width = 70, Margin = new Thickness(4, 0, 12, 0) };
        var maxInput = new TextBox { Text = _vaultSession.HistoryMaximumBytes == 0 ? "0" : _vaultSession.HistoryMaximumBytes.ToString(), Width = 120, Margin = new Thickness(4, 0, 4, 0) };
        var settings = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(12, 12, 12, 0) };
        settings.Children.Add(new TextBlock { Text = IsEnglish ? "Keep days:" : "保留天数：", VerticalAlignment = VerticalAlignment.Center }); settings.Children.Add(daysInput);
        settings.Children.Add(new TextBlock { Text = IsEnglish ? "Max bytes (0 = unlimited):" : "最大字节数（0 表示不限）：", VerticalAlignment = VerticalAlignment.Center }); settings.Children.Add(maxInput);
        var restore = new Button { Content = IsEnglish ? "Restore" : "恢复所选", Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(12, 0, 0, 12), IsEnabled = false };
        var delete = new Button { Content = IsEnglish ? "Permanently delete" : "永久清除", Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(8, 0, 12, 12), IsEnabled = false };
        list.SelectionChanged += (_, _) => { restore.IsEnabled = delete.IsEnabled = list.SelectedItem is VaultHistoryEntry; };
        var panel = new StackPanel(); panel.Children.Add(settings); panel.Children.Add(list); var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right }; buttons.Children.Add(restore); buttons.Children.Add(delete); panel.Children.Add(buttons);
        var dialog = new Window { Owner = this, Title = IsEnglish ? "Vault history" : "历史版本", Content = panel, Width = 600, Height = 380, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = (System.Windows.Media.Brush)FindResource("PageBrush") };
        void SaveSettings()
        {
            if (int.TryParse(daysInput.Text, out var days) && days > 0) _vaultSession.HistoryRetentionDays = days;
            if (long.TryParse(maxInput.Text, out var max) && max >= 0) _vaultSession.HistoryMaximumBytes = max;
        }
        restore.Click += async (_, _) =>
        {
            SaveSettings();
            if (list.SelectedItem is not VaultHistoryEntry selected) return;
            var target = selected.RelativePath; var overwrite = false;
            if (_vaultSession.TryGetEntry(target, out var existing) && existing is not null)
            {
                var compare = $"历史版本：{selected.Length:N0} 字节，时间：{selected.LastWriteTimeUtc.ToLocalTime():g}\n当前文件：{existing.Length:N0} 字节，时间：{existing.LastWriteTimeUtc.ToLocalTime():g}\n\n是否覆盖当前文件？选择“否”将另存为副本。";
                var result = MessageBox.Show(this, compare, IsEnglish ? "Compare versions" : "比较历史版本", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
                if (result == MessageBoxResult.Cancel) return;
                if (result == MessageBoxResult.No) target = Path.Combine(Path.GetDirectoryName(target) ?? "", Path.GetFileNameWithoutExtension(target) + " (恢复副本)" + Path.GetExtension(target)).Replace('\\', '/'); else overwrite = true;
            }
            try { await _vaultSession.RestoreHistoryAsync(selected.Id, target, overwrite); dialog.Close(); ShowInfo(IsEnglish ? "The historical version was restored." : "历史版本已经恢复。", MessageBoxImage.Information); }
            catch (Exception exception) { ShowError(IsEnglish ? "Could not restore the version" : "无法恢复历史版本", exception); }
        };
        delete.Click += (_, _) => { SaveSettings(); if (list.SelectedItem is VaultHistoryEntry selected && MessageBox.Show(this, IsEnglish ? "Permanently delete this historical version?" : "永久清除这个历史版本？", IsEnglish ? "Confirm" : "确认", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes) { _vaultSession.DeleteHistory(selected.Id); list.ItemsSource = _vaultSession.History; } };
        dialog.ShowDialog();
    }

    private async void AppendFiles_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        var dialog = new AppendFilePickerDialog(null) { Owner = this };
        if (dialog.ShowDialog() == true) await AppendSourcesAsync(dialog.SelectedFiles);
    }

    private async void AppendFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        var dialog = new OpenFolderDialog { Title = IsEnglish ? "Choose a folder to add" : "选择要追加的文件夹" };
        if (dialog.ShowDialog(this) == true) await AppendSourcesAsync([dialog.FolderName]);
    }

    private async Task AppendSourcesAsync(IReadOnlyList<string> paths)
    {
        if (_vaultSession is null || paths.Count == 0) return;
        try
        {
            SetBusy(true);
            _operationCancellation = new CancellationTokenSource();
            CancelOperationButton.IsEnabled = true;
            ProgressPanel.Visibility = Visibility.Visible;
            var progress = CreateVaultProgressReporter();
            var result = await _vaultService.AddSourcesAsync(
                _vaultSession, paths, progress, _operationCancellation.Token);
            StatusText.Text = IsEnglish ? $"Added {result.AddedEntries:N0} entries." : $"已追加 {result.AddedEntries:N0} 项内容。";
        }
        catch (OperationCanceledException) { if (_vaultSession is not null) StatusText.Text = IsEnglish ? "Adding files was cancelled; original files were not changed." : "追加已取消，原始资料没有改变。"; }
        catch (Exception exception) { if (_vaultSession is not null) ShowError(IsEnglish ? "Could not add sources" : "无法追加资料", exception); }
        finally { _operationCancellation?.Dispose(); _operationCancellation = null; ProgressPanel.Visibility = Visibility.Collapsed; SetBusy(false); }
    }

    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        var dialog = new OpenFileDialog { Title = IsEnglish ? "Choose an .nrenc archive" : "选择要导入的 .nrenc 文件", Filter = "NingRan archives|*.nrenc|All files|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            await _archiveService.InspectAsync(dialog.FileName);
        }
        catch (Exception exception)
        {
            ShowError(IsEnglish ? "Could not read the archive" : "无法读取加密包", exception);
            return;
        }
        var passwordDialog = new PasswordPromptWindow(IsEnglish ? "Archive password" : "加密包密码") { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            passwordDialog.Password.Dispose();
            return;
        }
        try
        {
            SetBusy(true);
            _operationCancellation = new CancellationTokenSource();
            CancelOperationButton.IsEnabled = true;
            ProgressPanel.Visibility = Visibility.Visible;
            using var request = new DecryptRequest(
                dialog.FileName,
                string.Empty,
                passwordDialog.Password,
                passwordDialog.KeyFilePath,
                null,
                new System.Windows.Interop.WindowInteropHelper(this).Handle,
                passwordDialog.SelectedMode);
            using var archive = await _archiveService.OpenForBrowsingAsync(request);
            var result = await _vaultService.ImportArchiveAsync(
                _vaultSession, archive, progress: CreateVaultProgressReporter(), cancellationToken: _operationCancellation.Token);
            StatusText.Text = IsEnglish ? $"Imported {result.AddedEntries:N0} entries." : $"已导入 {result.AddedEntries:N0} 项内容。";
        }
        catch (OperationCanceledException) { if (_vaultSession is not null) StatusText.Text = IsEnglish ? "Import was cancelled; the incomplete addition was removed." : "导入已取消，未完成的追加内容已经清理。"; }
        catch (Exception exception) { if (_vaultSession is not null) ShowError(IsEnglish ? "Could not import archive" : "无法导入加密包", exception); }
        finally { _operationCancellation?.Dispose(); _operationCancellation = null; ProgressPanel.Visibility = Visibility.Collapsed; SetBusy(false); }
    }

    private async void Verify_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        try
        {
            SetBusy(true);
            _operationCancellation = new CancellationTokenSource();
            CancelOperationButton.IsEnabled = true;
            ProgressPanel.Visibility = Visibility.Visible;
            await _vaultSession.VerifyAsync(CreateVaultProgressReporter(), _operationCancellation.Token);
            StatusText.Text = IsEnglish ? "Full integrity check passed." : "保险箱完整检查已经通过。";
        }
        catch (OperationCanceledException) { if (_vaultSession is not null) StatusText.Text = IsEnglish ? "Full check was cancelled; the vault was not changed." : "完整检查已取消，保险箱没有改变。"; }
        catch (Exception exception) { if (_vaultSession is not null) ShowError(IsEnglish ? "Full check failed" : "完整检查失败", exception); }
        finally { _operationCancellation?.Dispose(); _operationCancellation = null; ProgressPanel.Visibility = Visibility.Collapsed; SetBusy(false); }
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        IReadOnlyList<IdentitySummary> identities;
        try { identities = new NrIdentityService().ListLocalIdentities(); }
        catch (Exception exception)
        {
            ShowError(IsEnglish ? "Could not read sender identities" : "无法读取发送者身份", exception);
            return;
        }
        if (identities.Count == 0)
        {
            ShowInfo(IsEnglish
                ? "Create a sender identity in the main window before exporting."
                : "请先回到主窗口创建发送者身份，然后再导出。", MessageBoxImage.Information);
            return;
        }
        var settings = new VaultExportWindow(identities) { Owner = this };
        if (settings.ShowDialog() != true)
        {
            settings.ArchivePassword.Dispose();
            settings.IdentityPassword.Dispose();
            return;
        }
        var save = new SaveFileDialog
        {
            Title = IsEnglish ? "Save the exported archive" : "保存导出的加密包",
            Filter = "NingRan archives|*.nrenc",
            AddExtension = true,
            DefaultExt = ".nrenc",
            FileName = _vaultSession.Name + ".nrenc",
        };
        if (save.ShowDialog(this) != true)
        {
            settings.ArchivePassword.Dispose();
            settings.IdentityPassword.Dispose();
            return;
        }
        try
        {
            PauseIdleLockForVaultExport();
            SetBusy(true);
            _operationCancellation = new CancellationTokenSource();
            CancelOperationButton.IsEnabled = true;
            ProgressPanel.Visibility = Visibility.Visible;
            OperationProgress.Value = 0;
            ProgressStageText.Text = IsEnglish ? "Preparing vault export…" : "正在准备导出保险箱…";
            ProgressPercentText.Text = "0%";
            using var request = new EncryptRequest(
                _vaultSession, save.FileName, settings.ArchivePassword, EncryptionMode.Standard,
                SizePadding: SizePaddingMode.None,
                Compression: ArchiveCompressionLevel.Standard,
                SigningIdentityId: settings.SelectedIdentity!.Id,
                SigningIdentityPassword: settings.IdentityPassword,
                OwnerWindowHandle: new System.Windows.Interop.WindowInteropHelper(this).Handle);
            var progress = CreateVaultProgressReporter();
            await _archiveService.EncryptAsync(request, progress, _operationCancellation.Token);
            if (_vaultSession is not null) StatusText.Text = IsEnglish ? "Vault export completed." : "保险箱已经成功导出为 .nrenc。";
        }
        catch (OperationCanceledException) { if (_vaultSession is not null) StatusText.Text = IsEnglish ? "Export was cancelled." : "保险箱导出已取消。"; }
        catch (Exception exception) { if (_vaultSession is not null) ShowError(IsEnglish ? "Could not export the vault" : "无法导出保险箱", exception); }
        finally
        {
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            ProgressPanel.Visibility = Visibility.Collapsed;
            SetBusy(false);
            ResumeIdleLockAfterVaultExport();
        }
    }

    private void Lock_Click(object sender, RoutedEventArgs e) => RequestImmediateLock();

    private void RequestImmediateLock()
    {
        _operationCancellation?.Cancel();
        LockVault();
    }

    private void LockVault()
    {
        _idleTimer.Stop();
        _workspaceWindow?.CloseForLock();
        _workspaceWindow = null;
        _vaultDrive?.Dispose(); _vaultDrive = null;
        _vaultSession?.Dispose(); _vaultSession = null;
        UnlockedActionsPanel.Visibility = Visibility.Collapsed;
        InternalBrowseButton.Visibility = Visibility.Collapsed;
        ExportButton.Visibility = Visibility.Visible;
        LockButton.Content = IsEnglish ? "Lock and remove drive" : "锁定并卸载磁盘";
        HistoryDaysInput.IsEnabled = HistoryBytesInput.IsEnabled = SaveHistorySettingsButton.IsEnabled = false;
        HistorySettingsPanel.Visibility = Visibility.Collapsed;
        SidebarStatusText.Text = IsEnglish ? "Not unlocked" : "尚未解锁";
        SidebarDriveText.Text = string.Empty;
        SidebarSpaceText.Text = string.Empty;
        CreateSetupPanel.Visibility = _windowMode == VaultWindowMode.Create ? Visibility.Visible : Visibility.Collapsed;
        OpenSetupPanel.Visibility = _windowMode == VaultWindowMode.Open ? Visibility.Visible : Visibility.Collapsed;
        ActionsTitle.Text = IsEnglish
            ? (_windowMode == VaultWindowMode.Create ? "Finish creation" : "Open vault")
            : (_windowMode == VaultWindowMode.Create ? "完成创建" : "打开保险箱");
        CreateButton.IsEnabled = _windowMode == VaultWindowMode.Create;
        OpenButton.IsEnabled = _windowMode == VaultWindowMode.Open;
        UpgradeButton.IsEnabled = _windowMode == VaultWindowMode.Open;
        DriveText.Text = string.Empty;
        if (StatusText is not null) StatusText.Text = IsEnglish ? "Vault is locked." : "保险箱已锁定。";
    }

    private async Task WatchPhysicalDeviceAsync(VaultSession session)
    {
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, session.CancellationToken);
        }
        catch (OperationCanceledException)
        {
            if (_closing || !ReferenceEquals(_vaultSession, session)) return;
            await Dispatcher.InvokeAsync(() =>
            {
                if (_closing || !ReferenceEquals(_vaultSession, session)) return;
                LockVault();
                ShowInfo(IsEnglish
                    ? "The authorized physical device was removed. The vault has been locked."
                    : "授权物理设备已被拔出，保险箱已经自动锁定。", MessageBoxImage.Warning);
            });
        }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_busy) { e.Cancel = true; return; }
        _closing = true;
        SystemEvents.SessionSwitch -= SystemEvents_SessionSwitch;
        SystemEvents.PowerModeChanged -= SystemEvents_PowerModeChanged;
        _idleTimer.Stop();
        LockVault();
    }

    private void IdleTimer_Tick(object? sender, EventArgs e)
        => EnforceIdleLockIfNeeded();

    private void PauseIdleLockForVaultExport()
    {
        _vaultArchiveExportInProgress = true;
        _idleTimer.Stop();
    }

    private void ResumeIdleLockAfterVaultExport()
    {
        _vaultArchiveExportInProgress = false;
        if (_vaultSession is null) return;

        EnforceIdleLockIfNeeded();
        if (_vaultSession is not null) _idleTimer.Start();
    }

    private void EnforceIdleLockIfNeeded()
    {
        if (_vaultSession is null || _vaultArchiveExportInProgress) return;
        try
        {
            if (!GetLastInputInfo(out var info))
            {
                RequestImmediateLock();
                ShowInfo(IsEnglish
                    ? "Windows activity could not be checked, so the vault was locked for safety."
                    : "无法确认电脑活动状态，保险箱已为安全自动锁定。", MessageBoxImage.Warning);
                return;
            }

            if (ShouldLockForIdle((uint)Environment.TickCount, info.dwTime, _vaultArchiveExportInProgress))
            {
                RequestImmediateLock();
                ShowInfo(IsEnglish ? "The vault was locked after 15 minutes without activity." : "保险箱因连续 15 分钟没有操作，已经自动锁定。", MessageBoxImage.Information);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            RequestImmediateLock();
            OperationLog.Append("VaultWindow.IdleTimer", null, "failed-and-locked", ex.ToString());
            ShowInfo(IsEnglish
                ? "Windows activity monitoring is unavailable, so the vault was locked for safety."
                : "Windows 活动监测不可用，保险箱已为安全自动锁定。", MessageBoxImage.Warning);
        }
    }

    internal static bool ShouldLockForIdle(uint currentTick, uint lastInputTick, bool vaultArchiveExportInProgress)
        => !vaultArchiveExportInProgress &&
           unchecked(currentTick - lastInputTick) >= LockAfterIdleMilliseconds;

    private void SystemEvents_SessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is not (SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff)) return;
        Dispatcher.BeginInvoke(new Action(() =>
        {
            if (_vaultSession is null) return;
            RequestImmediateLock();
            ShowInfo(IsEnglish ? "The vault was locked because Windows was locked or signed out." : "Windows 已锁屏或注销，保险箱已经自动锁定。", MessageBoxImage.Information);
        }));
    }

    private void SystemEvents_PowerModeChanged(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode != PowerModes.Suspend) return;
        Dispatcher.BeginInvoke(new Action(() =>
        {
            if (_vaultSession is null) return;
            RequestImmediateLock();
            ShowInfo(IsEnglish ? "The vault was locked before the computer went to sleep." : "电脑进入休眠前，保险箱已经自动锁定。", MessageBoxImage.Information);
        }));
    }

    private void NavigateLocation_Click(object sender, RoutedEventArgs e) => ShowPage(LocationPage, LocationNavButton);
    private void NavigateProtection_Click(object sender, RoutedEventArgs e) => ShowPage(ProtectionPage, ProtectionNavButton);
    private void NavigateActions_Click(object sender, RoutedEventArgs e) => ShowPage(ActionsPage, ActionsNavButton);

    private void ShowPage(UIElement page, Button selectedButton)
    {
        LocationPage.Visibility = page == LocationPage ? Visibility.Visible : Visibility.Collapsed;
        ProtectionPage.Visibility = page == ProtectionPage ? Visibility.Visible : Visibility.Collapsed;
        ActionsPage.Visibility = page == ActionsPage ? Visibility.Visible : Visibility.Collapsed;
        LocationNavButton.FontWeight = ProtectionNavButton.FontWeight = ActionsNavButton.FontWeight = FontWeights.Normal;
        selectedButton.FontWeight = FontWeights.SemiBold;
        MainScrollViewer.ScrollToTop();
    }

    private void SaveHistorySettings_Click(object sender, RoutedEventArgs e)
    {
        if (_vaultSession is null || _busy) return;
        if (!int.TryParse(HistoryDaysInput.Text, out var days) || days < 1 || days > 3650)
        {
            ShowInfo(IsEnglish ? "Retention days must be between 1 and 3650." : "保留天数必须在 1 到 3650 之间。", MessageBoxImage.Warning); return;
        }
        if (!long.TryParse(HistoryBytesInput.Text, out var maximumBytes) || maximumBytes < 0)
        {
            ShowInfo(IsEnglish ? "The space limit must be zero or a positive number." : "空间上限必须为 0 或正数。", MessageBoxImage.Warning); return;
        }
        _vaultSession.HistoryRetentionDays = days;
        _vaultSession.HistoryMaximumBytes = maximumBytes;
        HistoryDaysInput.Text = _vaultSession.HistoryRetentionDays.ToString();
        HistoryBytesInput.Text = _vaultSession.HistoryMaximumBytes.ToString();
        ShowInfo(IsEnglish ? "Settings saved for this vault." : "当前保险箱的设置已保存。", MessageBoxImage.Information);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    [DllImport("user32.dll", EntryPoint = "GetLastInputInfo", ExactSpelling = true)]
    private static extern bool GetLastInputInfoNative(ref LASTINPUTINFO plii);
    private static bool GetLastInputInfo(out LASTINPUTINFO info)
    {
        info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        return GetLastInputInfoNative(ref info);
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        CreateButton.IsEnabled = _windowMode == VaultWindowMode.Create && !busy && _vaultSession is null;
        OpenButton.IsEnabled = _windowMode == VaultWindowMode.Open && !busy && _vaultSession is null;
        UpgradeButton.IsEnabled = _windowMode == VaultWindowMode.Open && !busy && _vaultSession is null;
        CancelOperationButton.IsEnabled = busy && _operationCancellation is not null;
        AppendButton.IsEnabled = !busy; ImportButton.IsEnabled = !busy; ExportButton.IsEnabled = !busy; VerifyButton.IsEnabled = !busy;
        LockButton.IsEnabled = _vaultSession is not null;
    }

    private SensitivePassword ReadPassword(PasswordBox box) => SensitivePassword.FromSecureString(box.SecurePassword);

    private void ShowInfo(string message, MessageBoxImage image) => System.Windows.MessageBox.Show(this, UiLanguage.Translate(message), UiLanguage.Translate("凝然保险箱"), MessageBoxButton.OK, image);

    private void ShowError(string title, Exception exception) => System.Windows.MessageBox.Show(this, UiLanguage.Translate($"{title}：\n\n{exception.Message}"), UiLanguage.Translate("凝然保险箱"), MessageBoxButton.OK, MessageBoxImage.Warning);

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(bytes, 0); var index = 0;
        while (value >= 1024 && index < units.Length - 1) { value /= 1024; index++; }
        return $"{value:0.##} {units[index]}";
    }

    private string FormatProgressText(CryptoProgress value)
    {
        var text = UiLanguage.Translate(value.Message);
        if (value.BytesPerSecond is > 0)
            text += IsEnglish ? $" · {FormatBytes((long)value.BytesPerSecond.Value)}/s" : $" · 速度 {FormatBytes((long)value.BytesPerSecond.Value)}/秒";
        if (value.EstimatedRemaining is { } remaining && remaining > TimeSpan.Zero)
        {
            var rounded = TimeSpan.FromSeconds(Math.Ceiling(remaining.TotalSeconds));
            text += IsEnglish
                ? $" · about {rounded:hh\\:mm\\:ss} remaining"
                : $" · 预计剩余 {rounded:hh\\:mm\\:ss}";
        }
        return text;
    }

    private IProgress<CryptoProgress> CreateVaultProgressReporter() => new Progress<CryptoProgress>(value =>
    {
        if (_vaultSession is null) return;
        var text = FormatProgressText(value);
        StatusText.Text = text;
        ProgressStageText.Text = text;
        OperationProgress.Value = value.Fraction * 100;
        ProgressPercentText.Text = $"{value.Fraction * 100:0}%";
    });
}
