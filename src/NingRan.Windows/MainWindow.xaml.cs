using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

public partial class MainWindow : Window
{
    private const string AppName = "凝然加密";
    private const double PreferredWindowWidth = 1420;
    private const double PreferredWindowHeight = 920;
    private const double WorkAreaGap = 40;
    private readonly NrKeyFileService _keyFileService = new();
    private readonly NrIdentityService _identityService = new();
    private readonly NrTrustedContactService _trustedContactService;
    private readonly NrPhysicalDeviceService _physicalDeviceService = new();
    private readonly NrArchiveService _archiveService;
    private readonly Effect? _normalWindowEffect;
    private CancellationTokenSource? _operationCancellation;
    private ProgressWindow? _progressWindow;
    private EncryptionMode _detectedArchiveMode = EncryptionMode.Standard;
    private ArchiveInfo _detectedArchiveInfo = new(EncryptionMode.Standard, false);
    private string? _sourcePath;
    private bool _isBusy;
    private bool _closeAfterCancellation;
    private bool _physicalOperationActive;
    private HwndSource? _windowSource;
    private SecureArchiveSession? _archiveSession;
    private readonly StrictProtectionCoordinator _strictProtection = new();
    private StrictProtectionSettings _strictProtectionSettings = new();
    private bool _strictThreatHandled;
    private bool _strictStartupAttempted;
    private bool _closingAnimationActive;
    private bool _closingAnimationComplete;
    private readonly bool _allowElevatedMediaBrowsing;

    public MainWindow(bool allowElevatedMediaBrowsing = false)
    {
        InitializeComponent();
        _allowElevatedMediaBrowsing = allowElevatedMediaBrowsing;
        _strictProtectionSettings = StrictProtectionSettings.Load();
        _strictProtection.AlertRaised += StrictProtection_AlertRaised;
        _trustedContactService = new NrTrustedContactService(_identityService);
        _archiveService = new NrArchiveService(
            keyFileService: _keyFileService,
            identityService: _identityService,
            trustedContactService: _trustedContactService,
            physicalDeviceProvider: _physicalDeviceService);
        _normalWindowEffect = WindowFrame.Effect;
        RefreshIdentityList();
        MigrateTrustedContactStorage();
        RefreshPhysicalDeviceList();
        SourceInitialized += MainWindow_SourceInitialized;
        ContentRendered += MainWindow_ContentRendered;
        Loaded += MainWindow_Loaded;
        RefreshSettingsRegion();
        RefreshStrictProtectionButton();
    }

    private bool IsEncrypting => EncryptRadio.IsChecked == true;

    private EncryptionMode CurrentMode => IsEncrypting
        ? (PhysicalRadio.IsChecked == true
            ? EncryptionMode.PhysicalDevice
            : AdvancedRadio.IsChecked == true ? EncryptionMode.Advanced : EncryptionMode.Standard)
        : _detectedArchiveMode;

    private IReadOnlyList<PhysicalDeviceDescriptor> SelectedPhysicalDevices =>
        EncryptPhysicalDeviceList.SelectedItems.Cast<PhysicalDeviceDescriptor>().ToArray();

    private string? CurrentKeyFilePath => IsEncrypting
        ? (CurrentMode == EncryptionMode.Advanced ? EncryptKeyFilePathInput.Text : null)
        : DecryptKeyFilePathInput.Text;

    private SizePaddingMode CurrentSizePadding => SizePaddingCombo.SelectedIndex switch
    {
        1 => SizePaddingMode.Rounded,
        2 => SizePaddingMode.Fixed100MiB,
        3 => SizePaddingMode.Fixed1GiB,
        4 => SizePaddingMode.Fixed10GiB,
        _ => SizePaddingMode.None,
    };

    private IdentitySummary? SelectedSigningIdentity =>
        SigningIdentityCombo.SelectedItem as IdentitySummary;

    private async void PickFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择需要加密或解密的文件",
            Filter = "所有文件|*.*|凝然加密文件|*.nrenc",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true)
        {
            await SetSourceAsync(dialog.FileName);
        }
    }

    private async void PickFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择需要加密的文件夹",
            Multiselect = false,
        };
        if (dialog.ShowDialog(this) == true)
        {
            await SetSourceAsync(dialog.FolderName);
        }
    }

    private void PickDestination_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择保存位置",
            Multiselect = false,
            InitialDirectory = Directory.Exists(DestinationInput.Text) ? DestinationInput.Text : null,
        };
        if (dialog.ShowDialog(this) == true)
        {
            DestinationInput.Text = dialog.FolderName;
        }
    }

    private void PickEncryptKeyFile_Click(object sender, RoutedEventArgs e) =>
        PickKeyFile(EncryptKeyFilePathInput);

    private void PickDecryptKeyFile_Click(object sender, RoutedEventArgs e) =>
        PickKeyFile(DecryptKeyFilePathInput);

    private async void PickSenderPublicIdentity_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择发送者提供的公开身份文件",
            Filter = "凝然公开身份|*.nrpub|所有文件|*.*",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var info = _identityService.ReadPublicIdentityInfo(dialog.FileName);
            var trustedContact = _trustedContactService.FindTrustedContactForPublicIdentity(dialog.FileName);
            if (trustedContact is null)
            {
                if (!ConfirmPublicIdentityTrust(info))
                {
                    ClearTrustedSenderSelection();
                    return;
                }

                SetBusy(true);
                trustedContact = await _trustedContactService.TrustPublicIdentityAsync(
                    dialog.FileName,
                    userExplicitlyConfirmed: true);
                SetBusy(false);
            }

            SenderPublicIdentityPathInput.Text = trustedContact.DisplayText;
            SenderIdentityStatusText.Text =
                $"已信任联系人：{trustedContact.Name}\n解密时仍会自动核验文件签名。";
            SenderIdentityStatusText.Foreground = (Brush)FindResource("PrimaryBrush");
        }
        catch (Exception exception)
        {
            SetBusy(false);
            ClearTrustedSenderSelection();
            ShowFriendlyError("无法读取公开身份", exception);
        }
    }

    private bool ConfirmPublicIdentityTrust(PublicIdentityInfo info)
    {
        var dialog = new PublicIdentityVerificationDialog(info.Name, info.VerificationCode)
        {
            Owner = this,
        };
        return dialog.ShowDialog() == true;
    }

    private void ManageTrustedContacts_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new TrustedContactsDialog(_trustedContactService) { Owner = this };
            dialog.ShowDialog();
            if (_detectedArchiveInfo.HasSenderSignature)
            {
                SelectTrustedContactForDetectedArchive();
            }
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法管理可信联系人", exception);
        }
    }

    private void ManagePhysicalDevices_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        try
        {
            var selectedIds = SelectedPhysicalDevices.Select(device => device.Id).ToHashSet(StringComparer.Ordinal);
            var dialog = new PhysicalDevicesDialog(_physicalDeviceService) { Owner = this };
            dialog.ShowDialog();
            RefreshPhysicalDeviceList(selectedIds);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法管理物理设备", exception);
        }
    }

    private void PickKeyFile(TextBox target)
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择密匙文件（可以是任意普通文件）",
            Filter = "所有文件|*.*|凝然专用密匙|*.nrkey",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true)
        {
            target.Text = dialog.FileName;
            MessageBox.Show(
                this,
                "如果选择的是普通文件，程序只会读取它，绝不会修改、改名或复制。文件内容必须始终完全一致；图片被压缩、重新保存，或文档被修改后，都将不能再用于解锁。\n\n很小或很常见的普通文件较容易被别人猜到或复制，推荐使用程序生成的 .nrkey 专用密匙。",
                "密匙安全提醒",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private async void CreateKey_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        using var password = ReadPassword(EncryptPasswordInput);
        using var confirmationPassword = ReadPassword(ConfirmPasswordInput);
        try
        {
            PasswordRules.ValidateForCreation(password);
            if (!password.FixedTimeEquals(confirmationPassword))
            {
                MessageBox.Show(this, "两次输入的密码不一致。", AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!ConfirmWeakPassword(password, "密钥文件密码"))
            {
                return;
            }

            var saveDialog = new SaveFileDialog
            {
                Title = "选择新版密钥文件的保存位置",
                Filter = "凝然 5.2 密钥文件|*.nrkey",
                DefaultExt = ".nrkey",
                AddExtension = true,
                FileName = $"凝然密钥-{DateTime.Now:yyyyMMdd-HHmmss}.nrkey",
                OverwritePrompt = false,
            };
            if (saveDialog.ShowDialog(this) != true)
            {
                return;
            }

            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            await _keyFileService.CreateAsync(saveDialog.FileName, password);
            var path = saveDialog.FileName;
            EncryptKeyFilePathInput.Text = path;
            MessageBox.Show(
                this,
                $"新版密钥文件已经生成：\n\n{path}\n\n请把它和加密文件分开保存。该文件使用当前加密密码保护。",
                AppName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法生成密钥文件", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
            ClearPasswords();
        }
    }

    private async void CreateIdentity_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        var dialog = new IdentityDialog(isCreating: true) { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var identityName = dialog.IdentityName;
        using var identityPassword = dialog.TakeIdentityPassword();

        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            var result = await _identityService.CreateAsync(identityName, identityPassword);
            RefreshIdentityList(result.Identity.Id);
            MessageBox.Show(
                this,
                "发送者身份已经创建并加密保存在程序中。\n\n需要备份时，请主动点击“导出私密备份”；需要分享身份时，请点击“导出公开身份”。",
                AppName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法创建发送者身份", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private async void ImportIdentity_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        var fileDialog = new OpenFileDialog
        {
            Title = "选择凝然身份备份",
            Filter = "凝然身份备份|*.nrid|所有文件|*.*",
            CheckFileExists = true,
        };
        if (fileDialog.ShowDialog(this) != true)
        {
            return;
        }

        await ImportIdentityFileAsync(fileDialog.FileName);
    }

    public async Task OpenAssociatedFileAsync(string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            var extension = Path.GetExtension(fullPath);
            if (string.Equals(extension, ".nrenc", StringComparison.OrdinalIgnoreCase))
            {
                await SetSourceAsync(fullPath);
            }
            else if (string.Equals(extension, ".nrid", StringComparison.OrdinalIgnoreCase))
            {
                await ImportIdentityFileAsync(fullPath);
            }
            else if (string.Equals(extension, ".nrpub", StringComparison.OrdinalIgnoreCase))
            {
                await TrustAssociatedPublicIdentityAsync(fullPath);
            }
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法打开关联文件", exception);
        }
    }

    public void HandleExternalLaunch(string? path)
    {
        var foregroundWindow = OwnedWindows.Cast<Window>()
            .LastOrDefault(window => window.IsVisible) ?? this;
        if (foregroundWindow.WindowState == WindowState.Minimized)
        {
            foregroundWindow.WindowState = WindowState.Normal;
        }

        foregroundWindow.Activate();
        foregroundWindow.Focus();
        if (path is null)
        {
            return;
        }

        if (_isBusy || !IsEnabled || foregroundWindow != this)
        {
            const string message = "凝然加密当前正在处理内容或等待您的确认。为避免打断现有操作，这次双击的文件没有打开；请完成当前操作后再双击一次。";
            if (foregroundWindow.IsEnabled)
            {
                MessageBox.Show(
                    foregroundWindow,
                    message,
                    AppName,
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(
                    message,
                    AppName,
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            return;
        }

        _ = OpenAssociatedFileAsync(path);
    }

    private async Task ImportIdentityFileAsync(string path)
    {
        if (_isBusy)
        {
            return;
        }

        var passwordDialog = new IdentityDialog(isCreating: false) { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        using var identityPassword = passwordDialog.TakeIdentityPassword();

        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            var identity = await _identityService.ImportAsync(
                path,
                identityPassword);
            RefreshIdentityList(identity.Id);
            MessageBox.Show(this, $"发送者身份“{identity.Name}”已经导入。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法导入身份备份", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private async Task TrustAssociatedPublicIdentityAsync(string path)
    {
        if (_isBusy)
        {
            return;
        }

        var info = _identityService.ReadPublicIdentityInfo(path);
        var trustedContact = _trustedContactService.FindTrustedContactForPublicIdentity(path);
        if (trustedContact is not null)
        {
            MessageBox.Show(this, $"发送者身份“{trustedContact.Name}”已经在可信联系人中。",
                AppName, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!ConfirmPublicIdentityTrust(info))
        {
            return;
        }

        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            trustedContact = await _trustedContactService.TrustPublicIdentityAsync(
                path,
                userExplicitlyConfirmed: true);
            MessageBox.Show(this, $"发送者身份“{trustedContact.Name}”已经加入可信联系人。",
                AppName, MessageBoxButton.OK, MessageBoxImage.Information);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private async void ExportPrivateIdentityBackup_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy || SelectedSigningIdentity is not { } identity)
        {
            MessageBox.Show(this, "请先选择一个发送者身份。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var saveDialog = new SaveFileDialog
        {
            Title = "导出加密的私密身份备份",
            Filter = "凝然身份备份|*.nrid",
            DefaultExt = ".nrid",
            AddExtension = true,
            FileName = $"{identity.Name}-凝然身份备份.nrid",
            OverwritePrompt = false,
        };
        if (saveDialog.ShowDialog(this) != true)
        {
            return;
        }

        var passwordDialog = new IdentityDialog(isCreating: false, isExporting: true) { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        using var identityPassword = passwordDialog.TakeIdentityPassword();
        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            await _identityService.ExportPrivateIdentityBackupAsync(
                identity.Id,
                saveDialog.FileName,
                identityPassword);
            MessageBox.Show(this,
                "加密的私密身份备份已经导出。请把备份文件和身份密码分开保管。",
                AppName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法导出私密身份备份", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private async void ExportPublicIdentity_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy || SelectedSigningIdentity is not { } identity)
        {
            MessageBox.Show(this, "请先选择一个发送者身份。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "导出可分享的公开身份",
            Filter = "凝然公开身份|*.nrpub",
            DefaultExt = ".nrpub",
            AddExtension = true,
            FileName = $"{identity.Name}-公开身份.nrpub",
            OverwritePrompt = false,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            await _identityService.ExportPublicIdentityAsync(identity.Id, dialog.FileName);
            var publicInfo = _identityService.ReadPublicIdentityInfo(dialog.FileName);
            MessageBox.Show(this,
                $"公开身份已经导出，可以发送给接收者。\n\n安全码：{publicInfo.VerificationCode}\n\n安全码严格区分大写和小写。请通过电话、当面或其他独立可信方式把它告诉接收者，不要和公开身份文件放在同一条消息中发送。",
                AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法导出公开身份", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private async void DeleteIdentity_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy || SelectedSigningIdentity is not { } identity)
        {
            MessageBox.Show(this, "请先选择要删除的发送者身份。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MessageBox.Show(
                this,
                $"准备删除程序内保存的发送者身份：\n\n名称：{identity.Name}\n\n删除后不能再用该身份制作新的加密文件。桌面或其他位置的身份备份、公开身份文件不会被删除。\n\n是否继续验证身份密码？",
                "确认删除发送者身份",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        var passwordDialog = new IdentityDialog(isCreating: false, isDeleting: true) { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        using var identityPassword = passwordDialog.TakeIdentityPassword();
        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            await _identityService.DeleteLocalIdentityAsync(identity.Id, identityPassword);
            RefreshIdentityList();
            SigningIdentityPasswordInput.Clear();
            MessageBox.Show(
                this,
                $"程序内保存的身份“{identity.Name}”已经删除。\n\n外部身份备份和公开身份文件没有被删除。",
                AppName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法删除发送者身份", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_sourcePath) || (!File.Exists(_sourcePath) && !Directory.Exists(_sourcePath)))
        {
            MessageBox.Show(this, "请先选择存在的文件或文件夹。", AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        using var operationPassword = IsEncrypting
            ? ReadPassword(EncryptPasswordInput)
            : ReadPassword(DecryptPasswordInput);
        using var confirmationPassword = IsEncrypting
            ? ReadPassword(ConfirmPasswordInput)
            : SensitivePassword.FromString(string.Empty);
        using var signingPassword = IsEncrypting && SignIdentityCheck.IsChecked == true
            ? ReadPassword(SigningIdentityPasswordInput)
            : null;
        if (operationPassword.IsEmpty)
        {
            MessageBox.Show(this, "请输入密码。", AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (IsEncrypting)
        {
            try
            {
                PasswordRules.ValidateForCreation(operationPassword);
            }
            catch (ArgumentException exception)
            {
                MessageBox.Show(this, exception.Message, AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!operationPassword.FixedTimeEquals(confirmationPassword))
            {
                MessageBox.Show(this, "两次输入的密码不一致。", AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!ConfirmWeakPassword(operationPassword, "加密密码"))
            {
                return;
            }
        }

        if (CurrentMode == EncryptionMode.Advanced &&
            (string.IsNullOrWhiteSpace(CurrentKeyFilePath) || !File.Exists(CurrentKeyFilePath)))
        {
            MessageBox.Show(this, "高级模式必须选择加密时使用的有效密钥文件。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (IsEncrypting && CurrentMode == EncryptionMode.PhysicalDevice && SelectedPhysicalDevices.Count == 0)
        {
            MessageBox.Show(this, "物理设备模式必须至少选择一个已登记设备。请先点击“管理设备”完成登记。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (IsEncrypting && SignIdentityCheck.IsChecked == true)
        {
            if (SelectedSigningIdentity is null)
            {
                MessageBox.Show(this, "请先创建或选择发送者身份。", AppName,
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (signingPassword is null || signingPassword.IsEmpty)
            {
                MessageBox.Show(this, "请输入独立的发送者身份密码。", AppName,
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        if (!IsEncrypting && !_detectedArchiveInfo.HasSenderSignature)
        {
            MessageBox.Show(
                this,
                "此文件没有发送者身份证明，无法确认来源。当前版本禁止还原未签名文件。",
                AppName,
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            return;
        }

        if (!IsEncrypting)
        {
            if (!_allowElevatedMediaBrowsing)
            {
                var choice = MessageBox.Show(
                    this,
                    "选择打开方式：\n\n“是”：普通打开，播放期间独占锁定加密文件；\n“否”：严格防护，程序会关闭并以管理员权限重新打开，然后需要再次验证密码、密匙或物理设备。\n\n严格防护只用于本次安全查看，不会把密匙传给新进程。",
                    "选择安全查看方式",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Question,
                    MessageBoxResult.Yes);
                if (choice == MessageBoxResult.Cancel)
                {
                    return;
                }

                if (choice == MessageBoxResult.No)
                {
                    if (!await EnableStrictProtectionAsync())
                    {
                        MessageBox.Show(this, $"严格防护监控没有启动，因此没有打开安全内容。\n\n原因：{GetStrictProtectionFailureReason()}\n\n请在 Windows 提示中允许监控程序，或稍后重试。",
                            AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    await OpenArchiveForBrowsingAsync(operationPassword);
                    return;
                }
            }

            await OpenArchiveForBrowsingAsync(operationPassword);
            return;
        }

        var destination = string.IsNullOrWhiteSpace(DestinationInput.Text)
            ? Path.GetDirectoryName(_sourcePath)!
            : DestinationInput.Text;
        try
        {
            Directory.CreateDirectory(destination);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法使用所选保存位置", exception);
            return;
        }

        if (IsEncrypting && CurrentSizePadding != SizePaddingMode.None)
        {
            SizePaddingEstimate estimate;
            try
            {
                SetBusy(true);
                Mouse.OverrideCursor = Cursors.Wait;
                var sourcePath = _sourcePath;
                var paddingMode = CurrentSizePadding;
                estimate = await Task.Run(() => _archiveService.EstimateSizePadding(sourcePath, paddingMode));
            }
            catch (Exception exception)
            {
                ShowFriendlyError("无法估算大小隐藏空间", exception);
                return;
            }
            finally
            {
                Mouse.OverrideCursor = null;
                SetBusy(false);
            }

            if (MessageBox.Show(
                    this,
                    $"所选内容约为 {FormatByteSize(estimate.ContentBytes)}。\n" +
                    $"大小隐藏预计额外占用约 {FormatByteSize(estimate.AdditionalPaddingBytes)}。\n\n" +
                    "是否按此设置继续？",
                    "确认额外空间",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information,
                    MessageBoxResult.No) != MessageBoxResult.Yes)
            {
                return;
            }
        }

        const string decryptConfirmation =
            "程序会先完整检查加密内容和发送者身份，此阶段不会创建任何还原文件；全部通过后才会再次读取并还原到所选位置。同名内容会自动改名保留。是否继续？";
        if (!IsEncrypting && MessageBox.Show(
                this,
                decryptConfirmation,
                AppName,
                MessageBoxButton.YesNo,
                MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        _operationCancellation = new CancellationTokenSource();
        _physicalOperationActive = CurrentMode == EncryptionMode.PhysicalDevice;
        _progressWindow = new ProgressWindow(IsEncrypting) { Owner = this };
        _progressWindow.CancelRequested += ProgressWindow_CancelRequested;
        var progress = new Progress<CryptoProgress>(value => _progressWindow?.UpdateProgress(value));
        SetBusy(true);
        _progressWindow.Show();

        try
        {
            if (IsEncrypting)
            {
                var output = GetUniqueArchivePath(destination, Path.GetFileName(_sourcePath));
                EncryptionResult result;
                using (var request = new EncryptRequest(
                        _sourcePath,
                        output,
                        operationPassword,
                        CurrentMode,
                        CurrentKeyFilePath,
                        CurrentSizePadding,
                        SignIdentityCheck.IsChecked == true ? SelectedSigningIdentity?.Id : null,
                        SignIdentityCheck.IsChecked == true ? signingPassword : null,
                        CurrentMode == EncryptionMode.PhysicalDevice ? SelectedPhysicalDevices : null,
                        new WindowInteropHelper(this).Handle))
                {
                    result = await _archiveService.EncryptAsync(
                        request,
                        progress,
                        _operationCancellation.Token);
                }

                CloseProgressWindow();
                var deleteOriginal = MessageBox.Show(
                    this,
                    $"加密文件已经完成并通过验证。\n\n" +
                    $"加密成品：{result.ArchivePath}\n\n" +
                    $"准备永久删除的{(result.SourceIsDirectory ? "文件夹" : "文件")}：\n" +
                    $"名称：{result.SourceName}\n" +
                    $"完整位置：{result.SourcePath}\n\n" +
                    "警告：这不是移入回收站，删除后无法从回收站恢复。程序会再次核对加密成品和原内容，只删除刚才加密并确认的同一份内容。\n\n" +
                    "确定要永久删除吗？",
                    "确认永久删除原内容",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);
                if (deleteOriginal == MessageBoxResult.Yes)
                {
                    try
                    {
                        await _archiveService.PermanentlyDeleteVerifiedSourceAsync(
                            result,
                            _operationCancellation.Token);
                        MessageBox.Show(
                            this,
                            $"已经永久删除确认过的原{(result.SourceIsDirectory ? "文件夹" : "文件")}：\n\n" +
                            $"{result.SourceName}\n\n加密成品保存在：\n{result.ArchivePath}",
                            AppName,
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    catch (Exception exception)
                    {
                        MessageBox.Show(
                            this,
                            "加密文件已经安全保存，但永久删除没有完整完成。程序已停止继续删除；如果原内容是文件夹，其中部分已确认内容可能已经删除，请检查原位置。\n\n" +
                            exception.Message,
                            AppName,
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }
                }
                else
                {
                    MessageBox.Show(this, $"结果已保存到：\n\n{result.ArchivePath}", AppName,
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            else
            {
                DecryptionResult result;
                using (var request = new DecryptRequest(
                        _sourcePath,
                        destination,
                        operationPassword,
                        CurrentKeyFilePath,
                        TrustedSenderId: null,
                        OwnerWindowHandle: new WindowInteropHelper(this).Handle))
                {
                    result = await _archiveService.DecryptAsync(
                        request,
                        progress,
                        _operationCancellation.Token);
                }

                CloseProgressWindow();
                var senderMessage = result.VerifiedSenderName is null
                    ? "\n\n此文件没有发送者身份证明。"
                    : $"\n\n已核验的可信联系人：{result.VerifiedSenderName}";
                MessageBox.Show(this, $"内容已经还原到：\n\n{result.OutputPath}{senderMessage}", AppName,
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (OperationCanceledException)
        {
            CloseProgressWindow();
            if (!_closeAfterCancellation)
            {
                MessageBox.Show(this, "操作已取消，未完成内容已经清理，原文件没有变动。", AppName,
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception exception)
        {
            CloseProgressWindow();
            ShowFriendlyError("处理失败", exception);
        }
        finally
        {
            CloseProgressWindow();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            _physicalOperationActive = false;
            SetBusy(false);
            ClearPasswords();
            EncryptKeyFilePathInput.Clear();
            DecryptKeyFilePathInput.Clear();

            if (_closeAfterCancellation)
            {
                _closeAfterCancellation = false;
                Close();
            }
        }
    }

    private void ProgressWindow_CancelRequested(object? sender, EventArgs e)
    {
        _operationCancellation?.Cancel();
    }

    private async Task OpenArchiveForBrowsingAsync(SensitivePassword password)
    {
        if (string.IsNullOrWhiteSpace(_sourcePath))
        {
            return;
        }

        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            using var request = new DecryptRequest(
                _sourcePath,
                DestinationDirectory: string.Empty,
                password,
                CurrentKeyFilePath,
                TrustedSenderId: null,
                OwnerWindowHandle: new WindowInteropHelper(this).Handle);
            var session = await _archiveService.OpenForBrowsingAsync(
                request,
                allowElevated: _allowElevatedMediaBrowsing);
            CloseArchiveSession();
            _archiveSession = session;
            _physicalOperationActive = CurrentMode == EncryptionMode.PhysicalDevice;
            UnlockedArchiveStatusText.Text =
                $"已验证可信发送者：{session.VerifiedSenderName}\n" +
                "文件内容只会在程序内按需读取；关闭安全查看后，内存中的解锁材料会立即清除。";
            BuildUnlockedFileTree(session);
            RefreshSettingsRegion();
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法打开安全内容", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private void BuildUnlockedFileTree(SecureArchiveSession session)
    {
        UnlockedFileTree.Items.Clear();
        var items = new Dictionary<string, TreeViewItem>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in session.Entries.OrderBy(entry => entry.RelativePath.Count(character => character == '/'))
                     .ThenBy(entry => !entry.IsDirectory).ThenBy(entry => entry.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var item = new TreeViewItem
            {
                Header = entry.IsDirectory ? $"📁  {entry.Name}" : $"{GetUnlockedFileIcon(entry)}  {entry.Name}",
                Tag = entry,
            };
            items[entry.RelativePath] = item;
            var parentPath = GetArchiveParentPath(entry.RelativePath);
            if (parentPath is not null && items.TryGetValue(parentPath, out var parent))
            {
                parent.Items.Add(item);
            }
            else
            {
                UnlockedFileTree.Items.Add(item);
            }
        }

        foreach (var item in UnlockedFileTree.Items.OfType<TreeViewItem>())
        {
            item.IsExpanded = true;
        }
    }

    private async void UnlockedFileTree_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (_isBusy || _archiveSession is null || UnlockedFileTree.SelectedItem is not TreeViewItem { Tag: SecureArchiveEntry entry } ||
            entry.IsDirectory)
        {
            return;
        }

        if (entry.MediaKind is not null)
        {
            var parentPath = GetArchiveParentPath(entry.RelativePath) ?? string.Empty;
            var mediaEntries = _archiveSession.Entries
                .Where(candidate => !candidate.IsDirectory && candidate.MediaKind is not null &&
                                    string.Equals(GetArchiveParentPath(candidate.RelativePath) ?? string.Empty, parentPath,
                                        StringComparison.OrdinalIgnoreCase))
                .OrderBy(candidate => candidate.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
            var viewer = new SecureMediaViewerWindow(_archiveSession, mediaEntries, entry) { Owner = this };
            viewer.ShowDialog();
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "选择普通文件的导出位置",
            FileName = entry.Name,
            OverwritePrompt = false,
            AddExtension = false,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            await _archiveSession.ExportEntryAsync(entry.RelativePath, dialog.FileName);
            MessageBox.Show(this, $"已导出明文文件：\n\n{dialog.FileName}", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法导出文件", exception);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            SetBusy(false);
        }
    }

    private async void ExportAllUnlocked_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy || _archiveSession is null)
        {
            return;
        }

        var dialog = new OpenFolderDialog { Title = "选择全部明文内容的导出位置", Multiselect = false };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        if (MessageBox.Show(
                this,
                "程序会先完整验证所有加密内容，然后才会导出明文文件。是否继续？",
                "确认导出全部明文",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        _operationCancellation = new CancellationTokenSource();
        _progressWindow = new ProgressWindow(isEncrypting: false) { Owner = this };
        _progressWindow.CancelRequested += ProgressWindow_CancelRequested;
        var progress = new Progress<CryptoProgress>(value => _progressWindow?.UpdateProgress(value));
        try
        {
            SetBusy(true);
            _progressWindow.Show();
            var result = await _archiveSession.ExportAllAsync(
                dialog.FolderName,
                progress,
                _operationCancellation.Token);
            CloseProgressWindow();
            MessageBox.Show(this, $"内容已经导出到：\n\n{result.OutputPath}", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            CloseProgressWindow();
            MessageBox.Show(this, "导出已取消，未完成的临时明文已经清理。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            CloseProgressWindow();
            ShowFriendlyError("无法导出全部内容", exception);
        }
        finally
        {
            CloseProgressWindow();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            SetBusy(false);
        }
    }

    private void CloseUnlockedArchive_Click(object sender, RoutedEventArgs e) => CloseArchiveSession();

    private async void StrictProtection_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            MessageBox.Show(this, "请先等待当前操作完成，再调整严格防护设置。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new StrictProtectionDialog(_strictProtectionSettings) { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        _strictProtectionSettings = dialog.Settings;
        _strictProtectionSettings.Save();
        if (_strictProtectionSettings.Enabled)
        {
            if (!await EnableStrictProtectionAsync())
            {
                MessageBox.Show(this, $"设置已经记住，但本次未能启动监控。\n\n原因：{GetStrictProtectionFailureReason()}\n\n下次启动时会再次请求管理员确认。",
                    AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        else
        {
            await _strictProtection.StopAsync();
        }

        RefreshStrictProtectionButton();
    }

    private async void MainWindow_ContentRendered(object? sender, EventArgs e)
    {
        if (_strictStartupAttempted)
        {
            return;
        }

        _strictStartupAttempted = true;
        if (_strictProtectionSettings.Enabled && !await EnableStrictProtectionAsync())
        {
            MessageBox.Show(this, $"上次已开启严格防护，但本次监控没有启动。\n\n原因：{GetStrictProtectionFailureReason()}\n\n您可以稍后点击“严格防护”再次启动。",
                AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        RefreshStrictProtectionButton();
    }

    private async Task<bool> EnableStrictProtectionAsync()
    {
        if (_strictProtection.IsRunning)
        {
            return true;
        }

        var started = await _strictProtection.StartAsync(_strictProtectionSettings);
        if (started)
        {
            _strictThreatHandled = false;
        }
        if (started && !_strictProtectionSettings.Enabled)
        {
            _strictProtectionSettings = new StrictProtectionSettings
            {
                Enabled = true,
                AllowedProcessPaths = _strictProtectionSettings.AllowedProcessPaths,
            };
            _strictProtectionSettings.Save();
        }

        RefreshStrictProtectionButton();
        return started;
    }

    private string GetStrictProtectionFailureReason() => _strictProtection.LastFailureReason ?? "没有收到监控程序的启动确认。";

    private void StrictProtection_AlertRaised(object? sender, StrictProtectionAlert alert)
    {
        _ = Dispatcher.InvokeAsync(async () =>
        {
            if (_strictThreatHandled)
            {
                return;
            }

            _strictThreatHandled = true;
            try
            {
                SecurityEventLog.Append(alert);
            }
            catch
            {
                // 即使日志位置不可用，也必须继续停止操作和清理明文。
            }
            _progressWindow?.SetCancelling();
            _operationCancellation?.Cancel();
            CloseArchiveSession();
            await _strictProtection.StopAsync();

            TemporaryContentCleanupResult cleanup;
            try
            {
                cleanup = await Task.Run(NrArchiveService.CleanupAbandonedTemporaryContent);
            }
            catch (Exception exception)
            {
                cleanup = new TemporaryContentCleanupResult(0,
                    [new TemporaryContentCleanupFailure("临时明文清理", exception.Message)]);
            }

            var processName = string.IsNullOrWhiteSpace(alert.ProcessPath)
                ? $"进程编号 {alert.ProcessId}"
                : alert.ProcessPath;
            var cleanupResult = cleanup.Failures.Count == 0
                ? "已停止当前操作，并已执行临时明文清理。"
                : $"已停止当前操作；有 {cleanup.Failures.Count} 项临时内容将由下次启动继续清理。";
            MessageBox.Show(this,
                $"严格防护发现未允许的软件尝试读取受保护内存：\n\n访问程序：{processName}\n被访问组件：{alert.TargetComponent}\n\n{cleanupResult}\n事件已记录到安全日志。",
                "严格防护已介入", MessageBoxButton.OK, MessageBoxImage.Warning);
            RefreshStrictProtectionButton();
        });
    }

    private void RefreshStrictProtectionButton()
    {
        if (!IsInitialized || StrictProtectionButton is null)
        {
            return;
        }

        StrictProtectionButton.Content = _strictProtection.IsRunning ? "严格防护：已开启" : "严格防护";
        StrictProtectionButton.ToolTip = _strictProtection.IsRunning
            ? "严格防护监控正在运行"
            : _strictProtectionSettings.Enabled
                ? "严格防护已记住，但本次监控尚未启动"
                : "设置严格防护和允许的软件";
    }

    private void CloseArchiveSession()
    {
        var session = _archiveSession;
        _archiveSession = null;
        _physicalOperationActive = false;
        session?.Dispose();
        if (IsInitialized && UnlockedArchivePanel is not null)
        {
            UnlockedFileTree.Items.Clear();
            RefreshSettingsRegion();
        }
    }

    private static string? GetArchiveParentPath(string relativePath)
    {
        var separator = relativePath.LastIndexOf('/');
        return separator < 0 ? null : relativePath[..separator];
    }

    private static string GetUnlockedFileIcon(SecureArchiveEntry entry) => entry.MediaKind switch
    {
        SecureMediaKind.Text => "📄",
        SecureMediaKind.Image => "🖼️",
        SecureMediaKind.Audio => "🎵",
        SecureMediaKind.Video => "🎬",
        _ => "📄",
    };

    private void CloseProgressWindow()
    {
        if (_progressWindow is null)
        {
            return;
        }

        _progressWindow.CancelRequested -= ProgressWindow_CancelRequested;
        _progressWindow.CloseAfterOperation();
        _progressWindow = null;
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (_isBusy || !e.Data.GetDataPresent(DataFormats.FileDrop) ||
            e.Data.GetData(DataFormats.FileDrop) is not string[] paths || paths.Length == 0)
        {
            return;
        }

        if (paths.Length > 1)
        {
            MessageBox.Show(this, "当前每次处理一个文件或一个文件夹，请只拖入一项。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        await SetSourceAsync(paths[0]);
    }

    private void ActionChanged(object sender, RoutedEventArgs e) => RefreshSettingsRegion();

    private void ModeChanged(object sender, RoutedEventArgs e) => RefreshSettingsRegion();

    private void SigningChanged(object sender, RoutedEventArgs e) => RefreshSettingsRegion();

    private async Task SetSourceAsync(string path)
    {
        var selectedPath = Path.GetFullPath(path);
        CloseArchiveSession();
        _sourcePath = selectedPath;
        _detectedArchiveMode = EncryptionMode.Standard;
        _detectedArchiveInfo = new ArchiveInfo(EncryptionMode.Standard, false);
        DecryptPhysicalDeviceText.Text = string.Empty;
        ClearTrustedSenderSelection();
        var isEncryptedArchive = File.Exists(selectedPath) &&
            string.Equals(Path.GetExtension(selectedPath), ".nrenc", StringComparison.OrdinalIgnoreCase);
        SelectedPathText.Text = isEncryptedArchive
            ? Path.GetFileName(selectedPath)
            : selectedPath;
        DestinationInput.Text = isEncryptedArchive
            ? string.Empty
            : Path.GetDirectoryName(selectedPath) ?? string.Empty;
        BuildFileTree(selectedPath);

        if (isEncryptedArchive)
        {
            DecryptRadio.IsChecked = true;
            DetectedModeText.Text = "正在读取公开文件信息…";
            try
            {
                var info = await _archiveService.InspectAsync(selectedPath);
                if (!string.Equals(_sourcePath, selectedPath, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                _detectedArchiveMode = info.Mode;
                _detectedArchiveInfo = info;
                SelectTrustedContactForDetectedArchive();
                DecryptPhysicalDeviceText.Text =
                    "如果此文件使用物理设备保护，请插入获授权的设备。设备名称和编号会在成功解锁前保持隐藏。";
                DetectedModeText.Text =
                    $"格式版本：{info.FormatVersion}　文件大小：{FormatByteSize(info.FileSize)}\n" +
                    $"创建时间：{info.CreatedAtLocal:yyyy-MM-dd HH:mm:ss}\n" +
                    "其余信息（保护模式、发送者、原文件名和目录结构）均已隐藏，成功解锁后才会读取。";
            }
            catch (NingRanException exception)
            {
                if (string.Equals(_sourcePath, selectedPath, StringComparison.OrdinalIgnoreCase))
                {
                    DetectedModeText.Text = exception.Message;
                }
            }
        }
        else
        {
            EncryptRadio.IsChecked = true;
        }

        RefreshSettingsRegion();
    }

    private void BuildFileTree(string path)
    {
        FileTree.Items.Clear();
        try
        {
            FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
            FileTree.Items.Add(CreateTreeItem(info));
        }
        catch (Exception exception)
        {
            FileTree.Items.Add(new TreeViewItem { Header = $"无法预览：{exception.Message}" });
        }
    }

    private TreeViewItem CreateTreeItem(FileSystemInfo info)
    {
        var item = new TreeViewItem
        {
            Header = info is DirectoryInfo ? $"📁  {info.Name}" : $"📄  {info.Name}",
            Tag = info.FullName,
        };

        if (info is DirectoryInfo && (info.Attributes & FileAttributes.ReparsePoint) == 0)
        {
            item.Items.Add(new TreeViewItem { Header = "正在读取…", Tag = "placeholder" });
            item.Expanded += DirectoryItem_Expanded;
        }

        return item;
    }

    private void DirectoryItem_Expanded(object sender, RoutedEventArgs e)
    {
        if (sender is not TreeViewItem item || item.Tag is not string path ||
            item.Items.Count != 1 || item.Items[0] is not TreeViewItem placeholder ||
            !Equals(placeholder.Tag, "placeholder"))
        {
            return;
        }

        item.Items.Clear();
        try
        {
            foreach (var child in new DirectoryInfo(path).GetFileSystemInfos()
                .Where(child => (child.Attributes & FileAttributes.ReparsePoint) == 0)
                .OrderBy(child => child is FileInfo)
                .ThenBy(child => child.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                item.Items.Add(CreateTreeItem(child));
            }
        }
        catch (Exception exception)
        {
            item.Items.Add(new TreeViewItem { Header = $"无法读取：{exception.Message}" });
        }
    }

    private void RefreshSettingsRegion()
    {
        if (!IsInitialized || RunButton is null)
        {
            return;
        }

        var archiveUnlocked = _archiveSession is not null;
        EncryptSettingsPanel.Visibility = !archiveUnlocked && IsEncrypting ? Visibility.Visible : Visibility.Collapsed;
        DecryptSettingsPanel.Visibility = !archiveUnlocked && !IsEncrypting ? Visibility.Visible : Visibility.Collapsed;
        UnlockedArchivePanel.Visibility = archiveUnlocked ? Visibility.Visible : Visibility.Collapsed;
        DestinationPanel.Visibility = archiveUnlocked ? Visibility.Collapsed : Visibility.Visible;
        EncryptAdvancedKeyPanel.Visibility =
            IsEncrypting && AdvancedRadio.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        EncryptPhysicalDevicePanel.Visibility =
            IsEncrypting && PhysicalRadio.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        EncryptIdentityPanel.Visibility =
            IsEncrypting && SignIdentityCheck.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        DecryptKeyPanel.Visibility = !IsEncrypting ? Visibility.Visible : Visibility.Collapsed;
        DecryptPhysicalDevicePanel.Visibility = !IsEncrypting ? Visibility.Visible : Visibility.Collapsed;
        DecryptSenderPanel.Visibility =
            !IsEncrypting && _detectedArchiveInfo.HasSenderSignature ? Visibility.Visible : Visibility.Collapsed;
        RunButton.Content = archiveUnlocked
            ? "已在安全查看中"
            : !IsEncrypting && !_detectedArchiveInfo.HasSenderSignature
            ? "禁止还原未签名文件"
            : IsEncrypting ? "开始加密" : "打开安全内容";
        RunButton.Visibility = archiveUnlocked ? Visibility.Collapsed : Visibility.Visible;
        RunButton.IsEnabled = !archiveUnlocked && (IsEncrypting || _detectedArchiveInfo.HasSenderSignature);
    }

    private void RefreshIdentityList(string? selectIdentityId = null)
    {
        var selectedId = selectIdentityId ?? SelectedSigningIdentity?.Id;
        try
        {
            var identities = _identityService.ListLocalIdentities();
            SigningIdentityCombo.ItemsSource = identities;
            SigningIdentityCombo.SelectedItem = identities.FirstOrDefault(identity =>
                string.Equals(identity.Id, selectedId, StringComparison.OrdinalIgnoreCase));
            if (SigningIdentityCombo.SelectedItem is null && identities.Count > 0)
            {
                SigningIdentityCombo.SelectedIndex = 0;
            }
        }
        catch (Exception exception)
        {
            SigningIdentityCombo.ItemsSource = Array.Empty<IdentitySummary>();
            MessageBox.Show(this, $"无法读取本机发送者身份：\n\n{exception.Message}", AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RefreshPhysicalDeviceList(IEnumerable<string>? selectDeviceIds = null)
    {
        var selectedIds = selectDeviceIds?.ToHashSet(StringComparer.Ordinal) ?? [];
        try
        {
            var devices = _physicalDeviceService.ListRegisteredDevices();
            EncryptPhysicalDeviceList.ItemsSource = devices;
            foreach (var device in devices.Where(device => selectedIds.Contains(device.Id)))
            {
                EncryptPhysicalDeviceList.SelectedItems.Add(device);
            }
        }
        catch (Exception exception)
        {
            EncryptPhysicalDeviceList.ItemsSource = Array.Empty<PhysicalDeviceDescriptor>();
            MessageBox.Show(this, $"无法读取本机物理设备清单：\n\n{exception.Message}", AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void MigrateTrustedContactStorage()
    {
        try
        {
            _trustedContactService.ListTrustedContacts();
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"无法检查本机可信联系人：\n\n{exception.Message}", AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ClearPasswords()
    {
        EncryptPasswordInput.Clear();
        ConfirmPasswordInput.Clear();
        DecryptPasswordInput.Clear();
        SigningIdentityPasswordInput.Clear();
    }

    private static SensitivePassword ReadPassword(PasswordBox input)
    {
        using var securePassword = input.SecurePassword;
        return SensitivePassword.FromSecureString(securePassword);
    }

    private bool ConfirmWeakPassword(SensitivePassword password, string purpose)
    {
        var assessment = PasswordRules.Assess(password);
        if (!assessment.HasWarnings)
        {
            return true;
        }

        var details = string.Join("\n", assessment.Warnings.Select(warning => $"• {warning}"));
        return MessageBox.Show(
            this,
            $"{purpose}可能不够安全：\n\n{details}\n\n仍要继续使用吗？",
            "密码安全提示",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
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

    private void ClearTrustedSenderSelection()
    {
        SenderPublicIdentityPathInput.Clear();
        SenderIdentityStatusText.Text = "解密时会自动核验本机可信联系人；如尚未信任发送者，请先导入其公开身份。";
        SenderIdentityStatusText.Foreground = (Brush)FindResource("MutedBrush");
    }

    private void SelectTrustedContactForDetectedArchive()
    {
        ClearTrustedSenderSelection();
        if (!_detectedArchiveInfo.HasSenderSignature)
        {
            return;
        }
        SenderIdentityStatusText.Text =
            "解密时会自动核验本机可信联系人；如尚未信任发送者，请先导入其公开身份并输入安全码。";
        SenderIdentityStatusText.Foreground = (Brush)FindResource("PrimaryBrush");
    }

    private void MainWindow_SourceInitialized(object? sender, EventArgs e)
    {
        FitWindowToWorkArea();
        _windowSource = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
        _windowSource?.AddHook(WindowMessageHook);
    }

    private void FitWindowToWorkArea()
    {
        var workArea = SystemParameters.WorkArea;
        var availableWidth = Math.Max(MinWidth, workArea.Width - (WorkAreaGap * 2));
        var availableHeight = Math.Max(MinHeight, workArea.Height - (WorkAreaGap * 2));

        Width = Math.Min(PreferredWindowWidth, availableWidth);
        Height = Math.Min(PreferredWindowHeight, availableHeight);
        Left = workArea.Left + ((workArea.Width - Width) / 2);
        Top = workArea.Top + ((workArea.Height - Height) / 2);
    }

    private nint WindowMessageHook(nint hwnd, int message, nint wParam, nint lParam, ref bool handled)
    {
        const int WmDeviceChange = 0x0219;
        const long DeviceQueryRemove = 0x8001;
        const long DeviceRemovePending = 0x8003;
        const long DeviceRemoveComplete = 0x8004;
        var deviceEvent = wParam.ToInt64();
        if (message == WmDeviceChange &&
            deviceEvent is DeviceQueryRemove or DeviceRemovePending or DeviceRemoveComplete &&
            _physicalOperationActive && _operationCancellation is not null)
        {
            _progressWindow?.SetCancelling();
            _operationCancellation.Cancel();
        }

        return 0;
    }

    private void SetBusy(bool busy)
    {
        _isBusy = busy;
        MainContent.IsEnabled = !busy;
    }

    private static string GetUniqueArchivePath(string directory, string sourceName)
    {
        var candidate = Path.Combine(directory, sourceName + ".nrenc");
        if (!File.Exists(candidate) && !Directory.Exists(candidate))
        {
            return candidate;
        }

        for (var index = 1; ; index++)
        {
            candidate = Path.Combine(directory, $"{sourceName} ({index}).nrenc");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }
    }

    private void ShowFriendlyError(string title, Exception exception)
    {
        var message = exception is NingRanException or ArgumentException
            ? exception.Message
            : $"{exception.Message}\n\n未完成内容已经清理，原文件没有变动。";
        CrashReportDialog.ShowTemporary(this, title, message, "主窗口操作", exception);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
        {
            return;
        }

        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        if (WindowState == WindowState.Maximized)
        {
            var position = e.GetPosition(this);
            var widthRatio = position.X / Math.Max(ActualWidth, 1);
            WindowState = WindowState.Normal;
            Left = position.X - RestoreBounds.Width * widthRatio;
            Top = Math.Max(0, position.Y - 24);
        }

        DragMove();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        WindowFrame.Opacity = 0;
        await AnimateWindowFrameAsync(1, 1, 180);
    }

    private async void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        await AnimateWindowFrameAsync(0.985, 0.35, 130);
        WindowState = WindowState.Minimized;
        WindowScale.ScaleX = WindowScale.ScaleY = 1;
        WindowFrame.Opacity = 1;
    }

    private void MaximizeButton_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private async void ToggleMaximize()
    {
        await AnimateWindowFrameAsync(0.99, 0.78, 100);
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        await AnimateWindowFrameAsync(1, 1, 150);
    }

    private void Window_StateChanged(object sender, EventArgs e)
    {
        var maximized = WindowState == WindowState.Maximized;
        WindowFrame.Margin = maximized ? new Thickness(0) : new Thickness(10);
        WindowFrame.CornerRadius = maximized ? new CornerRadius(0) : new CornerRadius(20);
        WindowFrame.Effect = maximized ? null : _normalWindowEffect;
        MaximizeButton.Content = maximized ? "\uE923" : "\uE922";
        MaximizeButton.ToolTip = maximized ? "还原" : "最大化";
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_isBusy || _operationCancellation is null)
        {
            if (!_closingAnimationComplete)
            {
                e.Cancel = true;
                _ = CloseAfterAnimationAsync();
                return;
            }
            CloseArchiveSession();
            _windowSource?.RemoveHook(WindowMessageHook);
            _strictProtection.AlertRaised -= StrictProtection_AlertRaised;
            _ = _strictProtection.DisposeAsync();
            return;
        }

        e.Cancel = true;
        if (MessageBox.Show(this, "程序仍在处理文件。是否取消当前操作并退出？", AppName,
                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            _closeAfterCancellation = true;
            _progressWindow?.SetCancelling();
            _operationCancellation.Cancel();
        }
    }

    private async Task CloseAfterAnimationAsync()
    {
        if (_closingAnimationActive) return;
        _closingAnimationActive = true;
        await AnimateWindowFrameAsync(0.985, 0, 150);
        _closingAnimationComplete = true;
        Close();
    }

    private Task AnimateWindowFrameAsync(double scale, double opacity, int milliseconds)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var duration = new Duration(TimeSpan.FromMilliseconds(milliseconds));
        var opacityAnimation = new DoubleAnimation(opacity, duration) { FillBehavior = FillBehavior.HoldEnd };
        opacityAnimation.Completed += (_, _) => completion.TrySetResult();
        WindowScale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(scale, duration) { FillBehavior = FillBehavior.HoldEnd });
        WindowScale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(scale, duration) { FillBehavior = FillBehavior.HoldEnd });
        WindowFrame.BeginAnimation(OpacityProperty, opacityAnimation);
        return completion.Task;
    }
}
