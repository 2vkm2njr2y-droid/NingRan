using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Media3D;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

public partial class MainWindow : Window
{
    private static string AppName => UiLanguage.ProductName;
    private const double PreferredWindowWidth = 1420;
    private const double PreferredWindowHeight = 920;
    private const double WorkAreaGap = 40;
    private readonly NrKeyFileService _keyFileService = new();
    private readonly NrIdentityService _identityService = new();
    private readonly NrTrustedContactService _trustedContactService;
    private readonly TrustedContactBrokerClient _trustedContactBrokerClient;
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
    private readonly HashSet<MediaPlaybackHost> _activeExternalMediaViewers = [];
    private MediaViewerFailurePreferences _mediaViewerFailurePreferences = new();

    public MainWindow(bool allowElevatedMediaBrowsing = false)
    {
        InitializeComponent();
        _allowElevatedMediaBrowsing = allowElevatedMediaBrowsing;
        _strictProtectionSettings = StrictProtectionSettings.Load();
        _strictProtection.AlertRaised += StrictProtection_AlertRaised;
        _strictProtection.HealthFailed += StrictProtection_HealthFailed;
        _trustedContactService = new NrTrustedContactService(_identityService);
        _trustedContactBrokerClient = new TrustedContactBrokerClient(_trustedContactService);
        _archiveService = new NrArchiveService(
            keyFileService: _keyFileService,
            identityService: _identityService,
            trustedContactService: _trustedContactService,
            physicalDeviceProvider: _physicalDeviceService);
        _normalWindowEffect = WindowFrame.Effect;
        if (_allowElevatedMediaBrowsing)
        {
            Title = $"{AppName} - {(UiLanguage.IsEnglish ? "High-security view" : "高安全查看")}";
            AllowDrop = false;
            SourceDropArea.IsEnabled = false;
            SourceDropArea.Opacity = 0.55;
            PickFolderButton.Visibility = Visibility.Collapsed;
            PickFileButton.Content = UiLanguage.IsEnglish ? "Choose .nrenc encrypted file" : "选择 .nrenc 加密文件";
            EncryptRadio.IsEnabled = false;
            DecryptRadio.IsChecked = true;
            StrictProtectionButton.Visibility = Visibility.Collapsed;
            PickSenderPublicIdentityButton.Visibility = Visibility.Collapsed;
            ManageTrustedContactsButton.Visibility = Visibility.Collapsed;
            ManagePhysicalDevicesButton.Visibility = Visibility.Collapsed;
            HighSecurityStatusText.Text = WindowsSecureExecution.GetStatus().Message +
                (UiLanguage.IsEnglish
                    ? " High-security view does not receive passwords or keys from the ordinary window and limits export and editing."
                    : " 高安全查看不接收普通窗口的密码或密匙，并限制导出和修改。");
        }
        else
        {
            _mediaViewerFailurePreferences = MediaViewerFailurePreferences.Load();
            RefreshIdentityList();
            MigrateTrustedContactStorage();
        }
        if (_allowElevatedMediaBrowsing)
        {
            // 高安全管理员窗口不读取普通用户的 LocalAppData 设备清单。
            // 归档查看仍会在用户明确选择物理保护时按归档要求验证设备。
            EncryptPhysicalDeviceList.ItemsSource = Array.Empty<PhysicalDeviceDescriptor>();
        }
        else
        {
            RefreshPhysicalDeviceList();
        }
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

    private ArchiveCompressionLevel CurrentCompression => CompressionCombo.SelectedIndex switch
    {
        0 => ArchiveCompressionLevel.Store,
        1 => ArchiveCompressionLevel.Fastest,
        3 => ArchiveCompressionLevel.Maximum,
        _ => ArchiveCompressionLevel.Standard,
    };

    private IdentitySummary? SelectedSigningIdentity =>
        SigningIdentityCombo.SelectedItem as IdentitySummary;

    private IdentitySummary? SelectedArchiveSigningIdentity =>
        ArchiveSigningIdentityCombo.SelectedItem as IdentitySummary;

    private void HelpButton_Click(object sender, RoutedEventArgs e)
    {
        var helpWindow = new HelpWindow { Owner = this };
        helpWindow.Show();
    }

    private async void PickFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = _allowElevatedMediaBrowsing ? "选择需要高安全查看的凝然加密文件" : "选择需要加密或解密的文件",
            Filter = _allowElevatedMediaBrowsing ? "凝然加密文件|*.nrenc" : "所有文件|*.*|凝然加密文件|*.nrenc",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true)
        {
            await SetSourceAsync(dialog.FileName);
        }
    }

    private async void PickFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
            var trustedContact = _trustedContactService.FindTrustedContactForPublicIdentity(dialog.FileName);
            if (trustedContact is null)
            {
                SetBusy(true);
                trustedContact = await _trustedContactBrokerClient.TrustAsync(dialog.FileName);
                SetBusy(false);
                if (trustedContact is null)
                {
                    ClearTrustedSenderSelection();
                    return;
                }
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

    private void ManageTrustedContacts_Click(object sender, RoutedEventArgs e)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

        try
        {
            var dialog = new TrustedContactsDialog(_trustedContactService, _trustedContactBrokerClient) { Owner = this };
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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
            if (_allowElevatedMediaBrowsing &&
                !string.Equals(extension, ".nrenc", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("高安全查看只接受凝然加密文件，不导入或修改身份、联系人及其他设置。");
            }

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

        var trustedContact = _trustedContactService.FindTrustedContactForPublicIdentity(path);
        if (trustedContact is not null)
        {
            MessageBox.Show(this, $"发送者身份“{trustedContact.Name}”已经在可信联系人中。",
                AppName, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            SetBusy(true);
            Mouse.OverrideCursor = Cursors.Wait;
            trustedContact = await _trustedContactBrokerClient.TrustAsync(path);
            if (trustedContact is null)
            {
                return;
            }

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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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

        if (_allowElevatedMediaBrowsing &&
            (IsEncrypting || string.IsNullOrWhiteSpace(_sourcePath) || !File.Exists(_sourcePath) ||
             !string.Equals(Path.GetExtension(_sourcePath), ".nrenc", StringComparison.OrdinalIgnoreCase)))
        {
            ShowHighSecurityViewingOnlyMessage();
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
                        CurrentCompression,
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
                Header = CreateUnlockedFileHeader(entry.IsDirectory ? "📁" : GetUnlockedFileIcon(entry), entry.Name),
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

    private static FrameworkElement CreateUnlockedFileHeader(string icon, string name)
    {
        var header = new Grid { ToolTip = name };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.Children.Add(new TextBlock { Text = icon, Margin = new Thickness(0, 0, 6, 0) });
        var nameText = new TextBlock
        {
            Text = name,
            TextTrimming = TextTrimming.CharacterEllipsis,
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = name,
        };
        Grid.SetColumn(nameText, 1);
        header.Children.Add(nameText);
        return header;
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
            if (_allowElevatedMediaBrowsing && entry.MediaKind is
                    SecureMediaKind.Audio or SecureMediaKind.Video or SecureMediaKind.Pdf)
            {
                MessageBox.Show(
                    this,
                    "高安全查看不会加载浏览器或第三方播放插件，因此暂不打开音频、视频和 PDF。您仍可在高安全窗口查看文字和常见图片；如需查看此文件，请关闭高安全窗口后在普通窗口打开。",
                    "凝然加密 - 高安全查看",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }
            if (_strictProtection.IsRunning && entry.MediaKind == SecureMediaKind.Pdf)
            {
                MessageBox.Show(
                    this,
                    "严格防护运行时不会把解密内容交给无法纳入内存监控的 PDF 浏览器进程，因此暂不打开 PDF。关闭严格防护后可在普通窗口查看。",
                    "凝然加密 - 严格防护",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            var parentPath = GetArchiveParentPath(entry.RelativePath) ?? string.Empty;
            var mediaEntries = _archiveSession.Entries
                .Where(candidate => !candidate.IsDirectory && candidate.MediaKind is not null &&
                                    string.Equals(GetArchiveParentPath(candidate.RelativePath) ?? string.Empty, parentPath,
                                        StringComparison.OrdinalIgnoreCase))
                .OrderBy(candidate => candidate.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
            var externalMediaEntries = mediaEntries.Where(IsSupportedByExternalMediaViewer).ToArray();
            // 管理员高安全窗口绝不能启动外部进程。即使外部查看器路径或
            // 启动逻辑以后发生变化，这里也始终回退到当前进程内的查看器。
            if (!_allowElevatedMediaBrowsing && !_strictProtection.IsRunning &&
                IsSupportedByExternalMediaViewer(entry))
            {
                var launch = await TryOpenWithExternalMediaViewerAsync(externalMediaEntries, entry);
                if (launch.Started) return;
                ShowExternalMediaViewerFailure(launch);
            }
            if (entry.MediaKind == SecureMediaKind.Pdf)
            {
                var pdfViewer = new SecurePdfViewerWindow(_archiveSession, entry) { Owner = this };
                pdfViewer.ShowDialog();
                return;
            }
            var viewer = new SecureMediaViewerWindow(_archiveSession, mediaEntries, entry) { Owner = this };
            viewer.ShowDialog();
            return;
        }

        await ExportUnlockedEntryAsync(entry);
    }

    private void UnlockedFileTree_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        var item = FindVisualParent<TreeViewItem>(e.OriginalSource as DependencyObject);
        if (item is not null)
        {
            item.IsSelected = true;
            item.Focus();
        }
    }

    private void UnlockedFileTree_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var selectedEntry = (UnlockedFileTree.SelectedItem as TreeViewItem)?.Tag as SecureArchiveEntry;
        var canHandleEntry = selectedEntry is not null && !_allowElevatedMediaBrowsing;
        var canDeleteEntry = canHandleEntry && _archiveSession is not null &&
            !string.Equals(selectedEntry!.RelativePath, _archiveSession.RootName, StringComparison.OrdinalIgnoreCase);
        if (UnlockedFileTree.ContextMenu is null)
        {
            return;
        }

        var menuItems = UnlockedFileTree.ContextMenu.Items.OfType<MenuItem>().ToArray();
        if (menuItems.Length > 0)
        {
            menuItems[0].IsEnabled = canHandleEntry;
        }
        if (menuItems.Length > 1)
        {
            menuItems[1].IsEnabled = canDeleteEntry;
        }
    }

    private async void ExportUnlockedEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }
        if (_isBusy || _archiveSession is null ||
            UnlockedFileTree.SelectedItem is not TreeViewItem { Tag: SecureArchiveEntry entry })
        {
            return;
        }

        await ExportUnlockedEntryAsync(entry);
    }

    private async Task ExportUnlockedEntryAsync(SecureArchiveEntry entry)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }
        if (_archiveSession is null)
        {
            return;
        }

        string destinationDirectory;
        string? outputName = null;
        if (entry.IsDirectory)
        {
            var dialog = new OpenFolderDialog { Title = "选择解密文件夹副本的保存位置", Multiselect = false };
            if (dialog.ShowDialog(this) != true) return;
            destinationDirectory = dialog.FolderName;
        }
        else
        {
            var dialog = new SaveFileDialog
            {
                Title = "选择单独解密副本的保存位置",
                FileName = entry.Name,
                OverwritePrompt = false,
                AddExtension = false,
            };
            if (dialog.ShowDialog(this) != true) return;
            destinationDirectory = Path.GetDirectoryName(dialog.FileName) ?? string.Empty;
            outputName = Path.GetFileName(dialog.FileName);
        }

        _operationCancellation = new CancellationTokenSource();
        _progressWindow = new ProgressWindow(isEncrypting: false) { Owner = this };
        _progressWindow.CancelRequested += ProgressWindow_CancelRequested;
        var progress = new Progress<CryptoProgress>(value => _progressWindow?.UpdateProgress(value));
        try
        {
            SetBusy(true);
            _progressWindow.Show();
            var result = await _archiveSession.ExportSelectionAsync(
                entry.RelativePath,
                destinationDirectory,
                outputName,
                progress,
                _operationCancellation.Token);
            CloseProgressWindow();
            MessageBox.Show(this, $"已导出{(entry.IsDirectory ? "明文文件夹" : "明文文件")}：\n\n{result.OutputPath}", AppName,
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
            ShowFriendlyError(entry.IsDirectory ? "无法导出文件夹" : "无法导出文件", exception);
        }
        finally
        {
            CloseProgressWindow();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            SetBusy(false);
        }
    }

    private async void DeleteUnlockedEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }
        if (_isBusy || _archiveSession is null ||
            UnlockedFileTree.SelectedItem is not TreeViewItem { Tag: SecureArchiveEntry entry })
        {
            return;
        }

        if (string.Equals(entry.RelativePath, _archiveSession.RootName, StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, "加密文件最外层的根内容必须保留。请选择其中的文件或文件夹进行删除。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var affectedEntries = _archiveSession.Entries
            .Where(candidate => string.Equals(candidate.RelativePath, entry.RelativePath, StringComparison.OrdinalIgnoreCase) ||
                                entry.IsDirectory && candidate.RelativePath.StartsWith(entry.RelativePath + "/", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var fileCount = affectedEntries.Count(candidate => !candidate.IsDirectory);
        var totalBytes = affectedEntries.Where(candidate => !candidate.IsDirectory).Sum(candidate => candidate.Length);
        var targetDescription = entry.IsDirectory
            ? $"文件夹：{entry.RelativePath}\n包含：{fileCount:N0} 个文件，共 {FormatByteSize(totalBytes)}"
            : $"文件：{entry.RelativePath}\n大小：{FormatByteSize(entry.Length)}";
        var confirmation = MessageBox.Show(this,
            $"确定要从加密文件中永久删除以下内容吗？\n\n{targetDescription}\n\n删除后无法恢复。",
            "确认从加密文件中删除", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        await UpdateUnlockedArchiveAsync([entry.RelativePath], []);
    }

    private async void AppendFilesToUnlocked_Click(object sender, RoutedEventArgs e)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }
        if (_isBusy || _archiveSession is null ||
            UnlockedFileTree.SelectedItem is not TreeViewItem { Tag: SecureArchiveEntry { IsDirectory: true } target })
        {
            MessageBox.Show(this, "请先在文件树中选中要放入内容的文件夹，再点击“追加文件”。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var type = MessageBox.Show(this,
            "请选择要追加的内容：\n\n“是”：选择一个或多个文件\n“否”：选择一个文件夹\n“取消”：不追加",
            "追加文件", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        if (type == MessageBoxResult.Cancel)
        {
            return;
        }

        var sourcePaths = new List<string>();
        if (type == MessageBoxResult.Yes)
        {
            var dialog = new OpenFileDialog { Title = "选择要追加的文件", Multiselect = true, CheckFileExists = true };
            if (dialog.ShowDialog(this) != true) return;
            sourcePaths.AddRange(dialog.FileNames.Distinct(StringComparer.OrdinalIgnoreCase));
        }
        else
        {
            var dialog = new OpenFolderDialog { Title = "选择要追加的文件夹", Multiselect = false };
            if (dialog.ShowDialog(this) != true) return;
            sourcePaths.Add(dialog.FolderName);
        }

        var existingPaths = _archiveSession.Entries.Select(entry => entry.RelativePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var removals = new List<string>();
        var additions = new List<ArchiveAppendSource>();
        foreach (var sourcePath in sourcePaths)
        {
            var name = File.Exists(sourcePath) ? new FileInfo(sourcePath).Name : new DirectoryInfo(sourcePath).Name;
            var desiredPath = target.RelativePath + "/" + name;
            var existing = _archiveSession.Entries.FirstOrDefault(entry =>
                string.Equals(entry.RelativePath, desiredPath, StringComparison.OrdinalIgnoreCase));
            if (existing is not null || existingPaths.Contains(desiredPath))
            {
                var choice = ArchiveConflictDialog.Show(this, name, existing?.Length ?? 0, GetSourceSize(sourcePath));
                if (choice == ArchiveConflictChoice.Cancel)
                {
                    return;
                }

                if (choice == ArchiveConflictChoice.Replace)
                {
                    if (existing is not null) removals.Add(existing.RelativePath);
                }
                else
                {
                    name = GetUniqueArchiveChildName(target.RelativePath, name, existingPaths);
                    desiredPath = target.RelativePath + "/" + name;
                }
            }

            existingPaths.Add(desiredPath);
            additions.Add(new ArchiveAppendSource(sourcePath, target.RelativePath, name));
        }

        if (additions.Count > 0)
        {
            await UpdateUnlockedArchiveAsync(removals, additions);
        }
    }

    private async Task UpdateUnlockedArchiveAsync(IReadOnlyList<string> removals, IReadOnlyList<ArchiveAppendSource> additions)
    {
        if (_archiveSession is null || _sourcePath is null)
        {
            return;
        }

        if (SelectedArchiveSigningIdentity is not { } identity)
        {
            MessageBox.Show(this, "请选择修改后使用的发送者身份。", AppName, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        using var archivePassword = ReadPassword(ArchivePasswordInput);
        using var signingPassword = ReadPassword(ArchiveSigningIdentityPasswordInput);
        if (archivePassword.IsEmpty || signingPassword.IsEmpty)
        {
            MessageBox.Show(this, "修改前请填写加密文件密码和修改后发送者身份密码。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        using var request = new ArchiveUpdateRequest(
            _sourcePath,
            archivePassword,
            identity.Id,
            signingPassword,
            CurrentKeyFilePath,
            CurrentCompression,
            removals,
            additions,
            new WindowInteropHelper(this).Handle);
        _operationCancellation = new CancellationTokenSource();
        _progressWindow = new ProgressWindow(isEncrypting: true, operationTitle: "正在更新加密文件") { Owner = this };
        _progressWindow.CancelRequested += ProgressWindow_CancelRequested;
        var progress = new Progress<CryptoProgress>(value => _progressWindow?.UpdateProgress(value));
        try
        {
            SetBusy(true);
            _progressWindow.Show();
            await _archiveService.RebuildArchiveAsync(_archiveSession, request, progress, _operationCancellation.Token);
            CloseProgressWindow();
            CloseArchiveSession();
            using var reopenPassword = ReadPassword(ArchivePasswordInput);
            await OpenArchiveForBrowsingAsync(reopenPassword);
            if (_archiveSession is null)
            {
                return;
            }
            ArchiveSigningIdentityPasswordInput.Clear();
            MessageBox.Show(this, "加密文件已更新，并已使用所选发送者身份重新签名。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            CloseProgressWindow();
            MessageBox.Show(this, "修改已取消，原加密文件没有变动。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            CloseProgressWindow();
            if (_archiveSession is { IsOpen: false })
            {
                CloseArchiveSession();
            }
            ShowFriendlyError("无法更新加密文件", exception);
        }
        finally
        {
            CloseProgressWindow();
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            SetBusy(false);
        }
    }

    private static long GetSourceSize(string path)
    {
        try
        {
            if (File.Exists(path)) return new FileInfo(path).Length;
            return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
                .Aggregate(0L, (total, file) => checked(total + new FileInfo(file).Length));
        }
        catch
        {
            return 0;
        }
    }

    private static string GetUniqueArchiveChildName(string parentPath, string name, IReadOnlySet<string> existingPaths)
    {
        var extension = Path.GetExtension(name);
        var baseName = extension.Length == 0 ? name : name[..^extension.Length];
        for (var index = 2; ; index++)
        {
            var candidate = $"{baseName} ({index}){extension}";
            if (!existingPaths.Contains(parentPath + "/" + candidate)) return candidate;
        }
    }

    private static T? FindVisualParent<T>(DependencyObject? source) where T : DependencyObject
    {
        while (source is not null)
        {
            if (source is T found) return found;
            source = VisualTreeHelper.GetParent(source);
        }

        return null;
    }

    private async void ExportAllUnlocked_Click(object sender, RoutedEventArgs e)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }
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
            MessageBox.Show(this, UiLanguage.IsEnglish ? "Wait for the current operation to finish before changing Strict Protection settings." : "请先等待当前操作完成，再调整严格防护设置。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            if (!await StrictProtectionSettings.OpenProtectedEditorAsync())
            {
                return;
            }
        }
        catch (System.ComponentModel.Win32Exception exception) when (HighSecurityLaunch.WasCancelled(exception))
        {
            MessageBox.Show(this, UiLanguage.IsEnglish ? "Windows administrator confirmation was canceled. Strict Protection settings were not changed." : "Windows 管理员确认已取消，严格防护设置没有改变。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法修改严格防护设置", exception);
            return;
        }

        _strictProtectionSettings = StrictProtectionSettings.Load();
        if (!string.IsNullOrWhiteSpace(_strictProtectionSettings.LoadFailureReason))
        {
            MessageBox.Show(this, _strictProtectionSettings.LoadFailureReason, AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        if (_strictProtectionSettings.Enabled)
        {
            if (!await EnableStrictProtectionAsync())
            {
                MessageBox.Show(this, UiLanguage.IsEnglish
                        ? $"The setting was saved, but monitoring could not start this time.\n\nReason: {GetStrictProtectionFailureReason()}\n\nAdministrator confirmation will be requested again next time."
                        : $"设置已经记住，但本次未能启动监控。\n\n原因：{GetStrictProtectionFailureReason()}\n\n下次启动时会再次请求管理员确认。",
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
        if (_allowElevatedMediaBrowsing)
        {
            // 高完整性窗口已由 Windows 隔离普通权限进程；不再启动会写用户日志的额外管理员监控。
            RefreshStrictProtectionButton();
            return;
        }

        if (!string.IsNullOrWhiteSpace(_strictProtectionSettings.LoadFailureReason))
        {
            MessageBox.Show(this, _strictProtectionSettings.LoadFailureReason, AppName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        if (_strictProtectionSettings.Enabled && !await EnableStrictProtectionAsync())
        {
            MessageBox.Show(this, UiLanguage.IsEnglish
                    ? $"Strict Protection was enabled previously, but monitoring did not start this time.\n\nReason: {GetStrictProtectionFailureReason()}\n\nClick Strict Protection later to start it again."
                    : $"上次已开启严格防护，但本次监控没有启动。\n\n原因：{GetStrictProtectionFailureReason()}\n\n您可以稍后点击“严格防护”再次启动。",
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

        foreach (var viewer in _activeExternalMediaViewers.ToArray())
        {
            await viewer.DisposeAsync();
            _activeExternalMediaViewers.Remove(viewer);
        }

        var started = await _strictProtection.StartAsync(_strictProtectionSettings);
        if (started)
        {
            _strictThreatHandled = false;
        }
        RefreshStrictProtectionButton();
        return started;
    }

    private string GetStrictProtectionFailureReason() =>
        _strictProtection.LastFailureReason is { } reason
            ? UiLanguage.Translate(reason)
            : UiLanguage.IsEnglish ? "No startup confirmation was received from the monitor." : "没有收到监控程序的启动确认。";

    private void StrictProtection_AlertRaised(object? sender, StrictProtectionAlert alert)
    {
        _ = Dispatcher.InvokeAsync(() => HandleStrictProtectionFailureAsync(alert, null));
    }

    private void StrictProtection_HealthFailed(object? sender, StrictProtectionHealthFailureEventArgs failure)
    {
        _ = Dispatcher.InvokeAsync(() => HandleStrictProtectionFailureAsync(null, failure.Reason));
    }

    private async Task HandleStrictProtectionFailureAsync(StrictProtectionAlert? alert, string? healthFailureReason)
    {
        if (_strictThreatHandled)
        {
            return;
        }

        _strictThreatHandled = true;
        try
        {
            if (alert is not null)
            {
                SecurityEventLog.Append(alert);
            }
            else
            {
                SecurityEventLog.AppendRuntimeFailure(healthFailureReason ?? "监控连接意外停止。");
            }
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
        if (NingRanRuntime.IsProcessElevated())
        {
            // 管理员高安全窗口不接触普通用户的恢复登记目录。
            cleanup = new TemporaryContentCleanupResult(0, []);
        }
        else
        {
            try
            {
                cleanup = await Task.Run(NrArchiveService.CleanupAbandonedTemporaryContent);
            }
            catch (Exception exception)
            {
                cleanup = new TemporaryContentCleanupResult(0,
                    [new TemporaryContentCleanupFailure("临时明文清理", exception.Message)]);
            }
        }

        var cleanupResult = cleanup.Failures.Count == 0
            ? (UiLanguage.IsEnglish ? "The current operation was stopped and temporary plaintext was cleaned." : "已停止当前操作，并已执行临时明文清理。")
            : (UiLanguage.IsEnglish ? $"The current operation was stopped; {cleanup.Failures.Count} temporary items will continue cleaning next time." : $"已停止当前操作；有 {cleanup.Failures.Count} 项临时内容将由下次启动继续清理。");
        if (alert is not null)
        {
            var processName = string.IsNullOrWhiteSpace(alert.ProcessPath)
                ? (UiLanguage.IsEnglish ? $"Process ID {alert.ProcessId}" : $"进程编号 {alert.ProcessId}")
                : alert.ProcessPath;
            MessageBox.Show(this,
                UiLanguage.IsEnglish
                    ? $"Strict Protection found that unapproved software still has read access to protected memory.\n\nAccessing process: {processName}\nAccessed component: {alert.TargetComponent}\n\n{cleanupResult}\nThe event was recorded in the security log. This feature helps detect and shorten exposure but cannot guarantee blocking an extremely brief read."
                    : $"严格防护发现未允许的软件仍持有受保护内存读取权限：\n\n访问程序：{processName}\n被访问组件：{alert.TargetComponent}\n\n{cleanupResult}\n事件已记录到安全日志。此功能用于发现和缩短风险，不能保证拦截一次极短的读取。",
                UiLanguage.IsEnglish ? "Strict Protection cleanup executed" : "严格防护已执行清理", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        else
        {
            MessageBox.Show(this,
                UiLanguage.IsEnglish
                    ? $"Strict Protection monitoring stopped unexpectedly.\n\n{UiLanguage.Translate(healthFailureReason)}\n\n{cleanupResult}\n\nRestart Strict Protection before continuing to handle sensitive content."
                    : $"严格防护监控已经意外停止：\n\n{healthFailureReason}\n\n{cleanupResult}\n\n请重新开启严格防护后再继续处理敏感内容。",
                UiLanguage.IsEnglish ? "Strict Protection failed and cleanup executed" : "严格防护已失效并执行清理", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        RefreshStrictProtectionButton();
    }

    private void RefreshStrictProtectionButton()
    {
        if (!IsInitialized || StrictProtectionButton is null)
        {
            return;
        }

        StrictProtectionButton.Content = UiLanguage.IsEnglish
            ? (_strictProtection.IsRunning ? "Strict Protection: On" : "Strict Protection")
            : (_strictProtection.IsRunning ? "严格防护：已开启" : "严格防护");
        StrictProtectionButton.ToolTip = UiLanguage.IsEnglish
            ? (_strictProtection.IsRunning
                ? "Strict Protection monitoring is running: detected threats stop the operation and clean up"
                : _strictProtectionSettings.Enabled
                    ? "Strict Protection is enabled but monitoring has not started this time"
                    : "Configure Strict Protection monitoring")
            : (_strictProtection.IsRunning
                ? "严格防护监控正在运行：发现后会停止操作并清理"
                : _strictProtectionSettings.Enabled
                    ? "严格防护已记住，但本次监控尚未启动"
                    : "设置严格防护监控");
    }

    private void CloseArchiveSession()
    {
        foreach (var viewer in _activeExternalMediaViewers.ToArray())
        {
            _ = viewer.DisposeAsync();
        }
        _activeExternalMediaViewers.Clear();
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
        SecureMediaKind.Pdf => "PDF",
        _ => "📄",
    };

    private static bool IsSupportedByExternalMediaViewer(SecureArchiveEntry entry) =>
        MediaPlaybackHost.CanOpenWithExternalViewer(entry);

    private async Task<ExternalMediaViewerLaunchResult> TryOpenWithExternalMediaViewerAsync(
        IReadOnlyList<SecureArchiveEntry> mediaEntries,
        SecureArchiveEntry initialEntry)
    {
        var playerPath = MediaPlaybackHost.FindExternalViewer();
        if (playerPath is null || _archiveSession is null)
        {
            // 未安装播放器属于正常情况，调用处会自动打开内置播放器。
            return new ExternalMediaViewerLaunchResult(false, "viewer-not-found", null);
        }

        var host = new MediaPlaybackHost(_archiveSession, mediaEntries, initialEntry);
        _activeExternalMediaViewers.Add(host);
        try
        {
            await host.StartAsync(playerPath);
            _ = ObserveExternalMediaViewerAsync(host, initialEntry.Name);
            return new ExternalMediaViewerLaunchResult(true, null, null);
        }
        catch (Exception exception)
        {
            _activeExternalMediaViewers.Remove(host);
            await host.DisposeAsync();
            var (problemId, reason) = exception switch
            {
                TimeoutException => ("secure-session-timeout", "查看器已启动，但五秒内没有完成内部安全连接。请确认安装的是最新版凝然媒体查看器。"),
                FileNotFoundException => ("viewer-file-missing", "Windows 记录的媒体查看器文件已不存在或无法读取。请重新安装查看器。"),
                _ => ($"viewer-start-{exception.GetType().Name}", $"查看器没有成功建立安全连接：{exception.Message}"),
            };
            return new ExternalMediaViewerLaunchResult(false, problemId, reason);
        }
    }

    private void ShowExternalMediaViewerFailure(ExternalMediaViewerLaunchResult result)
    {
        if (result.Started || string.IsNullOrWhiteSpace(result.ProblemId) || string.IsNullOrWhiteSpace(result.Reason) ||
            _mediaViewerFailurePreferences.IsIgnored(result.ProblemId))
        {
            return;
        }
        if (MediaViewerFailureNotice.Show(this, result.Reason))
        {
            _mediaViewerFailurePreferences = _mediaViewerFailurePreferences.Ignore(result.ProblemId);
        }
    }

    private async Task ObserveExternalMediaViewerAsync(MediaPlaybackHost host, string fileName)
    {
        int? abnormalExitCode = null;
        try
        {
            var exitCode = await host.WaitForExitAsync();
            if (exitCode != 0) abnormalExitCode = exitCode;
        }
        catch
        {
            // 主窗口正在关闭或严格防护正在清理时，查看器会被主动停止。
        }
        finally
        {
            _activeExternalMediaViewers.Remove(host);
            await host.DisposeAsync();
        }

        if (abnormalExitCode is not null && IsLoaded && !_closingAnimationComplete)
        {
            await Dispatcher.InvokeAsync(() => ShowExternalMediaViewerFailure(new ExternalMediaViewerLaunchResult(
                false,
                $"viewer-exited-{abnormalExitCode.Value}",
                $"查看器在查看“{fileName}”时意外退出（代码 {abnormalExitCode.Value}）。文件仍保持加密，未创建普通副本。")));
        }
    }

    private sealed record ExternalMediaViewerLaunchResult(bool Started, string? ProblemId, string? Reason);

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
        if (_allowElevatedMediaBrowsing)
        {
            e.Effects = DragDropEffects.None;
            e.Handled = true;
            return;
        }

        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (_allowElevatedMediaBrowsing)
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        if (_allowElevatedMediaBrowsing &&
            (!File.Exists(selectedPath) ||
             !string.Equals(Path.GetExtension(selectedPath), ".nrenc", StringComparison.OrdinalIgnoreCase)))
        {
            ShowHighSecurityViewingOnlyMessage();
            return;
        }

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
        SettingsScrollViewer.VerticalScrollBarVisibility = archiveUnlocked
            ? ScrollBarVisibility.Disabled
            : ScrollBarVisibility.Hidden;
        SettingsScrollViewer.PanningMode = archiveUnlocked
            ? PanningMode.None
            : PanningMode.VerticalOnly;
        if (archiveUnlocked)
        {
            SettingsScrollViewer.ScrollToTop();
        }
        EncryptSettingsPanel.Visibility = !archiveUnlocked && IsEncrypting ? Visibility.Visible : Visibility.Collapsed;
        DecryptSettingsPanel.Visibility = !archiveUnlocked && !IsEncrypting ? Visibility.Visible : Visibility.Collapsed;
        UnlockedArchivePanel.Visibility = archiveUnlocked ? Visibility.Visible : Visibility.Collapsed;
        DestinationPanel.Visibility = archiveUnlocked || _allowElevatedMediaBrowsing
            ? Visibility.Collapsed
            : Visibility.Visible;
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
        HighSecurityOpenButton.Visibility = !archiveUnlocked && !IsEncrypting && !_allowElevatedMediaBrowsing &&
            _detectedArchiveInfo.HasSenderSignature ? Visibility.Visible : Visibility.Collapsed;
        HighSecurityStatusText.Visibility = _allowElevatedMediaBrowsing ? Visibility.Visible : Visibility.Collapsed;
        ArchiveEditingPanel.Visibility = _allowElevatedMediaBrowsing ? Visibility.Collapsed : Visibility.Visible;
        ExportAllUnlockedButton.Visibility = _allowElevatedMediaBrowsing ? Visibility.Collapsed : Visibility.Visible;
        AppendFilesToUnlockedButton.Visibility = _allowElevatedMediaBrowsing ? Visibility.Collapsed : Visibility.Visible;
    }

    private void SettingsScrollViewer_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (_archiveSession is null || e.OriginalSource is not DependencyObject source ||
            IsDescendantOf(source, UnlockedFileTree))
        {
            return;
        }

        e.Handled = true;
    }

    private void UnlockedFileTree_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        var scrollViewer = FindVisualChild<ScrollViewer>(UnlockedFileTree);
        if (scrollViewer is null || scrollViewer.ScrollableHeight <= 0)
        {
            return;
        }

        // Drive the tree's own scrolling so hidden chrome cannot restrict the last rows.
        var line = Math.Max(24, scrollViewer.ViewportHeight > 0 ? scrollViewer.ViewportHeight / 10 : 32);
        var nextOffset = scrollViewer.VerticalOffset - (e.Delta / 120d * line);
        scrollViewer.ScrollToVerticalOffset(Math.Clamp(nextOffset, 0, scrollViewer.ScrollableHeight));
        e.Handled = true;
    }

    private static bool IsDescendantOf(DependencyObject source, DependencyObject ancestor)
    {
        for (var current = source; current is not null; current = current is Visual || current is Visual3D
                 ? VisualTreeHelper.GetParent(current)
                 : LogicalTreeHelper.GetParent(current))
        {
            if (ReferenceEquals(current, ancestor)) return true;
        }

        return false;
    }

    private static T? FindVisualChild<T>(DependencyObject? source) where T : DependencyObject
    {
        if (source is null) return null;
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(source); index++)
        {
            var child = VisualTreeHelper.GetChild(source, index);
            if (child is T found) return found;
            var nested = FindVisualChild<T>(child);
            if (nested is not null) return nested;
        }

        return null;
    }

    private void HighSecurityOpen_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy || string.IsNullOrWhiteSpace(_sourcePath) || !File.Exists(_sourcePath) ||
            !string.Equals(Path.GetExtension(_sourcePath), ".nrenc", StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, "请先选择一个可打开的凝然加密文件。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var result = MessageBox.Show(this,
            "高安全打开会启动一个单独的管理员窗口。该窗口不会接收当前输入的密码或密匙，您需要重新验证；它仅用于程序内查看，不能导出或修改文件。\n\n它不是 Windows 最高级受保护进程，不能防止同一 Windows 账户下已能读取其他程序内存的软件。\n\n继续吗？",
            "高安全打开", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            ClearPasswords();
            HighSecurityLaunch.Start(_sourcePath);
        }
        catch (Exception exception) when (HighSecurityLaunch.WasCancelled(exception))
        {
            MessageBox.Show(this, "未获得 Windows 管理员确认，高安全查看没有启动。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            ShowFriendlyError("无法启动高安全查看", exception);
        }
    }

    private void ShowHighSecurityViewingOnlyMessage() => MessageBox.Show(this,
        "高安全查看只允许在程序内查看内容，不能导出、删除或修改文件。请关闭高安全查看后，在普通窗口中执行这些操作。",
        "高安全查看", MessageBoxButton.OK, MessageBoxImage.Information);

    private void RefreshIdentityList(string? selectIdentityId = null)
    {
        var selectedId = selectIdentityId ?? SelectedSigningIdentity?.Id;
        var archiveSelectedId = selectIdentityId ?? SelectedArchiveSigningIdentity?.Id ?? selectedId;
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

            ArchiveSigningIdentityCombo.ItemsSource = identities;
            ArchiveSigningIdentityCombo.SelectedItem = identities.FirstOrDefault(identity =>
                string.Equals(identity.Id, archiveSelectedId, StringComparison.OrdinalIgnoreCase));
            if (ArchiveSigningIdentityCombo.SelectedItem is null && identities.Count > 0)
            {
                ArchiveSigningIdentityCombo.SelectedIndex = 0;
            }
        }
        catch (Exception exception)
        {
            SigningIdentityCombo.ItemsSource = Array.Empty<IdentitySummary>();
            ArchiveSigningIdentityCombo.ItemsSource = Array.Empty<IdentitySummary>();
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
            var pendingCount = _trustedContactService.ListContactsForManagement()
                .Count(contact => contact.RequiresReverification);
            if (pendingCount > 0)
            {
                MessageBox.Show(
                    this,
                    $"发现 {pendingCount} 个升级前保存的联系人。为防止其他程序篡改，这些旧记录已暂停信任。\n\n" +
                    "请打开“管理可信联系人”，逐个重新核对安全码。完成前，它们不会用于验证发送者。",
                    AppName,
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
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
        ArchiveSigningIdentityPasswordInput.Clear();
        ArchivePasswordInput.Clear();
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
        // 动画的最终值优先级高于直接赋值；不清除它，窗口恢复时会偶尔一直保持半透明。
        WindowFrame.BeginAnimation(OpacityProperty, null);
        WindowScale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
        WindowScale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
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
        if (WindowState != WindowState.Minimized)
        {
            // 任务栏恢复窗口时也保证不会继承最小化动画留下的透明状态。
            WindowFrame.BeginAnimation(OpacityProperty, null);
            WindowScale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            WindowScale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            WindowFrame.Opacity = 1;
            WindowScale.ScaleX = WindowScale.ScaleY = 1;
        }
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
            _strictProtection.HealthFailed -= StrictProtection_HealthFailed;
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
