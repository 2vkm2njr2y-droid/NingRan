using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

public partial class ArchiveUnlockWindow : Window
{
    private readonly ArchiveInfo _archiveInfo;

    public ArchiveUnlockWindow(string archiveName, ArchiveInfo archiveInfo)
    {
        _archiveInfo = archiveInfo;
        InitializeComponent();

        SubtitleText.Text = UiLanguage.IsEnglish
            ? $"Choose how to unlock “{archiveName}”. Encrypted content is read only after verification."
            : $"选择“{archiveName}”的解锁方式。验证通过后才会读取加密内容。";

        FlexibleChoice.IsEnabled = archiveInfo.Mode == EncryptionMode.Flexible;
        if (archiveInfo.Mode == EncryptionMode.Flexible)
        {
            FlexibleChoice.IsChecked = true;
            ApplyFlexibleRequirements();
        }
        else if (archiveInfo.Mode == EncryptionMode.Advanced)
        {
            KeyChoice.IsChecked = true;
        }
        else if (archiveInfo.Mode == EncryptionMode.PhysicalDevice)
        {
            PhysicalChoice.IsChecked = true;
        }

        if (UiLanguage.IsEnglish)
        {
            Title = "Choose unlock method";
            TitleText.Text = "Choose unlock method";
            StandardTitle.Text = "Password";
            StandardDescription.Text = "Use the password set when this archive was created.";
            KeyTitle.Text = "Password + key file";
            KeyDescription.Text = "Also choose the key file used when this archive was created.";
            PhysicalTitle.Text = "Password + physical device";
            PhysicalDescription.Text = "Insert an authorized physical device before continuing.";
            FlexibleTitle.Text = "Custom protection";
            FlexibleDescription.Text = "Use every protection condition recorded in this archive.";
            KeyLabel.Text = "Key file";
            ChooseKeyButton.Content = "Choose";
            PhysicalHint.Text = "Insert the authorized physical device. Its name and identifier stay hidden until unlock succeeds.";
            PasswordLabel.Text = "Password";
            CancelButton.Content = "Cancel";
            UnlockButton.Content = "Unlock and open";
            FlexibleHintText.Text = "Every required condition must pass. The existing physical-device and Windows Hello checks continue after this window.";
        }

        UpdateModePanels();
    }

    public EncryptionMode SelectedMode => FlexibleChoice.IsChecked == true
        ? EncryptionMode.Flexible
        : StandardChoice.IsChecked == true
            ? EncryptionMode.Standard
            : KeyChoice.IsChecked == true ? EncryptionMode.Advanced : EncryptionMode.PhysicalDevice;

    public string? KeyFilePath =>
        SelectedMode == EncryptionMode.Advanced ||
        SelectedMode == EncryptionMode.Flexible && FlexibleKeyFileCheck.IsChecked == true
            ? KeyFileInput.Text
            : null;

    public SensitivePassword TakePassword()
    {
        var password = SensitivePassword.FromSecureString(PasswordInput.SecurePassword);
        PasswordInput.Clear();
        return password;
    }

    private ProtectionFactor RequiredFactors =>
        _archiveInfo.ProtectionFactors ??
        _archiveInfo.Mode switch
        {
            EncryptionMode.Advanced => ProtectionFactor.Password | ProtectionFactor.KeyFile,
            EncryptionMode.PhysicalDevice => ProtectionFactor.Password | ProtectionFactor.PhysicalDevice,
            EncryptionMode.Flexible => ProtectionFactor.Password,
            _ => ProtectionFactor.Password,
        };

    private void Mode_Checked(object sender, RoutedEventArgs e)
    {
        // XAML 初始化第一个选项时，其余选项尚未创建。
        if (!IsInitialized || FlexibleChoice is null)
        {
            return;
        }

        if (SelectedMode == EncryptionMode.Flexible)
        {
            ApplyFlexibleRequirements();
        }

        UpdateModePanels();
    }

    private void ApplyFlexibleRequirements()
    {
        var factors = RequiredFactors;
        FlexiblePasswordCheck.IsChecked = (factors & ProtectionFactor.Password) != 0;
        FlexibleKeyFileCheck.IsChecked = (factors & ProtectionFactor.KeyFile) != 0;
        FlexiblePhysicalCheck.IsChecked = (factors & ProtectionFactor.PhysicalDevice) != 0;
        FlexibleHelloCheck.IsChecked = (factors & ProtectionFactor.WindowsHello) != 0;
        FlexibleRequirementText.Text = DescribeFactors(factors);
    }

    private string DescribeFactors(ProtectionFactor factors)
    {
        var names = new List<string>();
        if ((factors & ProtectionFactor.Password) != 0) names.Add(UiLanguage.IsEnglish ? "Password" : "密码");
        if ((factors & ProtectionFactor.KeyFile) != 0) names.Add(UiLanguage.IsEnglish ? "Key file" : "密匙文件");
        if ((factors & ProtectionFactor.PhysicalDevice) != 0) names.Add(UiLanguage.IsEnglish ? "Physical device" : "物理设备");
        if ((factors & ProtectionFactor.WindowsHello) != 0) names.Add("Windows Hello");
        return names.Count == 0 ? (UiLanguage.IsEnglish ? "None" : "无") : string.Join(UiLanguage.IsEnglish ? " + " : " + ", names);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private void CloseWindow_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void UpdateModePanels()
    {
        if (!IsInitialized) return;
        var mode = SelectedMode;
        var needsKey = mode == EncryptionMode.Advanced ||
                       mode == EncryptionMode.Flexible && FlexibleKeyFileCheck.IsChecked == true;
        var needsPhysical = mode == EncryptionMode.PhysicalDevice ||
                            mode == EncryptionMode.Flexible && FlexiblePhysicalCheck.IsChecked == true;
        KeyPanel.Visibility = needsKey ? Visibility.Visible : Visibility.Collapsed;
        PhysicalPanel.Visibility = needsPhysical ? Visibility.Visible : Visibility.Collapsed;
        FlexiblePanel.Visibility = mode == EncryptionMode.Flexible ? Visibility.Visible : Visibility.Collapsed;
        PasswordLabel.Text = mode == EncryptionMode.Flexible && FlexiblePasswordCheck.IsChecked != true
            ? (UiLanguage.IsEnglish ? "Password (optional)" : "密码（此文件未要求）")
            : (UiLanguage.IsEnglish ? "Password" : "密码");
    }

    private void ChooseKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = UiLanguage.IsEnglish ? "Choose key file" : "选择密匙文件",
            Filter = "NingRan key files|*.nrkey|All files|*.*",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true) KeyFileInput.Text = dialog.FileName;
    }

    private void Unlock_Click(object sender, RoutedEventArgs e)
    {
        if ((SelectedMode == EncryptionMode.Advanced ||
             SelectedMode == EncryptionMode.Flexible && FlexibleKeyFileCheck.IsChecked == true) &&
            !File.Exists(KeyFileInput.Text))
        {
            MessageBox.Show(this,
                UiLanguage.IsEnglish ? "Choose the key file used by this archive first." : "请先选择此文件创建时使用的密匙文件。",
                Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var passwordRequired = SelectedMode != EncryptionMode.Flexible ||
                               FlexiblePasswordCheck.IsChecked == true;
        if (passwordRequired && PasswordInput.SecurePassword.Length == 0)
        {
            MessageBox.Show(this,
                UiLanguage.IsEnglish ? "Enter the archive password." : "请输入加密文件密码。",
                Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
