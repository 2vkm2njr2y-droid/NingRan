using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

public partial class PasswordPromptWindow : Window
{
    public PasswordPromptWindow(string prompt)
    {
        InitializeComponent();
        PromptText.Text = prompt;
        Title = prompt;
        if (UiLanguage.IsEnglish)
        {
            ProtectionLabel.Text = "Archive protection";
            PasswordLabel.Text = "Password";
            KeyFileLabel.Text = "Key file";
            ChooseKeyButton.Content = "Choose";
            ((ComboBoxItem)ProtectionModeCombo.Items[0]).Content = "Password";
            ((ComboBoxItem)ProtectionModeCombo.Items[1]).Content = "Password + key file";
            ((ComboBoxItem)ProtectionModeCombo.Items[2]).Content = "Password + physical device";
        }
    }

    public SensitivePassword Password { get; private set; } = SensitivePassword.FromString(string.Empty);

    public EncryptionMode SelectedMode => ProtectionModeCombo.SelectedIndex switch
    {
        1 => EncryptionMode.Advanced,
        2 => EncryptionMode.PhysicalDevice,
        _ => EncryptionMode.Standard,
    };

    public string? KeyFilePath => SelectedMode == EncryptionMode.Advanced ? KeyFileInput.Text : null;

    private void ProtectionModeCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) =>
        KeyFilePanel.Visibility = SelectedMode == EncryptionMode.Advanced ? Visibility.Visible : Visibility.Collapsed;

    private void ChooseKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = UiLanguage.IsEnglish ? "Choose key file" : "选择密匙文件",
            Filter = "All files|*.*|NingRan key files|*.nrkey",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == true) KeyFileInput.Text = dialog.FileName;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedMode == EncryptionMode.Advanced && !File.Exists(KeyFileInput.Text))
        {
            MessageBox.Show(this,
                UiLanguage.IsEnglish ? "Choose the original key file first." : "请先选择原来的密匙文件。",
                Title,
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }
        Password.Dispose();
        Password = SensitivePassword.FromSecureString(PasswordInput.SecurePassword);
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
