using System.Windows;
using NingRan.Core;

namespace NingRan.Windows;

public partial class ArchiveModificationWindow : Window
{
    private readonly EncryptionMode _mode;

    public ArchiveModificationWindow(
        IReadOnlyList<IdentitySummary> identities,
        EncryptionMode mode,
        Window? owner = null)
    {
        _mode = mode;
        Owner = owner;
        InitializeComponent();
        IdentityCombo.ItemsSource = identities;
        if (identities.Count > 0) IdentityCombo.SelectedIndex = 0;
        if (mode == EncryptionMode.Flexible)
        {
            ArchivePasswordLabel.Text = "原加密文件密码（如果文件要求）";
        }
    }

    public string? SelectedIdentityId => (IdentityCombo.SelectedItem as IdentitySummary)?.Id;

    public SensitivePassword TakeArchivePassword()
    {
        var password = SensitivePassword.FromSecureString(ArchivePasswordInput.SecurePassword);
        ArchivePasswordInput.Clear();
        return password;
    }

    public SensitivePassword TakeIdentityPassword()
    {
        var password = SensitivePassword.FromSecureString(IdentityPasswordInput.SecurePassword);
        IdentityPasswordInput.Clear();
        return password;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIdentityId is null)
        {
            ShowError("请选择修改后使用的发送者身份。");
            return;
        }

        if (IdentityPasswordInput.SecurePassword.Length == 0)
        {
            ShowError("请输入发送者身份密码。");
            return;
        }

        if (_mode != EncryptionMode.Flexible && ArchivePasswordInput.SecurePassword.Length == 0)
        {
            ShowError("请输入原加密文件密码。");
            return;
        }

        DialogResult = true;
    }

    private void ShowError(string message)
    {
        StatusText.Text = message;
        StatusText.Visibility = Visibility.Visible;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
