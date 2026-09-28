using System.Windows;
using NingRan.Core;

namespace NingRan.Windows;

public partial class VaultExportWindow : Window
{
    public VaultExportWindow(IReadOnlyList<IdentitySummary> identities)
    {
        InitializeComponent();
        IdentityCombo.ItemsSource = identities;
        if (identities.Count > 0) IdentityCombo.SelectedIndex = 0;
        if (UiLanguage.IsEnglish) ApplyEnglish();
    }

    public IdentitySummary? SelectedIdentity => IdentityCombo.SelectedItem as IdentitySummary;
    public SensitivePassword ArchivePassword { get; private set; } = SensitivePassword.FromString(string.Empty);
    public SensitivePassword IdentityPassword { get; private set; } = SensitivePassword.FromString(string.Empty);

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIdentity is null)
        {
            MessageBox.Show(this, UiLanguage.IsEnglish ? "Create or select a sender identity first." : "请先创建或选择一个发送者身份。",
                Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        using var first = SensitivePassword.FromSecureString(ArchivePasswordInput.SecurePassword);
        using var second = SensitivePassword.FromSecureString(ConfirmPasswordInput.SecurePassword);
        using var identity = SensitivePassword.FromSecureString(IdentityPasswordInput.SecurePassword);
        if (first.IsEmpty || !first.FixedTimeEquals(second))
        {
            MessageBox.Show(this, UiLanguage.IsEnglish ? "Enter the same non-empty archive password twice." : "请两次输入相同且非空的加密包密码。",
                Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (identity.IsEmpty)
        {
            MessageBox.Show(this, UiLanguage.IsEnglish ? "Enter the sender identity password." : "请输入发送者身份密码。",
                Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        try { PasswordRules.ValidateForCreation(first); }
        catch (ArgumentException exception)
        {
            MessageBox.Show(this, exception.Message, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        ArchivePassword.Dispose();
        IdentityPassword.Dispose();
        ArchivePassword = SensitivePassword.FromSecureString(ArchivePasswordInput.SecurePassword);
        IdentityPassword = SensitivePassword.FromSecureString(IdentityPasswordInput.SecurePassword);
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void ApplyEnglish()
    {
        Title = "Export vault";
        TitleText.Text = "Export as .nrenc";
        HintText.Text = "The exported archive uses its own password and is signed by the selected sender identity.";
        IdentityLabel.Text = "Sender identity";
        ArchivePasswordLabel.Text = "Archive password";
        ConfirmPasswordLabel.Text = "Confirm archive password";
        IdentityPasswordLabel.Text = "Sender identity password";
        CancelButton.Content = "Cancel";
        ExportButton.Content = "Start export";
    }
}
