using System.Windows;
using NingRan.Core;

namespace NingRan.Windows;

public partial class IdentityDialog : Window
{
    private readonly bool _isCreating;
    private SensitivePassword? _identityPassword;

    public IdentityDialog(bool isCreating, bool isDeleting = false, bool isExporting = false)
    {
        InitializeComponent();
        if (isDeleting && isExporting)
        {
            throw new ArgumentException("身份操作类型不能重复。", nameof(isExporting));
        }

        _isCreating = isCreating;
        if (!isCreating)
        {
            Title = isDeleting
                ? "删除发送者身份"
                : isExporting
                    ? "导出私密身份备份"
                    : "导入发送者身份";
            TitleText.Text = isDeleting || isExporting ? "确认身份密码" : "导入身份备份";
            DescriptionText.Text = isDeleting
                ? "请输入该身份的独立密码。密码正确后才允许删除程序内保存的身份。"
                : isExporting
                    ? "请输入该身份的独立密码。密码正确后才会导出加密的私密身份备份。"
                    : "请输入创建该身份时设置的独立身份密码。";
            NamePanel.Visibility = Visibility.Collapsed;
            ConfirmPanel.Visibility = Visibility.Collapsed;
            PasswordHintText.Text = isDeleting
                ? "已经主动导出的私密备份和公开身份文件不会被删除。"
                : isExporting
                    ? "密码不会写入导出路径或提示信息。"
                    : "此密码只用于解锁身份备份。";
            ConfirmButton.Content = isDeleting
                ? "验证并删除"
                : isExporting
                    ? "验证并导出"
                    : "导入身份";
        }
    }

    public string IdentityName => IdentityNameInput.Text.Trim();

    public SensitivePassword TakeIdentityPassword()
    {
        var password = _identityPassword
            ?? throw new InvalidOperationException("身份密码已经取出或对话框尚未确认。");
        _identityPassword = null;
        return password;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        SensitivePassword? password = ReadPassword(IdentityPasswordInput);
        using var confirmationPassword = _isCreating
            ? ReadPassword(ConfirmIdentityPasswordInput)
            : SensitivePassword.FromString(string.Empty);
        try
        {
            if (_isCreating)
            {
                if (string.IsNullOrWhiteSpace(IdentityName))
                {
                    MessageBox.Show(this, "请填写身份名称。", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                PasswordRules.ValidateForCreation(password);
                if (!password.FixedTimeEquals(confirmationPassword))
                {
                    MessageBox.Show(this, "两次输入的身份密码不一致。", Title,
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!ConfirmWeakPassword(password))
                {
                    return;
                }
            }
            else if (password.IsEmpty)
            {
                MessageBox.Show(this, "请输入身份密码。", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _identityPassword = password;
            password = null;
            IdentityPasswordInput.Clear();
            ConfirmIdentityPasswordInput.Clear();
            DialogResult = true;
        }
        catch (ArgumentException exception)
        {
            MessageBox.Show(this, exception.Message, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            password?.Dispose();
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    protected override void OnClosed(EventArgs e)
    {
        if (DialogResult != true)
        {
            _identityPassword?.Dispose();
            _identityPassword = null;
        }
        IdentityPasswordInput.Clear();
        ConfirmIdentityPasswordInput.Clear();
        base.OnClosed(e);
    }

    private SensitivePassword ReadPassword(System.Windows.Controls.PasswordBox input)
    {
        using var securePassword = input.SecurePassword;
        return SensitivePassword.FromSecureString(securePassword);
    }

    private bool ConfirmWeakPassword(SensitivePassword password)
    {
        var assessment = PasswordRules.Assess(password);
        if (!assessment.HasWarnings)
        {
            return true;
        }

        var details = string.Join("\n", assessment.Warnings.Select(warning => $"• {warning}"));
        return MessageBox.Show(
            this,
            $"这个身份密码可能不够安全：\n\n{details}\n\n仍要继续使用吗？",
            "密码安全提示",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }
}
