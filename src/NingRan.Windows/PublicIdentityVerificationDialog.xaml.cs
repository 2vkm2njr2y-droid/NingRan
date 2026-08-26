using System.Security.Cryptography;
using System.Windows;

namespace NingRan.Windows;

public partial class PublicIdentityVerificationDialog : Window
{
    private const int VerificationCodeLength = 7;
    private readonly string _expectedCode;

    public PublicIdentityVerificationDialog(
        string identityName,
        string expectedCode,
        string targetAccount,
        string targetUserSid)
    {
        InitializeComponent();
        ArgumentException.ThrowIfNullOrWhiteSpace(identityName);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetAccount);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetUserSid);
        if (!IsLetterCode(expectedCode))
        {
            throw new ArgumentException("公开身份安全码格式不正确。", nameof(expectedCode));
        }

        IdentityNameText.Text = identityName;
        TargetAccountText.Text =
            $"这次确认将修改以下 Windows 账户的受保护联系人：\n{targetAccount}\nSID：{targetUserSid}";
        _expectedCode = expectedCode;
    }

    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        VerificationCodeInput.Focus();
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (!CodesMatch(VerificationCodeInput.Text, _expectedCode))
        {
            ErrorText.Visibility = Visibility.Visible;
            VerificationCodeInput.SelectAll();
            VerificationCodeInput.Focus();
            return;
        }

        VerificationCodeInput.Clear();
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    protected override void OnClosed(EventArgs e)
    {
        VerificationCodeInput.Clear();
        base.OnClosed(e);
    }

    private static bool CodesMatch(string actual, string expected)
    {
        if (!IsLetterCode(actual) || !IsLetterCode(expected))
        {
            return false;
        }

        Span<byte> actualBytes = stackalloc byte[VerificationCodeLength];
        Span<byte> expectedBytes = stackalloc byte[VerificationCodeLength];
        for (var index = 0; index < VerificationCodeLength; index++)
        {
            actualBytes[index] = (byte)actual[index];
            expectedBytes[index] = (byte)expected[index];
        }

        return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
    }

    private static bool IsLetterCode(string value) =>
        value.Length == VerificationCodeLength &&
        value.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z');
}
