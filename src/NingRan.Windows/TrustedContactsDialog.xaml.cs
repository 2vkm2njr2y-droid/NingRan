using System.Windows;
using System.Windows.Controls;
using NingRan.Core;

namespace NingRan.Windows;

public partial class TrustedContactsDialog : Window
{
    private readonly NrTrustedContactService _service;
    private readonly TrustedContactBrokerClient _brokerClient;

    internal TrustedContactsDialog(
        NrTrustedContactService service,
        TrustedContactBrokerClient brokerClient)
    {
        InitializeComponent();
        _service = service;
        _brokerClient = brokerClient;
        RefreshContacts();
    }

    private TrustedContactSummary? SelectedContact => ContactList.SelectedItem as TrustedContactSummary;

    private void RefreshContacts()
    {
        ContactList.ItemsSource = _service.ListContactsForManagement();
        ContactDetails.Text = ContactList.Items.Count == 0
            ? "目前没有可信联系人。首次导入公开身份时，程序会要求您输入并核对安全码。"
            : "请选择一个联系人查看确认时间。";
        ReverifyButton.IsEnabled = false;
        RemoveButton.IsEnabled = false;
    }

    private void ContactList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var contact = SelectedContact;
        ReverifyButton.IsEnabled = contact?.RequiresReverification == true;
        RemoveButton.IsEnabled = contact is not null;
        ContactDetails.Text = contact is null
            ? "请选择一个联系人查看确认时间。"
            : contact.RequiresReverification
                ? $"名称：{contact.Name}\n状态：升级前的旧记录，已暂停信任，必须重新核对安全码"
                : $"名称：{contact.Name}\n确认时间：{contact.TrustedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm}\n状态：管理员保护";
    }

    private async void Reverify_Click(object sender, RoutedEventArgs e)
    {
        var contact = SelectedContact;
        if (contact?.RequiresReverification != true)
        {
            return;
        }

        try
        {
            SetOperationActive(true);
            var result = await _brokerClient.ReverifyAsync(contact);
            if (result is not null)
            {
                RefreshContacts();
                MessageBox.Show(this, $"联系人“{result.Name}”已经重新核对并受到管理员保护。",
                    "可信联系人", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "无法重新核对联系人", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            SetOperationActive(false);
        }
    }

    private async void Remove_Click(object sender, RoutedEventArgs e)
    {
        var contact = SelectedContact;
        if (contact is null)
        {
            return;
        }

        try
        {
            SetOperationActive(true);
            if (await _brokerClient.RemoveAsync(contact))
            {
                RefreshContacts();
            }
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "无法删除联系人", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            SetOperationActive(false);
        }
    }

    private void SetOperationActive(bool active)
    {
        ContactList.IsEnabled = !active;
        CloseButton.IsEnabled = !active;
        if (active)
        {
            ReverifyButton.IsEnabled = false;
            RemoveButton.IsEnabled = false;
        }
        else
        {
            var contact = SelectedContact;
            ReverifyButton.IsEnabled = contact?.RequiresReverification == true;
            RemoveButton.IsEnabled = contact is not null;
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
