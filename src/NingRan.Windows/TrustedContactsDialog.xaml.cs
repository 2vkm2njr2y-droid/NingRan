using System.Windows;
using System.Windows.Controls;
using NingRan.Core;

namespace NingRan.Windows;

public partial class TrustedContactsDialog : Window
{
    private readonly NrTrustedContactService _service;

    public TrustedContactsDialog(NrTrustedContactService service)
    {
        InitializeComponent();
        _service = service;
        RefreshContacts();
    }

    private TrustedContactSummary? SelectedContact => ContactList.SelectedItem as TrustedContactSummary;

    private void RefreshContacts()
    {
        ContactList.ItemsSource = _service.ListTrustedContacts();
        ContactDetails.Text = ContactList.Items.Count == 0
            ? "目前没有可信联系人。首次导入公开身份时，程序会要求您输入并核对安全码。"
            : "请选择一个联系人查看确认时间。";
        RemoveButton.IsEnabled = false;
    }

    private void ContactList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var contact = SelectedContact;
        RemoveButton.IsEnabled = contact is not null;
        ContactDetails.Text = contact is null
            ? "请选择一个联系人查看确认时间。"
            : $"名称：{contact.Name}\n确认时间：{contact.TrustedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm}";
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        var contact = SelectedContact;
        if (contact is null)
        {
            return;
        }

        if (MessageBox.Show(
                this,
                $"确定删除可信联系人“{contact.Name}”吗？\n\n以后再次收到该身份的文件时，必须重新核对并明确同意。",
                "删除可信联系人",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            _service.RemoveTrustedContact(contact.Id);
            RefreshContacts();
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "无法删除联系人", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
