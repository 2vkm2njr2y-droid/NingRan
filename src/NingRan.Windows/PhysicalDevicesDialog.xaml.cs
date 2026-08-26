using System.Windows;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

public partial class PhysicalDevicesDialog : Window
{
    private const string AppName = "凝然加密";
    private readonly NrPhysicalDeviceService _service;

    public PhysicalDevicesDialog(NrPhysicalDeviceService service)
    {
        _service = service;
        InitializeComponent();
        RefreshList();
    }

    private void AddStorage_Click(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFolderDialog
        {
            Title = "选择要登记的 U 盘、移动硬盘或读卡器盘符",
            Multiselect = false,
        };
        if (picker.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var preview = _service.PreviewStorageDevice(picker.FolderName);
            var nameDialog = new DeviceNameDialog { Owner = this };
            if (nameDialog.ShowDialog() != true)
            {
                return;
            }

            if (MessageBox.Show(
                    this,
                    $"准备登记：\n\n名称：{nameDialog.DeviceName}\n型号：{preview.Model}\n容量：{FormatByteSize(preview.CapacityBytes)}\n部分编号：{preview.ShortId}\n\n" +
                    "程序将在所选外接存储中写入一份隐藏的物理密钥凭证。格式化设备会让授权永久失效；设备丢失且没有其他已授权设备时，加密内容无法恢复。\n\n确定继续吗？",
                    "确认登记物理设备",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No) != MessageBoxResult.Yes)
            {
                return;
            }

            var registered = _service.RegisterStorageDevice(picker.FolderName, nameDialog.DeviceName);
            RefreshList(registered.Id);
        }
        catch (Exception exception)
        {
            ShowError("无法登记移动存储", exception);
        }
    }

    private async void AddFido_Click(object sender, RoutedEventArgs e)
    {
        var nameDialog = new DeviceNameDialog { Owner = this };
        if (nameDialog.ShowDialog() != true)
        {
            return;
        }

        if (MessageBox.Show(
                this,
                "接下来 Windows 会要求您插入 FIDO2 安全密钥，并输入安全密钥 PIN 或完成生物识别。只有同时支持 HMAC-secret/PRF 和 PIN/生物验证的外接安全密钥可以登记；仅触摸确认的设备不能使用，也不会改用较弱方式。\n\n设备丢失且没有其他已授权设备时，加密内容无法恢复。确定继续吗？",
                "确认登记 FIDO2 安全密钥",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            var handle = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            var registered = await _service.RegisterFido2DeviceAsync(nameDialog.DeviceName, handle);
            RefreshList(registered.Id);
        }
        catch (Exception exception)
        {
            ShowError("无法登记 FIDO2 安全密钥", exception);
        }
    }

    private void Rename_Click(object sender, RoutedEventArgs e)
    {
        if (DeviceList.SelectedItem is not PhysicalDeviceDescriptor selected)
        {
            MessageBox.Show(this, "请先选择一个设备。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new DeviceNameDialog(selected.Name) { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            _service.RenameDevice(selected.Id, dialog.DeviceName);
            RefreshList(selected.Id);
        }
        catch (Exception exception)
        {
            ShowError("无法重命名设备", exception);
        }
    }

    private void Forget_Click(object sender, RoutedEventArgs e)
    {
        if (DeviceList.SelectedItem is not PhysicalDeviceDescriptor selected)
        {
            MessageBox.Show(this, "请先选择一个设备。", AppName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MessageBox.Show(
                this,
                $"要把“{selected.Name}”从本机清单移除吗？\n\n这不会删除已有加密文件，也不会制作恢复后门；设备仍可用于它过去已获授权的文件。",
                "确认从清单移除",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            _service.ForgetDevice(selected.Id);
            RefreshList();
        }
        catch (Exception exception)
        {
            ShowError("无法从清单移除设备", exception);
        }
    }

    private void RefreshList(string? selectedId = null)
    {
        var devices = _service.ListRegisteredDevices();
        DeviceList.ItemsSource = devices;
        DeviceList.SelectedItem = devices.FirstOrDefault(device =>
            string.Equals(device.Id, selectedId, StringComparison.Ordinal));
    }

    private void ShowError(string title, Exception exception) => MessageBox.Show(
        this,
        $"{title}：\n\n{exception.Message}",
        AppName,
        MessageBoxButton.OK,
        MessageBoxImage.Error);

    private static string FormatByteSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.##} {units[unit]}";
    }
}
