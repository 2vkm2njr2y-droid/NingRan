using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

public partial class DeliveryWizardWindow : Window
{
    private readonly NrArchiveService _archiveService = new();
    private readonly NrIdentityService _identityService = new();
    private readonly NrTrustedContactService _contactService = new();
    private readonly NrPhysicalDeviceService _physicalDeviceService = new();
    private readonly RecentDeliveryHistory _recentDeliveryHistory = new();
    private readonly List<string> _sources = [];
    private int _page;
    private string? _createdPath;
    private string? _receiverInstructions;

    public DeliveryWizardWindow()
        : this(loadChoices: true)
    {
    }

    internal DeliveryWizardWindow(bool loadChoices)
    {
        InitializeComponent();
        if (loadChoices) LoadChoices();
        ShowPage(0);
    }

    public string? CreatedPath => _createdPath;

    private void LoadChoices()
    {
        try
        {
            SigningIdentityCombo.ItemsSource = _identityService.ListLocalIdentities();
            SigningIdentityCombo.SelectedIndex = SigningIdentityCombo.Items.Count > 0 ? 0 : -1;
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"无法读取发送者身份：\n\n{exception.Message}", Title,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        try
        {
            var contacts = new List<DeliveryContactChoice> { new(null) };
            contacts.AddRange(_contactService.ListTrustedContacts().Select(contact => new DeliveryContactChoice(contact)));
            RecipientCombo.ItemsSource = contacts;
            RecipientCombo.SelectedIndex = 0;
        }
        catch (Exception exception)
        {
            RecipientCombo.ItemsSource = new[] { new DeliveryContactChoice(null) };
            RecipientCombo.SelectedIndex = 0;
            MessageBox.Show(this, $"无法读取可信联系人：\n\n{exception.Message}", Title,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        try
        {
            PhysicalDeviceList.ItemsSource = _physicalDeviceService.ListRegisteredDevices();
        }
        catch
        {
            PhysicalDeviceList.ItemsSource = Array.Empty<PhysicalDeviceDescriptor>();
        }
    }

    private void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "选择要安全交付的文件",
            Multiselect = true,
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        AddSources(dialog.FileNames);
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择要安全交付的文件夹",
            Multiselect = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        AddSources(dialog.FolderNames);
    }

    private void AddSources(IEnumerable<string> paths)
    {
        foreach (var path in paths.Select(Path.GetFullPath))
        {
            if (!_sources.Contains(path, StringComparer.OrdinalIgnoreCase)) _sources.Add(path);
        }

        RefreshSources();
    }

    private void RemoveSource_Click(object sender, RoutedEventArgs e)
    {
        foreach (var selected in SourceList.SelectedItems.Cast<string>().ToArray())
        {
            _sources.RemoveAll(path => string.Equals(path, selected, StringComparison.OrdinalIgnoreCase));
        }

        RefreshSources();
    }

    private void RefreshSources()
    {
        SourceList.ItemsSource = null;
        SourceList.ItemsSource = _sources;
        var fileCount = _sources.Count(File.Exists);
        var folderCount = _sources.Count(Directory.Exists);
        SourceSummary.Text = _sources.Count == 0
            ? "尚未选择资料。"
            : $"已选择 {fileCount:N0} 个文件、{folderCount:N0} 个顶层文件夹。子文件夹和空文件夹会完整保留。";
    }

    private void ProtectionMode_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (KeyFilePanel is null || PhysicalDevicePanel is null) return;
        KeyFilePanel.Visibility = ProtectionModeCombo.SelectedIndex == 1 ? Visibility.Visible : Visibility.Collapsed;
        PhysicalDevicePanel.Visibility = ProtectionModeCombo.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void PickKeyFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "选择密匙文件", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) KeyFilePathInput.Text = dialog.FileName;
    }

    private void PickOutput_Click(object sender, RoutedEventArgs e)
    {
        var suggested = MakeSafeFileName(DeliveryNameInput.Text);
        var dialog = new SaveFileDialog
        {
            Title = "保存安全交付包",
            Filter = "凝然安全交付包 (*.nrenc)|*.nrenc",
            DefaultExt = ".nrenc",
            AddExtension = true,
            FileName = string.IsNullOrWhiteSpace(suggested) ? "安全交付.nrenc" : suggested + ".nrenc",
        };
        if (dialog.ShowDialog(this) == true) OutputPathInput.Text = dialog.FileName;
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_page > 0 && _page < 5) ShowPage(_page - 1);
    }

    private async void Next_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_page == 5)
            {
                DialogResult = true;
                return;
            }

            if (!ValidatePage(_page)) return;
            if (_page < 4)
            {
                if (_page == 0 && string.IsNullOrWhiteSpace(DeliveryNameInput.Text))
                {
                    DeliveryNameInput.Text = _sources.Count == 1
                        ? Path.GetFileName(_sources[0].TrimEnd(Path.DirectorySeparatorChar))
                        : $"资料交付 {DateTime.Now:yyyy-MM-dd}";
                }

                ShowPage(_page + 1);
                return;
            }

            await GenerateAsync();
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"无法继续：\n\n{FriendlyMessage(exception)}", Title,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private bool ValidatePage(int page)
    {
        switch (page)
        {
            case 0:
                if (_sources.Count == 0)
                {
                    ShowNotice("请至少添加一个文件或文件夹。");
                    return false;
                }

                var missing = _sources.FirstOrDefault(path => !File.Exists(path) && !Directory.Exists(path));
                if (missing is not null)
                {
                    ShowNotice($"所选项目已经不存在：\n\n{missing}");
                    return false;
                }
                break;
            case 1:
                try
                {
                    _ = DeliveryPackageInfo.Create(DeliveryNameInput.Text, DeliveryDescriptionInput.Text,
                        DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), true,
                        (RecipientCombo.SelectedItem as DeliveryContactChoice)?.Contact);
                }
                catch (Exception exception)
                {
                    ShowNotice(FriendlyMessage(exception));
                    return false;
                }
                break;
            case 2:
                using (var password = SensitivePassword.FromSecureString(PasswordInput.SecurePassword))
                using (var confirmation = SensitivePassword.FromSecureString(ConfirmPasswordInput.SecurePassword))
                {
                    if (password.IsEmpty || !password.FixedTimeEquals(confirmation))
                    {
                        ShowNotice(password.IsEmpty ? "请输入交付密码。" : "两次输入的交付密码不一致。");
                        return false;
                    }
                }

                if (SigningIdentityCombo.SelectedItem is not IdentitySummary || SigningPasswordInput.SecurePassword.Length == 0)
                {
                    ShowNotice("请选择发送者身份并输入身份密码。没有身份时，请先回到主窗口创建身份。");
                    return false;
                }

                if (ProtectionModeCombo.SelectedIndex == 1 && !File.Exists(KeyFilePathInput.Text))
                {
                    ShowNotice("请选择存在的密匙文件。");
                    return false;
                }

                if (ProtectionModeCombo.SelectedIndex == 2 && PhysicalDeviceList.SelectedItems.Count == 0)
                {
                    ShowNotice("请至少选择一个已经登记的物理设备。");
                    return false;
                }
                break;
            case 4:
                if (string.IsNullOrWhiteSpace(OutputPathInput.Text))
                {
                    PickOutput_Click(this, new RoutedEventArgs());
                    if (string.IsNullOrWhiteSpace(OutputPathInput.Text)) return false;
                }
                break;
        }

        return true;
    }

    private void ShowPage(int page)
    {
        _page = page;
        SourcePage.Visibility = page == 0 ? Visibility.Visible : Visibility.Collapsed;
        InfoPage.Visibility = page == 1 ? Visibility.Visible : Visibility.Collapsed;
        ProtectionPage.Visibility = page == 2 ? Visibility.Visible : Visibility.Collapsed;
        RulesPage.Visibility = page == 3 ? Visibility.Visible : Visibility.Collapsed;
        ReviewPage.Visibility = page == 4 ? Visibility.Visible : Visibility.Collapsed;
        ResultPage.Visibility = page == 5 ? Visibility.Visible : Visibility.Collapsed;

        string[] titles =
        [
            "第 1 步，共 5 步：选择资料",
            "第 2 步，共 5 步：填写交付信息",
            "第 3 步，共 5 步：设置密码和保护方式",
            "第 4 步，共 5 步：设置有效期和导出规则",
            "第 5 步，共 5 步：检查并生成",
            "生成完成",
        ];
        StepTitle.Text = titles[page];
        StepBadge.Text = page == 5 ? "完成" : $"{page + 1} / 5";
        BackButton.Visibility = page is > 0 and < 5 ? Visibility.Visible : Visibility.Hidden;
        CancelButton.Visibility = page == 5 ? Visibility.Collapsed : Visibility.Visible;
        NextButton.Content = page switch { 4 => "生成交付包", 5 => "完成", _ => "下一步" };

        if (page == 4) RefreshReview();
    }

    private void RefreshReview()
    {
        var recipient = (RecipientCombo.SelectedItem as DeliveryContactChoice)?.Contact;
        var expires = GetExpirationDays();
        var mode = ProtectionModeCombo.SelectedIndex switch
        {
            1 => "密码＋密匙文件",
            2 => "密码＋物理设备",
            _ => "只使用密码",
        };
        ReviewText.Text =
            $"交付名称：{DeliveryNameInput.Text.Trim()}\r\n" +
            $"资料：{_sources.Count:N0} 个顶层项目\r\n" +
            $"接收对象：{recipient?.Name ?? "未指定"}\r\n" +
            $"保护方式：{mode}\r\n" +
            $"有效期：{(expires == 0 ? "永久有效" : expires + " 天")}\r\n" +
            $"允许导出：{(AllowExportCheck.IsChecked == true ? "是" : "否")}\r\n\r\n" +
            "生成前会检查所选资料、保存位置和可用空间；生成后会重新读取并完整验证交付包。原始资料不会被修改。";
    }

    private async Task GenerateAsync()
    {
        using var password = SensitivePassword.FromSecureString(PasswordInput.SecurePassword);
        using var confirmation = SensitivePassword.FromSecureString(ConfirmPasswordInput.SecurePassword);
        if (!password.FixedTimeEquals(confirmation))
        {
            ShowNotice("两次输入的交付密码不一致。");
            return;
        }

        var assessment = PasswordRules.Assess(password);
        if (assessment.HasWarnings)
        {
            var warning = string.Join("\n", assessment.Warnings.Select(item => "• " + item));
            if (MessageBox.Show(this, $"这个密码有以下风险：\n\n{warning}\n\n仍要继续吗？", Title,
                    MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }
        }

        var outputPath = Path.GetFullPath(OutputPathInput.Text);
        if (!string.Equals(Path.GetExtension(outputPath), ".nrenc", StringComparison.OrdinalIgnoreCase))
            outputPath += ".nrenc";
        if (File.Exists(outputPath) || Directory.Exists(outputPath))
        {
            ShowNotice("保存位置已经有同名内容，请更换名称。");
            return;
        }

        var sourceBytes = await Task.Run(() => InspectSources(_sources));
        EnsureEnoughSpace(outputPath, sourceBytes);
        var createdAt = DateTimeOffset.UtcNow;
        var days = GetExpirationDays();
        var info = DeliveryPackageInfo.Create(
            DeliveryNameInput.Text,
            DeliveryDescriptionInput.Text,
            createdAt,
            days == 0 ? null : createdAt.AddDays(days),
            AllowExportCheck.IsChecked == true,
            (RecipientCombo.SelectedItem as DeliveryContactChoice)?.Contact);
        var identity = (IdentitySummary)SigningIdentityCombo.SelectedItem;
        using var signingPassword = SensitivePassword.FromSecureString(SigningPasswordInput.SecurePassword);
        var mode = ProtectionModeCombo.SelectedIndex switch
        {
            1 => EncryptionMode.Advanced,
            2 => EncryptionMode.PhysicalDevice,
            _ => EncryptionMode.Standard,
        };
        var devices = PhysicalDeviceList.SelectedItems.Cast<PhysicalDeviceDescriptor>().ToArray();
        using var request = new EncryptRequest(
            _sources,
            outputPath,
            password,
            info,
            mode,
            mode == EncryptionMode.Advanced ? KeyFilePathInput.Text : null,
            SizePaddingMode.None,
            ArchiveCompressionLevel.Standard,
            identity.Id,
            signingPassword,
            mode == EncryptionMode.PhysicalDevice ? devices : null,
            new WindowInteropHelper(this).Handle);

        using var cancellation = new CancellationTokenSource();
        var progressWindow = new ProgressWindow(true, "正在生成安全交付包") { Owner = this };
        progressWindow.CancelRequested += (_, _) => cancellation.Cancel();
        var progress = new Progress<CryptoProgress>(progressWindow.UpdateProgress);
        IsEnabled = false;
        progressWindow.Show();
        try
        {
            var result = await _archiveService.EncryptAsync(request, progress, cancellation.Token);
            _createdPath = result.ArchivePath;
            _recentDeliveryHistory.Add(result.ArchivePath, info.CreatedAtUtc, info.ExpiresAtUtc,
                verificationPassed: true);
            OperationLog.Append("生成安全交付", result.ArchivePath, "成功",
                $"顶层项目={_sources.Count}; 有效期={(days == 0 ? "永久" : days + "天")}; 允许导出={info.AllowExport}");
            _receiverInstructions = "请安装凝然后打开此安全交付包，并使用我通过其他安全方式单独告知你的密码。";
            ResultText.Text =
                $"{Path.GetFileName(result.ArchivePath)}\n" +
                $"{_sources.Count:N0} 个顶层项目；{(days == 0 ? "永久有效" : $"{days} 天有效")}；" +
                $"{(info.AllowExport ? "允许导出" : "禁止导出")}。";
            ShowPage(5);
        }
        catch (OperationCanceledException)
        {
            OperationLog.Append("生成安全交付", outputPath, "已取消");
            ShowNotice("已取消生成，未完成文件已清理，原始资料没有改动。");
        }
        catch (Exception exception)
        {
            OperationLog.Append("生成安全交付", outputPath, "失败", FriendlyMessage(exception));
            MessageBox.Show(this, $"安全交付包没有生成：\n\n{FriendlyMessage(exception)}", Title,
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            progressWindow.CloseAfterOperation();
            IsEnabled = true;
            Activate();
        }
    }

    private static long InspectSources(IEnumerable<string> sources)
    {
        long total = 0;
        foreach (var source in sources)
        {
            if (File.Exists(source))
            {
                using var stream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read,
                    bufferSize: 1, FileOptions.SequentialScan);
                total = checked(total + stream.Length);
                continue;
            }

            if (!Directory.Exists(source)) throw new NingRanException($"所选项目已经不存在：{source}");
            try
            {
                foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
                {
                    using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read,
                        bufferSize: 1, FileOptions.SequentialScan);
                    total = checked(total + stream.Length);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new NingRanException($"无法读取所选资料：{source}", exception);
            }
        }

        return total;
    }

    private static void EnsureEnoughSpace(string outputPath, long sourceBytes)
    {
        var root = Path.GetPathRoot(outputPath);
        if (string.IsNullOrWhiteSpace(root)) throw new NingRanException("保存位置不正确。");
        var drive = new DriveInfo(root);
        var required = checked(sourceBytes + 128L * 1024 * 1024);
        if (drive.IsReady && drive.AvailableFreeSpace < required)
        {
            throw new NingRanException("目标磁盘剩余空间不足。请清理空间或选择其他保存位置。");
        }
    }

    private int GetExpirationDays() =>
        ExpirationCombo.SelectedItem is ComboBoxItem { Tag: string tag } && int.TryParse(tag, out var days)
            ? days
            : 30;

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (_createdPath is null) return;
        var start = new ProcessStartInfo("explorer.exe") { UseShellExecute = true };
        start.ArgumentList.Add($"/select,{_createdPath}");
        Process.Start(start);
    }

    private void CopyInstructions_Click(object sender, RoutedEventArgs e)
    {
        if (_receiverInstructions is null) return;
        Clipboard.SetText(_receiverInstructions);
        MessageBox.Show(this, "接收说明已复制。请通过与交付包不同的安全方式告诉对方密码。", Title,
            MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ShowNotice(string message) =>
        MessageBox.Show(this, message, Title, MessageBoxButton.OK, MessageBoxImage.Information);

    private static string FriendlyMessage(Exception exception) => exception is NingRanException
        ? exception.Message
        : exception.InnerException?.Message ?? exception.Message;

    private static string MakeSafeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var result = new string(value.Trim().Select(character => invalid.Contains(character) ? '＿' : character).ToArray())
            .TrimEnd(' ', '.');
        return result.Length > 80 ? result[..80].TrimEnd(' ', '.') : result;
    }

    private sealed record DeliveryContactChoice(TrustedContactSummary? Contact)
    {
        public string DisplayText => Contact is null ? "不指定联系人，只使用密码交付" : $"{Contact.Name}（已确认）";
    }
}
