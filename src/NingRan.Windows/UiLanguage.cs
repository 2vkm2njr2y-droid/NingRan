using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NingRan.Windows;

internal static class UiLanguage
{
    private static readonly ConditionalWeakTable<Window, object> AppliedWindows = new();

    private static readonly IReadOnlyDictionary<string, string> EnglishText =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["凝然加密"] = "NingRan Encryption", ["凝然加密帮助文档"] = "NingRan Encryption Help", ["您的文件，只属于您"] = "Your files belong to you",
            ["严格防护"] = "Strict Protection", ["设置严格防护和允许的软件"] = "Configure Strict Protection and allowed software", ["帮助文档"] = "Help", ["打开使用说明、隐私条件和免责声明"] = "Open usage instructions, privacy terms, and disclaimer",
            ["最小化"] = "Minimize", ["最大化"] = "Maximize", ["关闭"] = "Close", ["选择需要保护或还原的内容"] = "Choose content to protect or restore", ["支持单个文件或整个文件夹，大于 10 GB 也可以正常处理。"] = "Single files and folders are supported, including files larger than 10 GB.", ["把文件或文件夹拖到这里"] = "Drop a file or folder here", ["也可以点击下方按钮选择"] = "Or choose one with a button below", ["选择文件"] = "Choose file", ["选择文件夹"] = "Choose folder", ["尚未选择"] = "Nothing selected",
            ["操作设置"] = "Operation settings", ["加密"] = "Encrypt", ["解密"] = "Decrypt", ["保护模式"] = "Protection mode", ["普通模式"] = "Standard", ["只使用密码"] = "Password only", ["高级模式"] = "Advanced", ["密码＋密钥"] = "Password + key", ["物理设备"] = "Physical device", ["密码＋设备"] = "Password + device", ["密码"] = "Password", ["再次输入"] = "Confirm",
            ["建议使用至少 16 个字符的口令短语；较弱密码会提示，但可自行决定继续。"] = "Use a passphrase of at least 16 characters. Weak passwords are flagged, but you decide whether to continue.", ["密匙文件（任意普通文件或 .nrkey）"] = "Key file (any regular file or .nrkey)", ["选择"] = "Choose", ["生成新版密钥文件"] = "Create new key file", ["授权物理设备（可多选）"] = "Authorized physical devices (multiple)", ["管理设备"] = "Manage devices", ["加密时需逐一出示所有所选设备；解密时插入其中任意一个并输入密码即可。全部设备丢失后无法恢复。"] = "All selected devices are required for encryption. Any one device plus the password can decrypt. Lost devices cannot be recovered.",
            ["大小隐藏"] = "Size hiding", ["不隐藏大小"] = "Do not hide size", ["粗略补齐（最多额外约 64 MB）"] = "Rough padding (up to about 64 MB)", ["固定补到约 100 MB"] = "Pad to about 100 MB", ["固定补到约 1 GB"] = "Pad to about 1 GB", ["固定补到约 10 GB"] = "Pad to about 10 GB", ["开始前会显示预计额外占用空间；固定容量小于原内容时不会缩小文件。"] = "Estimated extra space is shown before starting. A target smaller than the original never shrinks the file.",
            ["压缩等级"] = "Compression level", ["存储（不压缩）"] = "Store (no compression)", ["最快（优先速度）"] = "Fastest (speed first)", ["标准（平衡速度和体积）"] = "Standard (balanced)", ["最大（优先减小体积）"] = "Best (size first)", ["每个分段都会比较压缩结果和原始数据，自动保存较小的一份。"] = "Each segment is compared with its original and the smaller result is stored.", ["证明发送者身份（安全要求，必须启用）"] = "Prove sender identity (required for security)", ["发送者身份"] = "Sender identity", ["创建身份"] = "Create identity", ["导入备份"] = "Import backup", ["导出私密备份"] = "Export private backup", ["导出公开身份"] = "Export public identity", ["删除身份"] = "Delete identity", ["身份密码"] = "Identity password", ["这是创建身份时设置的独立密码。"] = "This is the separate password set when the identity was created.",
            ["选择加密文件后只显示必要的公开信息。"] = "Only necessary public information is shown after an encrypted file is selected.", ["请输入加密时使用的密码。"] = "Enter the password used during encryption.", ["密匙文件（仅高级模式需要；不确定时可暂不选择）"] = "Key file (required only for Advanced mode)", ["物理设备"] = "Physical device", ["如使用了物理设备保护，请插入获授权设备。FIDO2 密钥必须按 Windows 提示输入安全密钥 PIN 或完成生物识别。"] = "Insert an authorized device if physical-device protection was used. FIDO2 keys require a PIN or biometric verification when Windows asks.", ["可信发送者联系人"] = "Trusted sender contact", ["导入公开身份"] = "Import public identity", ["管理"] = "Manage", ["解密时会自动核验本机可信联系人。"] = "Trusted contacts are checked automatically during decryption.",
            ["已安全打开"] = "Opened securely", ["加密文件中的内容"] = "Contents of encrypted file", ["单独解密副本…"] = "Decrypt a separate copy…", ["从加密文件中删除…"] = "Remove from encrypted file…", ["修改后发送者身份"] = "Sender identity after editing", ["加密文件密码"] = "Encrypted-file password", ["导出全部明文"] = "Export all plaintext", ["追加文件"] = "Append files", ["关闭安全查看"] = "Close secure view", ["保存位置"] = "Save location", ["默认保存在原位置；同名内容会自动改名保留。"] = "Saved beside the original by default; duplicate names are kept with an automatic suffix.", ["开始加密"] = "Start encryption", ["高安全打开（管理员确认）"] = "High-security open (administrator confirmation)",
            ["物理设备管理"] = "Physical device management", ["登记 U 盘/移动硬盘"] = "Register USB/removable drive", ["登记 FIDO2 安全密钥"] = "Register FIDO2 security key", ["重命名"] = "Rename", ["从清单移除"] = "Remove from list", ["完成"] = "Done", ["取消"] = "Cancel", ["确定"] = "OK", ["设备名称"] = "Device name", ["给这台设备起一个容易辨认的名称"] = "Give this device an easy-to-recognize name", ["例如：老大的随身 U 盘、办公室备用密钥"] = "For example: Travel USB drive or office backup key",
            ["创建发送者身份"] = "Create sender identity", ["身份名称"] = "Identity name", ["再次输入身份密码"] = "Confirm identity password", ["正在处理"] = "Processing", ["请不要关闭电脑或移动正在处理的文件"] = "Do not shut down or move files while processing", ["正在准备…"] = "Preparing…", ["正在加强密码保护"] = "Strengthening password protection", ["正在加密并验证"] = "Encrypting and verifying", ["正在验证并解密"] = "Verifying and decrypting", ["正在更新加密文件"] = "Updating encrypted file", ["预计剩余"] = "Estimated remaining", ["已等待"] = "Elapsed", ["正在取消并清理未完成内容…"] = "Cancelling and cleaning up incomplete content…", ["原文件不会被改动"] = "The original file will not be changed", ["正在写入加密内容"] = "Writing encrypted content", ["正在检查所选内容"] = "Checking selected content", ["正在检查加密结果"] = "Checking encrypted result", ["正在还原内容"] = "Restoring content", ["正在完成保存"] = "Finishing save", ["管理员核对公开身份"] = "Administrator identity verification", ["管理员确认：核对发送者安全码"] = "Administrator confirmation: verify sender code", ["公开身份名称"] = "Public identity name", ["7 位安全码"] = "7-character security code", ["核对并信任"] = "Verify and trust",
            ["凝然安全媒体查看"] = "NingRan secure media view", ["凝然加密 · 安全媒体播放器"] = "NingRan Encryption · Secure media player", ["不保存明文，文件只在内存中按需读取"] = "No plaintext is saved; data is read on demand in memory", ["不保存明文"] = "No plaintext saved", ["文件列表"] = "File list", ["全部媒体"] = "All media", ["图片"] = "Images", ["视频"] = "Video", ["音频"] = "Audio", ["文本"] = "Text", ["媒体"] = "Media", ["播放结束后"] = "After playback", ["播放结束后："] = "After playback: ", ["停止"] = "Stop", ["播完停止"] = "Stop", ["自动下一项"] = "Play next", ["循环当前项"] = "Repeat item", ["循环整个列表"] = "Repeat list", ["请选择左侧文件"] = "Select a file on the left", ["正在生成预览…"] = "Generating preview…", ["预览暂不可用"] = "Preview unavailable", ["正在缓冲视频…"] = "Buffering video…", ["音量"] = "Volume", ["正在安全加载视频…"] = "Loading video securely…", ["缩放"] = "Zoom", ["还原"] = "Reset", ["全屏"] = "Full screen", ["播放或暂停"] = "Play or pause", ["播放进度"] = "Playback position", ["循环播放"] = "Loop", ["上一项"] = "Previous", ["下一项"] = "Next", ["后退 10 秒"] = "Back 10 seconds", ["前进 30 秒"] = "Forward 30 seconds", ["媒体无法解码或读取。"] = "Media could not be decoded or read.",
            ["凝然加密 · 安全 PDF 查看"] = "NingRan Encryption · Secure PDF view", ["安全查看：PDF 仅通过加密会话按需读取，不会导出普通文件。"] = "Secure view: PDF is read on demand through the encrypted session and is not exported as a regular file.", ["凝然加密 - 安全提醒"] = "NingRan Encryption - Security notice", ["凝然加密 · 安全提醒"] = "NingRan Encryption · Security notice", ["已停止高权限启动"] = "Elevated launch stopped", ["安全退出"] = "Exit safely", ["管理可信联系人"] = "Manage trusted contacts", ["可信发送者联系人"] = "Trusted sender contacts", ["重新核对"] = "Verify again", ["删除所选联系人"] = "Remove selected contact",
            ["双击图片、音频、视频或文本将在程序内打开；双击普通文件可选择位置导出。"] = "Double-click images, audio, video, or text to open them in the app. Double-click other files to choose an export location.", ["删除或追加后会用此身份重新签名。高级模式还会使用打开文件时选择的密匙。"] = "After removal or appending, the archive is re-signed with this identity. Advanced mode also uses the key selected when the file was opened.", ["图片可按住 Ctrl 并滚动鼠标滚轮缩放；放大后可直接拖动图片。"] = "Hold Ctrl and scroll the mouse wheel to zoom images. Drag an image after zooming.", ["点击画面暂停或继续　← / → 调整播放进度　双击画面全屏"] = "Click the picture to pause or resume; use Left/Right to seek; double-click for full screen", ["在单独的管理员窗口中重新输入解锁材料，不会传递密码或密匙"] = "Re-enter unlock material in a separate administrator window. Passwords and keys are not transferred.",
            ["身份用于证明加密文件由谁制作。私密身份会加密保存在本机。"] = "An identity proves who created an encrypted file. Private identities are encrypted on this computer.", ["例如姓名、昵称或组织名称，由您自行填写。"] = "For example, a name, nickname, or organization.",
            ["登记后可把设备加入新的物理设备加密文件。普通移动存储可被有能力的人复制，因此保护强度低于 FIDO2 安全密钥。完整设备编号不会显示。"] = "Registered devices can protect new physical-device archives. Removable storage can be copied, so it is weaker than a FIDO2 security key. Full device identifiers are never shown.", ["程序不会显示正确答案。请通过电话、当面或其他独立可信方式，向发送者取得安全码。"] = "The correct answer is never shown. Obtain the code from the sender by phone, in person, or another independent trusted method.", ["只能输入英文字母，严格区分大写和小写。"] = "Enter letters only. Uppercase and lowercase are different.", ["安全码不匹配，请向发送者重新核对后再试。"] = "The code does not match. Check it with the sender and try again.", ["点击“核对并信任”表示您明确同意把该身份加入可信联系人。"] = "Selecting Verify and trust confirms that you want to add this identity as a trusted contact.",
            ["受保护联系人只能经 Windows 管理员确认后新增或删除。升级前的旧记录会保留，但重新核对前不会被信任。"] = "Protected contacts can be added or removed only after Windows administrator confirmation. Older records remain but are not trusted until verified again.", ["请选择一个联系人查看确认时间。"] = "Select a contact to view its verification time.",
            ["目录"] = "Contents", ["开始使用"] = "Getting started", ["查看、导出与修改"] = "View, export, and edit", ["密码、密匙与身份"] = "Passwords, keys, and identities", ["隐私与本地处理"] = "Privacy and local processing", ["严格防护与高安全打开"] = "Strict Protection and high-security open", ["安全边界与免责声明"] = "Safety boundaries and disclaimer",
            ["严格防护设置"] = "Strict Protection settings", ["开启严格防护监控（下次启动会自动请求管理员确认）"] = "Enable Strict Protection monitoring (administrator confirmation will be requested next time)", ["导出安全日志"] = "Export security log", ["保存"] = "Save", ["安全说明"] = "Security notes", ["导出严格防护日志"] = "Export Strict Protection log", ["日志文件|*.jsonl"] = "Log files|*.jsonl", ["安全日志已经导出。日志不包含密码、密匙或文件内容。"] = "The security log was exported. It contains no passwords, keys, or file contents.", ["无法导出安全日志"] = "Could not export security log",
            ["监控程序单独申请管理员权限，并定期检查主窗口、内嵌播放器、预览画面和自身。发现不在允许名单内的软件仍持有读取权限时，会记录事件、停止当前操作并清理临时明文。它用于发现和缩短风险，不能保证拦截一次极短的读取。"] = "The monitor requests administrator permission separately and periodically checks the main window, embedded player, preview surface, and itself. If unapproved software still has read access, it records the event, stops the current operation, and cleans temporary plaintext. It helps detect and shorten exposure but cannot guarantee blocking an extremely brief read.", ["为防止恶意程序伪装成合法软件，严格防护不会自动或手动放行任何外部进程。安全软件或辅助工具若读取受保护内存，也会触发提醒。"] = "To prevent malicious software from impersonating legitimate software, Strict Protection never automatically or manually allows external processes. Security software or assistive tools that read protected memory also trigger an alert.",
            ["内置播放器无法启动："] = "Built-in player could not start: ", ["无法在程序内打开此文件："] = "Could not open this file in the app: ", ["播放器已停止，您已回到文件列表。"] = "Playback stopped. You are back at the file list.", ["播放器出现错误"] = "Player error", ["内嵌安全播放器"] = "Embedded secure player", ["无法打开媒体"] = "Could not open media", ["安全媒体查看"] = "Secure media view", ["该文件不是可直接查看的媒体类型。"] = "This file is not a directly viewable media type.", ["内置播放组件不完整，请重新安装最新版凝然加密。"] = "Built-in playback components are incomplete. Please reinstall the latest NingRan Encryption.", ["播放核心尚未准备好，请稍后重试。"] = "The playback core is not ready. Please try again later.", ["播放核心未能开始读取媒体。"] = "The playback core could not start reading this media.", ["播放核心无法继续读取或解码此媒体。"] = "The playback core could not continue reading or decoding this media.", ["媒体信息在 60 秒内未能准备完成，已停止播放以避免窗口卡死。"] = "Media information was not ready within 60 seconds. Playback stopped to keep the window responsive.", ["授权物理设备已被拔出或发生变化，安全查看将关闭。"] = "The authorized physical device was removed or changed. Secure view will close.", ["不支持的媒体读取范围。"] = "This media range is not supported.", ["媒体读取范围不正确。"] = "The media range is invalid.", ["媒体读取位置超出范围。"] = "The media read position is out of range.",
            ["凝然加密 · 安全 PDF 查看"] = "NingRan Encryption · Secure PDF view", ["安全查看：PDF 仅通过加密会话按需读取，不会导出普通文件。"] = "Secure view: PDF is read on demand through the encrypted session and is not exported as a regular file.", ["内嵌 PDF 查看"] = "Embedded PDF view", ["无法启动内嵌 PDF 查看："] = "Could not start embedded PDF view: ",
            ["导出报告"] = "Export report", ["关闭"] = "Close", ["已生成临时详细报告。报告不包含密码、密钥、文件内容或本机完整路径；您可以现在导出。关闭此窗口后报告会自动删除。"] = "A temporary detailed report was generated. It contains no passwords, keys, file contents, or full local paths; you can export it now. The report is deleted when this window closes.", ["导出错误报告"] = "Export error report", ["报告文件|*.json"] = "Report files|*.json", ["错误报告已导出。"] = "The error report was exported.", ["无法导出错误报告"] = "Could not export error report",
            ["高安全查看必须经 Windows 管理员确认启动。请从普通窗口的“高安全打开”按钮重新开始。"] = "High-security view must be started after Windows administrator confirmation. Restart it from the High-security open button in the ordinary window.", ["严格防护设置必须由受保护安装位置中的凝然加密，经 Windows 管理员确认后修改。"] = "Strict Protection settings can only be changed by NingRan Encryption from a protected installation location after Windows administrator confirmation.", ["严格防护设置需要修复"] = "Strict Protection settings need repair", ["保存后会重新建立只有管理员可修改的设置。"] = "Saving will recreate settings that only administrators can modify.", ["严格防护设置没有保存："] = "Strict Protection settings were not saved: ", ["凝然加密 - 管理员确认"] = "NingRan Encryption - Administrator confirmation", ["凝然加密 - 严格防护设置需要修复"] = "NingRan Encryption - Strict Protection settings need repair",
        };

    public static bool IsEnglish { get; } = ReadMarker();
    public static string ProductName => IsEnglish ? "NingRan Encryption" : "凝然加密";

    public static string Translate(string? value)
    {
        if (!IsEnglish || string.IsNullOrEmpty(value)) return value ?? string.Empty;
        return EnglishText.TryGetValue(value, out var translated) ? translated : value;
    }

    public static void Apply(Window window)
    {
        if (!IsEnglish) return;
        // Loaded can be raised again when a ComboBox popup creates its item containers.
        // Reapplying translated content at that point resets the native selection.
        if (!AppliedWindows.TryAdd(window, new object())) return;
        window.Title = Translate(window.Title);
        ApplyVisual(window);
    }

    private static void ApplyVisual(DependencyObject root)
    {
        if (root is TextBlock textBlock) textBlock.Text = Translate(textBlock.Text);
        if (root is ContentControl contentControl && contentControl.Content is string content)
            contentControl.Content = Translate(content);
        if (root is HeaderedContentControl headered && headered.Header is string header)
            headered.Header = Translate(header);
        if (root is FrameworkElement element && element.ToolTip is string tooltip)
            element.ToolTip = Translate(tooltip);
        if (root is ComboBox comboBox)
        {
            var selectedIndex = comboBox.SelectedIndex;
            foreach (var item in comboBox.Items)
            {
                if (item is DependencyObject itemObject)
                    ApplyVisual(itemObject);
            }

            // WPF caches the selection-box content. Reassign the same index after
            // translating item content so the closed ComboBox shows the real choice.
            if (selectedIndex >= 0 && selectedIndex < comboBox.Items.Count &&
                comboBox.Items[selectedIndex] is ComboBoxItem)
            {
                comboBox.SelectedIndex = -1;
                comboBox.SelectedIndex = selectedIndex;
            }
        }
        else if (root is ItemsControl itemsControl)
        {
            foreach (var item in itemsControl.Items)
            {
                if (item is DependencyObject itemObject)
                    ApplyVisual(itemObject);
            }
        }
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            ApplyVisual(VisualTreeHelper.GetChild(root, i));
    }

    private static bool ReadMarker()
    {
        try
        {
            var directory = Path.GetDirectoryName(Environment.ProcessPath);
            var marker = directory is null ? null : Path.Combine(directory, "language.txt");
            return marker is not null && string.Equals(File.ReadAllText(marker).Trim(), "en", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}

internal static class MessageBox
{
    public static MessageBoxResult Show(string text) => System.Windows.MessageBox.Show(UiLanguage.Translate(text));
    public static MessageBoxResult Show(string text, string caption) => System.Windows.MessageBox.Show(UiLanguage.Translate(text), UiLanguage.Translate(caption));
    public static MessageBoxResult Show(string text, string caption, MessageBoxButton buttons, MessageBoxImage image) => System.Windows.MessageBox.Show(UiLanguage.Translate(text), UiLanguage.Translate(caption), buttons, image);
    public static MessageBoxResult Show(string text, string caption, MessageBoxButton buttons, MessageBoxImage image, MessageBoxResult defaultResult) => System.Windows.MessageBox.Show(UiLanguage.Translate(text), UiLanguage.Translate(caption), buttons, image, defaultResult);
    public static MessageBoxResult Show(Window owner, string text, string caption, MessageBoxButton buttons, MessageBoxImage image) => System.Windows.MessageBox.Show(owner, UiLanguage.Translate(text), UiLanguage.Translate(caption), buttons, image);
    public static MessageBoxResult Show(Window owner, string text, string caption, MessageBoxButton buttons, MessageBoxImage image, MessageBoxResult defaultResult) => System.Windows.MessageBox.Show(owner, UiLanguage.Translate(text), UiLanguage.Translate(caption), buttons, image, defaultResult);
}
