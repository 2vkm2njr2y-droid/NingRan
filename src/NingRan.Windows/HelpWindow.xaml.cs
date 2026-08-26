using System.Windows;
using System.Windows.Controls;

namespace NingRan.Windows;

public partial class HelpWindow : Window
{
    public HelpWindow()
    {
        InitializeComponent();
        ApplyLanguage();
        HelpNavigation.SelectedIndex = 0;
    }

    private void ApplyLanguage()
    {
        if (!UiLanguage.IsEnglish)
        {
            DocumentTitle.Text = "凝然加密帮助文档";
            DocumentSubtitle.Text = "本说明介绍产品用途、日常使用方法和安全注意事项。";
            ContentsTitle.Text = "目录";
            OverviewTitle.Text = "产品介绍与开始使用";
            OverviewText.Text = "凝然加密用于在本机保护文件和媒体内容。选择文件或文件夹后，可选择加密或解密；加密文件以 .nrenc 保存。打开 .nrenc 后，可以先在程序内浏览文件树，再按需预览、播放、导出或删除内容，不需要一次性解开整个文件。\n\n" +
                "加密媒体仍通过原有的媒体传输方式交给播放器。凝然加密内置播放所需的 VLC 组件，不会把独立的“凝然媒体播放器”打包进本产品；Media-Helper 的联动通道保持不变。";
            ArchiveTitle.Text = "日常使用：加密、查看、播放与导出";
            ArchiveText.Text = "1. 加密：在主窗口选择“加密文件”或“加密文件夹”，设置发送者身份、密码和压缩等级，然后选择保存位置。压缩等级按压缩软件的常用名称显示：无压缩、存储、标准、最好。\n\n" +
                "2. 打开：双击 .nrenc，或在程序中选择“打开加密文件”，输入所需密码并完成身份验证。文件树显示后，可展开文件夹查看名称、大小和类型。\n\n" +
                "3. 预览和播放：选中图片、音频或视频后使用预览/播放。预览图由播放器按当前媒体内容生成；首次生成可能需要等待。拖动时间条、从 0:00 跳到 30:00、播放速度调整和连续播放都按需读取所需片段，实际响应还与视频关键帧、磁盘速度和电脑性能有关。\n\n" +
                "4. 导出和修改：右键文件或文件夹可选择“单独解密副本”或“从加密文件中删除”。导出文件夹会保留内部层级；删除文件夹会同时删除其中的内容。操作会显示进度，并可在安全位置取消。";
            PasswordsTitle.Text = "密码、密匙与身份";
            PasswordsText.Text = "请把加密密码、密匙文件、身份备份和授权设备分开保管。修改加密文件时，按界面要求输入原加密密码和发送者身份密码。遗失密码、密匙或满足解锁条件的设备后，程序无法替您恢复内容；重要资料必须保留独立备份。";
            PrivacyTitle.Text = "隐私与本地处理";
            PrivacyText.Text = "文件加密、解密、压缩、身份管理和设备核验均在本机完成。程序不会主动上传文件内容、密码、密匙、身份信息或使用记录。只有在您主动打开、导出、播放或分享时，相关内容才会在您指定的位置或播放器中使用。";
            SecureTitle.Text = "严格防护与高安全打开";
            SecureText1.Text = "需要额外限制时，可在界面中启用严格防护。它会请求管理员确认并监控主窗口、播放器和预览画面；发现不符合允许条件的读取后，会记录事件、停止当前操作并清理临时内容。不要把来源不明的软件加入允许名单。";
            SecureText2.Text = "选择“高安全打开（管理员确认）”后，会启动独立的管理员查看窗口；普通窗口不会传递密码、密匙或已解锁内容。高安全窗口只允许在程序内查看，不能导出、删除或修改文件。截图、管理员权限软件和同一账户下已获得读取能力的软件仍可能超出保护范围。";
            SecureText3.Text = "严格防护用于减少风险和缩短敏感内容停留时间，不能替代 Windows 安全设置、杀毒软件、备份和谨慎操作。";
            SafetyTitle.Text = "注意事项与免责声明";
            SafetyText.Text = "无损压缩不保证所有媒体文件都会变小。MP4、MP3、JPG 等已经压缩的格式可能几乎不变；压缩等级越高，处理时间和磁盘读写压力通常越大。播放、拖动、倍速和预览图生成受媒体编码、关键帧、磁盘速度和电脑性能影响，程序不保证所有编码格式都能播放。\n\n" +
                "请确认您有权处理所选内容，并在重要操作前保留独立备份。密码、身份备份、密匙文件或授权设备遗失后，程序不提供绕过验证的恢复方式。程序按当前状态提供，不保证适用于每一种电脑、存储设备或第三方程序。";
            SetNavigation("开始使用", "查看、导出与修改", "密码、密匙与身份", "隐私与本地处理", "严格防护与高安全打开", "注意事项与免责声明");
            Title = "凝然加密帮助文档";
            return;
        }

        DocumentTitle.Text = "NingRan Encryption Help";
        DocumentSubtitle.Text = "Product overview, everyday usage, and important safety notes.";
        ContentsTitle.Text = "Contents";
        OverviewTitle.Text = "Product Overview and Getting Started";
        OverviewText.Text = "NingRan Encryption protects files and media on this computer. Select a file or folder to encrypt or decrypt; encrypted archives use the .nrenc extension. After opening an .nrenc file, browse its file tree and preview, play, export, or remove selected items on demand instead of decrypting the entire archive first.\n\n" +
            "Encrypted media continues to use the existing media transport path. NingRan Encryption includes the VLC components needed for playback; the separate NingRan Media Player is not bundled with this product, and the Media-Helper integration channel remains unchanged.";
        ArchiveTitle.Text = "Everyday Use: Encrypt, View, Play, and Export";
        ArchiveText.Text = "1. Encrypt: choose “Encrypt file” or “Encrypt folder” in the main window, select the sender identity, password, and compression level, then choose where to save the archive. Compression levels use familiar archive names: No compression, Store, Standard, and Best.\n\n" +
            "2. Open: double-click an .nrenc file or choose “Open encrypted file” in the program. Enter the required password and complete identity verification. The file tree then shows names, sizes, and types.\n\n" +
            "3. Preview and play: select an image, audio file, or video and choose preview or play. Thumbnails are generated from the current media and may take a moment the first time. Seeking, jumping from 0:00 to 30:00, changing playback speed, and continuous playback read only the required portions. Actual response also depends on video keyframes, disk speed, and computer performance.\n\n" +
            "4. Export and edit: right-click a file or folder and choose “Decrypt a separate copy” or “Remove from encrypted file”. Exported folders keep their internal structure; removing a folder also removes its contents. Progress is shown and cancellable.";
        PasswordsTitle.Text = "Passwords, Keys, and Identities";
        PasswordsText.Text = "Keep encryption passwords, key files, identity backups, and authorized devices separately and safely. When editing an encrypted archive, enter the original encryption password and sender identity password as requested. If a password, key, or required device is lost, the program cannot recover the content for you; keep independent backups of important data.";
        PrivacyTitle.Text = "Privacy and Local Processing";
        PrivacyText.Text = "Encryption, decryption, compression, identity management, and device verification are performed locally. The program does not proactively upload file contents, passwords, keys, identity data, or usage records. Related content is used in the location or player you choose only when you explicitly open, export, play, or share it.";
        SecureTitle.Text = "Strict Protection and High-Security Open";
        SecureText1.Text = "For additional restrictions, enable Strict Protection in the interface. It requests administrator confirmation and monitors the main window, player, and preview surface; when an unapproved read is detected, it records the event, stops the current operation, and cleans temporary content. Do not add software from unknown sources to the allow list.";
        SecureText2.Text = "Choose “High-Security Open (administrator confirmation)” to start a separate administrator viewing window. The ordinary window does not pass passwords, keys, or unlocked content. The high-security window is view-only: it cannot export, remove, or edit files. Screenshots, administrator-level software, and software that already has read access under the same Windows account may still exceed the protection boundary.";
        SecureText3.Text = "Strict Protection reduces exposure and shortens the time sensitive content remains available. It does not replace Windows security settings, antivirus software, backups, or careful operation.";
        SafetyTitle.Text = "Important Notes and Disclaimer";
        SafetyText.Text = "Lossless compression does not guarantee that every media file becomes smaller. Already-compressed formats such as MP4, MP3, and JPG may change little; higher levels generally require more processing time and disk I/O. Playback, seeking, speed changes, and thumbnail generation depend on media codecs, keyframes, disk speed, and computer performance. Playback of every codec is not guaranteed.\n\n" +
            "Make sure you have the right to process selected content and keep independent backups before important operations. Lost passwords, identity backups, key files, or authorized devices cannot be bypassed or recovered by the program. The program is provided as-is and may not work with every computer, storage device, or third-party program.";
        SetNavigation("Getting Started", "View, Export, and Edit", "Passwords, Keys, and Identities", "Privacy and Local Processing", "Strict Protection and High-Security Open", "Important Notes and Disclaimer");
        Title = "NingRan Encryption Help";
    }

    private void SetNavigation(params string[] labels)
    {
        var items = new[] { NavOverview, NavArchive, NavPasswords, NavPrivacy, NavSecure, NavSafety };
        for (var index = 0; index < items.Length && index < labels.Length; index++)
        {
            items[index].Content = new TextBlock
            {
                Text = labels[index],
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 192,
            };
        }
    }

    private void HelpNavigation_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var target = HelpNavigation.SelectedIndex switch
        {
            0 => OverviewSection,
            1 => ArchiveSection,
            2 => PasswordsSection,
            3 => PrivacySection,
            4 => SecureViewingSection,
            5 => SafetySection,
            _ => null,
        };
        target?.BringIntoView();
    }
}
