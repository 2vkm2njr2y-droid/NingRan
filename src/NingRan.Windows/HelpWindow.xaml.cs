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
            OverviewText.Text = "凝然加密用于在本机保护文件和媒体内容。保存到 NTFS 磁盘时，成品会以 .jpg 保存：主文件是普通 JPEG 封面，普通看图软件只显示用户选择的照片；加密内容保存在同名文件的 NTFS 隐藏数据流中。在凝然内选择该照片后，可以浏览其中的文件树并按需预览、播放、导出或删除内容。保存到不支持 NTFS 隐藏数据流的磁盘时，程序会改为生成可移动的 .nrenc 加密包。\n\n" +
                "加密媒体仍通过原有的媒体传输方式交给播放器。凝然加密内置播放所需的 VLC 组件，不会把独立的“凝然媒体播放器”打包进本产品；Media-Helper 的联动通道保持不变。";
            ArchiveTitle.Text = "日常使用：加密、查看、播放与导出";
            ArchiveText.Text = "1. 加密：在主窗口选择文件或文件夹，设置发送者身份、密码和压缩等级，再选择保存位置。保存到 NTFS 时请选择一张封面照片，程序会制作 JPEG 封面并生成 .jpg；保存到其他磁盘时会自动生成 .nrenc，不需要照片。\n\n" +
                "2. 打开：在凝然中点击“选择文件”，选中加密照片或旧版 .nrenc 文件，输入所需密码并完成身份验证。为保留普通看图体验，程序不会抢占系统的 .jpg 双击打开方式。\n\n" +
                "3. 预览和播放：主窗口右上角的“播放器设置”可以选择音频、视频由凝然播放器或内置播放器打开，选择会自动记住，默认使用凝然播放器。凝然播放器未安装或连接失败时会说明原因并自动改用内置播放器；严格防护开启时也会临时强制使用内置播放器。该选择不影响图片、PDF 和保险箱备用查看。选中图片、音频或视频后使用预览/播放。预览图由播放器按当前媒体内容生成；首次生成可能需要等待。拖动时间条、从 0:00 跳到 30:00、播放速度调整和连续播放都按需读取所需片段，实际响应还与视频关键帧、磁盘速度和电脑性能有关。\n\n" +
                "4. 导出和修改：点击“追加文件”后可在 Windows 风格窗口中选择任意多个文件。普通单击只选择一个文件；按住 Shift 再单击可逐个增加选择，中间文件不会被连带选中。窗口不会显示隐藏或系统文件与文件夹，并会记住上次位置、窗口大小和排序。遇到同名内容时，可以逐个比较并选择替换、自动改名或跳过，也可以把决定应用到后续全部冲突。删除时可勾选多个文件或文件夹后点击“删除所选”，原来的右键“从加密文件中删除”仍然保留。点击“导出”可选择导出 .nrenc 加密包（不生成明文，适合携带、上传和发送），或导出明文。普通 .nrenc 的追加和删除使用增量方式：新增只暂时占用本次新增内容的空间；删除会立即从文件列表隐藏，但旧数据不会马上回收，所以包体积可能暂时不变。批量追加或删除只更新一次加密文件，操作会显示进度并可取消；如果程序在提交过程中意外退出，再次打开时会先安全恢复，无法确认时则保留上一个完整版本。\n\n移动 .jpg 时，只有在 NTFS 磁盘之间正常移动或复制才会保留隐藏数据流。复制到 FAT、exFAT、部分云盘同步目录或某些压缩工具时，隐藏数据流可能丢失；照片会正常显示，但凝然不能再打开其中内容。跨磁盘使用前请先导出 .nrenc。";
            DeliveryTitle.Text = "安全交付：把成套资料交给别人";
            DeliveryText.Text = "点击主窗口右上角“安全交付”，依次选择一个或多个文件、文件夹，填写交付名称和说明，设置密码、有效期以及是否允许导出，再选择保存位置。多个顶层项目、子文件夹、空文件夹和空文件都会保留。程序在生成前检查资料、保存位置和剩余空间，生成后重新读取并完整验证；失败或取消不会改动原始资料。\n\n" +
                "接收方必须安装凝然，并使用您通过其他安全方式单独告知的密码。交付信息和文件名在完成必要验证后才会显示。指定联系人时，界面会说明本机身份是否匹配，不能把不匹配联系人误显示为已确认。禁止导出时仍可在凝然内查看支持的内容，但单个、批量和全部明文导出都会被拒绝。\n\n" +
                "到期后，交付说明、发送者、接收者和文件树仍可查看，但文字、图片、PDF、音频、视频和所有明文导出都会立即停止。有效期依赖接收方电脑的本地时间，离线软件无法完全阻止手动修改时间；禁止导出也无法阻止截图、拍照或录屏。凝然不负责通过邮件、聊天软件、U 盘或网盘发送文件，外部平台可能保留文件副本和传输记录。";
            VaultTitle.Text = "凝然保险箱：日常整理与编辑";
            VaultText.Text = "保险箱用于长期保存并反复编辑资料。主入口先让您选择“创建保险箱”或“打开保险箱”，两项使用独立界面。新建时需要选择固定总容量；未使用区域会写入随机数据，创建后总容量不能调整。打开任一空间后，程序会优先挂载 Windows 临时磁盘并自动打开资源管理器；完成后点击“锁定并卸载磁盘”。\n\n新建时可打开默认关闭的“建立隐蔽空间”。它会在同一个固定大小的保险箱中建立两个互相独立的空间：输入日常密码只打开日常空间，输入另一套秘密密码只打开另一个空间；两者使用不同钥匙、目录和固定区域。两个密码必须明显不同，容量创建后不能重新分配，也不能在已打开的空间中直接切换。请先完整锁定，再从同一个“打开保险箱”入口输入另一套密码。忘记任一密码都无法恢复对应内容，程序也不能替您判断或证明另一个空间是否存在。\n\n日常空间和隐蔽空间都会优先挂载为临时磁盘。挂载失败时，程序才会打开软件内备用查看，让您继续查看文件树并管理内容。临时磁盘和外部软件可能在 Windows 最近记录、缩略图或其他位置留下使用痕迹。此功能的“隐蔽”只表示减少界面和日常目录中的直接暴露，不能保证抵抗所有专业取证、长期比较、键盘记录、屏幕或内存监控。\n\n旧单文件保险箱可以通过“升级旧保险箱”另存为新版。升级逐个搬移加密分段，不覆盖或删除原文件；新版重新读取并完整检查通过后才显示成功。确认新版内容前请继续保留原保险箱。\n\n导出明文或交给外部软件打开，可能被 Windows 最近记录、搜索、缩略图、休眠文件、内存转储、杀毒软件、自动保存、打印记录或云同步保留痕迹；截图、拍照和高权限软件也可能超出凝然可控制的范围。重要资料仍应保留独立备份。卸载凝然不会删除您自行选择位置保存的 .nrvault 保险箱。保险箱格式版本高于当前程序支持范围时，程序会停止打开并提示更新，绝不会猜测读取或修改该保险箱。";
            PasswordsTitle.Text = "密码、密匙与身份";
            PasswordsText.Text = "请把加密密码、密匙文件、身份备份和授权设备分开保管。修改加密文件时，按界面要求输入原加密密码和发送者身份密码。遗失密码、密匙或满足解锁条件的设备后，程序无法替您恢复内容；重要资料必须保留独立备份。";
            PrivacyTitle.Text = "隐私与本地处理";
            PrivacyText.Text = "文件加密、解密、压缩、身份管理和设备核验均在本机完成。程序不会主动上传文件内容、密码、密匙、身份信息或使用记录。只有在您主动打开、导出、播放或分享时，相关内容才会在您指定的位置或播放器中使用。";
            SecureTitle.Text = "严格防护与高安全打开";
            SecureText1.Text = "需要额外限制时，可在界面中启用严格防护。它会请求管理员确认并监控主窗口、播放器和预览画面；发现不符合允许条件的读取后，会记录事件、停止当前操作并清理临时内容。不要把来源不明的软件加入允许名单。";
            SecureText2.Text = "选择“高安全打开（管理员确认）”后，会启动独立的管理员查看窗口；普通窗口不会传递密码、密匙或已解锁内容。高安全窗口只允许在程序内查看，不能导出、删除或修改文件。截图、管理员权限软件和同一账户下已获得读取能力的软件仍可能超出保护范围。";
            SecureText3.Text = "严格防护用于减少风险和缩短敏感内容停留时间，不能替代 Windows 安全设置、杀毒软件、备份和谨慎操作。";
            SafetyTitle.Text = "注意事项与免责声明";
            SafetyText.Text = "标准压缩会跳过 MP4、MP3、JPG 等通常已经压缩的格式；完整压缩会尝试所有文件，但只保存较小的结果，不会降低媒体质量。压缩等级越高，处理时间和磁盘读写压力通常越大。播放、拖动、倍速和预览图生成受媒体编码、关键帧、磁盘速度和电脑性能影响，程序不保证所有编码格式都能播放。\n\n" +
                "请确认您有权处理所选内容，并在重要操作前保留独立备份。密码、身份备份、密匙文件或授权设备遗失后，程序不提供绕过验证的恢复方式。程序按当前状态提供，不保证适用于每一种电脑、存储设备或第三方程序。";
            SetNavigation("开始使用", "查看、导出与修改", "安全交付", "凝然保险箱", "密码、密匙与身份", "隐私与本地处理", "严格防护与高安全打开", "注意事项与免责声明");
            Title = "凝然加密帮助文档";
            return;
        }

        DocumentTitle.Text = "NingRan Encryption Help";
        DocumentSubtitle.Text = "Product overview, everyday usage, and important safety notes.";
        ContentsTitle.Text = "Contents";
        OverviewTitle.Text = "Product Overview and Getting Started";
        OverviewText.Text = "NingRan Encryption protects files and media on this computer. When saved to an NTFS disk, the result is a .jpg: the main file is an ordinary JPEG cover, so ordinary image viewers show only your chosen photo, while the encrypted content is stored in the file's NTFS alternate data stream. NingRan opens that content from the photo. When saved to a disk without NTFS alternate data streams, the program creates a portable .nrenc encrypted package instead.\n\n" +
            "Encrypted media continues to use the existing media transport path. NingRan Encryption includes the VLC components needed for playback; the separate NingRan Media Player is not bundled with this product, and the Media-Helper integration channel remains unchanged.";
        ArchiveTitle.Text = "Everyday Use: Encrypt, View, Play, and Export";
        ArchiveText.Text = "1. Encrypt: choose a file or folder, set the sender identity, password, compression level, and save location. When saving to NTFS, choose a cover photo; common image formats are converted to JPEG and the result is a .jpg. Other disks automatically create a .nrenc package and do not need a photo.\n\n" +
            "2. Open: choose the encrypted photo or a legacy .nrenc file from inside NingRan, then enter the required password and complete identity verification. NingRan does not take over the system .jpg double-click association, so normal opening still shows the photo.\n\n" +
            "3. Preview and play: Player settings in the upper-right corner chooses whether audio and video use NingRan Player or the built-in player. The choice is remembered, and NingRan Player is the default. If it is missing or cannot connect, NingRan explains the reason and uses the built-in player automatically. Strict Protection also temporarily forces the built-in player. The choice does not affect images, PDFs, or the vault fallback viewer. Select an image, audio file, or video and choose preview or play. Thumbnails are generated from the current media and may take a moment the first time. Seeking, jumping from 0:00 to 30:00, changing playback speed, and continuous playback read only the required portions. Actual response also depends on video keyframes, disk speed, and computer performance.\n\n" +
            "4. Export and edit: select Append files to choose any number of files in the Windows-style picker. A normal click selects one file; Shift-click adds individual files without selecting those in between. Hidden and system files and folders are not shown. The picker remembers its last location, window size, and sorting. For name conflicts, compare each item and replace, rename automatically, or skip it; the same choice can also be applied to all remaining conflicts. To remove several items, check them in the archive tree and select Remove checked. The original right-click Remove command remains available. Export can create a portable .nrenc package without plaintext, or export plaintext. Ordinary .nrenc packages use incremental updates: adding items temporarily needs space for the new items only; removing items hides them from the file list immediately, while old data is not reclaimed at once, so the package can temporarily stay the same size. A batch append or removal updates the archive only once; progress is shown and cancellable. If the application stops during commit, the next open first performs a safe recovery; if it cannot confirm the files, the previous complete version is kept.\n\nWhen moving a .jpg, the hidden data is retained only when Windows normally moves or copies it between NTFS disks. FAT, exFAT, some cloud-sync folders, and some archive tools can lose it. The photo will still display normally, but NingRan cannot open the encrypted content. Export .nrenc before using it across disks.";
        DeliveryTitle.Text = "Secure Delivery";
        DeliveryText.Text = "Choose Secure Delivery in the main window to combine multiple files and folders into one .nrenc package. Enter a delivery name and optional note, set a password, expiry, and plaintext-export rule, then choose where to save it. Top-level items, nested folders, empty folders, and empty files are preserved. NingRan checks inputs and free space before creation, then reopens and fully verifies the result. Cancellation or failure does not modify the source material.\n\n" +
            "The recipient must install NingRan and use the password you provide separately through a safer channel. Delivery information and filenames appear only after the required checks. If a contact is specified, NingRan reports whether the local identity matches and never labels a mismatch as confirmed. When export is prohibited, supported content can still be viewed inside NingRan, but single, batch, and full plaintext export are refused.\n\n" +
            "After expiry, the note, sender, recipient, and file tree remain visible, while text, images, PDF, audio, video, and all plaintext exports stop immediately. Expiry depends on the recipient computer's local clock and cannot fully resist deliberate clock changes. Export controls cannot prevent screenshots, photos, or screen recording. NingRan does not send the package; email, chat, USB, and cloud services may retain copies and transfer records.";
        VaultTitle.Text = "NingRan Vault: Everyday Organization and Editing";
        VaultText.Text = "Use a vault for files you organize and edit regularly. The vault entry first asks whether you want to create or open a vault, and each choice has a separate interface. New vaults require a fixed total capacity; unused space is filled with random data and the capacity cannot be changed later. Opening either space mounts a temporary Windows drive and opens File Explorer. Select Lock and unmount drive when finished.\n\nDuring creation, you can enable the off-by-default Create concealed space option. It creates two independent spaces inside the same fixed-size vault: the everyday password opens only the everyday space, and a different secret password opens only the other space. They use different keys, directories, and fixed regions. The passwords must be clearly different; their capacities cannot be reallocated after creation, and an open space cannot switch directly to the other one. Lock it completely, then enter the other password through the same Open vault entry. A forgotten password cannot be recovered, and the program cannot determine or prove for you whether another space exists.\n\nBoth everyday and concealed spaces are mounted as temporary drives. If mounting fails, NingRan opens its in-app fallback browser so that you can still view and manage the file tree. Temporary drives and external software can leave traces in Windows recent items, thumbnails, and other locations. Concealed means reducing direct exposure in the interface and everyday directory. It cannot guarantee resistance to every forensic method, long-term comparison, key logging, or screen and memory monitoring.\n\nUpgrade legacy vault creates a separate new-format copy one encrypted block at a time. It never overwrites or deletes the original and reports success only after reopening and fully verifying the result. Keep the original until you have checked the new copy.\n\nPlaintext export or opening a file in external software can leave traces in Windows recent items, search, thumbnails, hibernation files, memory dumps, antivirus tools, autosave data, print records, or cloud sync. Screenshots, cameras, and privileged software may also be outside NingRan's control. Keep an independent backup of important data. Uninstalling NingRan never deletes a .nrvault stored in a location you chose. If a vault uses a newer format, NingRan stops and asks you to update; it never guesses how to read or modify that vault.";
        PasswordsTitle.Text = "Passwords, Keys, and Identities";
        PasswordsText.Text = "Keep encryption passwords, key files, identity backups, and authorized devices separately and safely. When editing an encrypted archive, enter the original encryption password and sender identity password as requested. If a password, key, or required device is lost, the program cannot recover the content for you; keep independent backups of important data.";
        PrivacyTitle.Text = "Privacy and Local Processing";
        PrivacyText.Text = "Encryption, decryption, compression, identity management, and device verification are performed locally. The program does not proactively upload file contents, passwords, keys, identity data, or usage records. Related content is used in the location or player you choose only when you explicitly open, export, play, or share it.";
        SecureTitle.Text = "Strict Protection and High-Security Open";
        SecureText1.Text = "For additional restrictions, enable Strict Protection in the interface. It requests administrator confirmation and monitors the main window, player, and preview surface; when an unapproved read is detected, it records the event, stops the current operation, and cleans temporary content. Do not add software from unknown sources to the allow list.";
        SecureText2.Text = "Choose “High-Security Open (administrator confirmation)” to start a separate administrator viewing window. The ordinary window does not pass passwords, keys, or unlocked content. The high-security window is view-only: it cannot export, remove, or edit files. Screenshots, administrator-level software, and software that already has read access under the same Windows account may still exceed the protection boundary.";
        SecureText3.Text = "Strict Protection reduces exposure and shortens the time sensitive content remains available. It does not replace Windows security settings, antivirus software, backups, or careful operation.";
        SafetyTitle.Text = "Important Notes and Disclaimer";
        SafetyText.Text = "Standard compression skips formats that are usually already compressed, such as MP4, MP3, and JPG. Complete tries every file but stores only the smaller result and never reduces media quality. Higher levels generally require more processing time and disk I/O. Playback, seeking, speed changes, and thumbnail generation depend on media codecs, keyframes, disk speed, and computer performance. Playback of every codec is not guaranteed.\n\n" +
            "Make sure you have the right to process selected content and keep independent backups before important operations. Lost passwords, identity backups, key files, or authorized devices cannot be bypassed or recovered by the program. The program is provided as-is and may not work with every computer, storage device, or third-party program.";
        SetNavigation("Getting Started", "View, Export, and Edit", "Secure Delivery", "NingRan Vault", "Passwords, Keys, and Identities", "Privacy and Local Processing", "Strict Protection and High-Security Open", "Important Notes and Disclaimer");
        Title = "NingRan Encryption Help";
    }

    private void SetNavigation(params string[] labels)
    {
        var items = new[] { NavOverview, NavArchive, NavDelivery, NavVault, NavPasswords, NavPrivacy, NavSecure, NavSafety };
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
            2 => DeliverySection,
            3 => VaultSection,
            4 => PasswordsSection,
            5 => PrivacySection,
            6 => SecureViewingSection,
            7 => SafetySection,
            _ => null,
        };
        target?.BringIntoView();
    }
}
