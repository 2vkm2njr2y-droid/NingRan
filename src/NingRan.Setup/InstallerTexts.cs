namespace NingRan.Setup.Windows;

internal sealed record InstallerTexts(
    string InstallerTitle,
    string ProductMode,
    string StepOne,
    string StepTwo,
    string StepThree,
    string AdminRequired,
    string WelcomeTitle,
    string WelcomeDescription,
    string NoticeTitle,
    string NoticeText,
    string AcceptNotice,
    string OptionsTitle,
    string OptionsDescription,
    string InstallLocation,
    string CreateDesktopShortcut,
    string CreateStartMenuShortcut,
    string AssociateFiles,
    string AssociationDescription,
    string Back,
    string Cancel,
    string Continue,
    string ProgressTitle,
    string Preparing,
    string FinishTitle,
    string FinishMessage,
    string RunAfterInstall,
    string Language,
    string VersionFormat,
    string UninstallTitle,
    string UninstallDescription,
    string ProgramLocation,
    string DeleteUserData,
    string UserDataCounting,
    string UninstallProgress,
    string KeepDataProgress);

internal static class InstallerTextCatalog
{
    public static InstallerTexts Chinese { get; } = new(
        "凝然安装程序", "安全离线安装", "01  阅读说明", "02  安装选项", "03  安装完成", "需要管理员权限",
        "欢迎安装凝然", "完整离线安装；请先阅读产品介绍、隐私条件与使用边界。", "安装须知、产品介绍与免责声明",
        "1. 产品介绍：凝然加密用于在本机保护文件和媒体内容。它支持分段加密、按需读取，以及使用 Zstandard 的无损压缩；压缩后的每一段都会与原始数据比较，只保存较小的一份。外部播放器仍通过原有媒体传输方式读取原始媒体字节。\n\n" +
        "2. 本地处理：文件加密、解密、身份管理、设备核验和压缩均在本机完成。程序不会主动上传文件内容、密码、密匙、身份信息或使用记录。\n\n" +
        "3. 使用边界：无损压缩不保证所有文件都会变小。MP4、MP3、JPG 等已经压缩的格式可能几乎不变；压缩等级越高，处理时间和磁盘读写压力通常越大。\n\n" +
        "4. 播放提示：从 0:00 跳到 30:00、拖动、倍速和预览图生成的效果，还会受到视频关键帧、媒体编码、磁盘速度和电脑性能影响。程序不保证所有媒体编码格式都能播放。\n\n" +
        "5. 您的责任：请妥善保存密码、身份备份、密匙文件和授权设备，并确认您有权处理所选内容。遗失解锁条件后，程序无法代为恢复；重要文件应另行备份。\n\n" +
        "6. 数据保留：安装和升级默认保留身份、可信联系人、设备登记及设置。卸载时只有在您明确勾选并再次确认后，才会删除这些个人数据。",
        "我已阅读并理解产品介绍、隐私条件、使用边界和免责声明", "选择安装方式", "程序固定安装在受保护的系统位置；升级不会覆盖已有内容。", "安装位置",
        "创建桌面快捷方式", "创建开始菜单快捷方式", "关联加密文件和身份信息（.nrenc、.nrid、.nrpub）", "不关联普通密匙文件和 .nrkey；仍可在程序内手动选择。",
        "上一步", "取消", "继续", "正在安装凝然", "正在准备…", "凝然安装完成", "现在可以开始保护文件。", "立即运行凝然", "语言", "版本 {0} · Windows x64", "卸载凝然", "默认只删除程序，个人数据和设置都会保留。", "程序位置", "同时删除本机保存的全部身份、联系人、设备登记和设置", "正在统计个人数据…", "正在删除程序和已确认的个人数据…", "正在删除程序，个人数据会保留…");

    public static InstallerTexts English { get; } = new(
        "NingRan Installer", "Secure offline installation", "01  Read information", "02  Install options", "03  Complete", "Administrator permission required",
        "Welcome to NingRan", "Complete offline installation. Please review the product information, privacy terms, and usage boundaries.", "Product information, notices, and disclaimer",
        "1. Product: NingRan Encryption protects files and media locally. It supports segmented encryption, on-demand reading, and lossless Zstandard compression. Each compressed segment is compared with the original and only the smaller one is stored. External players continue to receive the original media bytes through the existing transport path.\n\n" +
        "2. Local processing: Encryption, decryption, identity management, device verification, and compression happen on this computer. The program does not proactively upload file contents, passwords, keys, identity data, or usage records.\n\n" +
        "3. Boundaries: Lossless compression does not guarantee that every file becomes smaller. Already-compressed formats such as MP4, MP3, and JPG may change little. Higher levels generally require more processing time and disk I/O.\n\n" +
        "4. Playback notice: Seeking from 0:00 to 30:00, dragging, playback speed, and thumbnail generation also depend on keyframes, media codecs, disk speed, and computer performance. Playback of every media codec is not guaranteed.\n\n" +
        "5. Your responsibility: Keep passwords, identity backups, key files, and authorized devices safe, and make sure you have the right to process the selected content. Lost unlock conditions cannot be recovered by the program; keep independent backups of important files.\n\n" +
        "6. Data retention: Installation and upgrades keep identities, trusted contacts, device registrations, and settings by default. Uninstall removes this personal data only after you explicitly select and confirm deletion.",
        "I have read and understood the product information, privacy terms, usage boundaries, and disclaimer", "Choose installation", "The program is installed in a protected system location; upgrades keep existing content.", "Installation location",
        "Create desktop shortcut", "Create Start menu shortcut", "Associate encrypted files and identity files (.nrenc, .nrid, .nrpub)", "Ordinary key files and .nrkey are not associated; you can still select them inside the program.",
        "Back", "Cancel", "Continue", "Installing NingRan", "Preparing…", "NingRan installation complete", "You can now start protecting files.", "Run NingRan now", "Language", "Version {0} · Windows x64", "Uninstall NingRan", "Only the program is removed by default; personal data and settings are kept.", "Program location", "Also delete all identities, contacts, device registrations, and settings on this computer", "Counting personal data…", "Removing the program and confirmed personal data…", "Removing the program; personal data will be kept…");
}
