using System.Windows;
using System.Windows.Controls;

namespace NingRan.Windows;

public partial class HelpWindow : Window
{
    private readonly IReadOnlyList<HelpTopic> _topics = BuildTopics();
    private IReadOnlyList<HelpTopic> _visibleTopics = Array.Empty<HelpTopic>();
    private HelpTopic? _selectedTopic;
    private bool _rebuilding;


    public HelpWindow()
    {
        InitializeComponent();
        ApplyChromeLanguage();
        RebuildTree();
    }

    private bool English => UiLanguage.IsEnglish;

    private void ApplyChromeLanguage()
    {
        Title = English ? "NingRan Encryption Help" : "凝然加密帮助文档";
        DocumentTitle.Text = Title;
        DocumentSubtitle.Text = English
            ? "Find detailed instructions, workflows, and safety boundaries by feature."
            : "按功能查找详细说明、操作步骤和安全边界。";
        SearchLabel.Text = English ? "Search" : "搜索";
        SearchBox.ToolTip = English ? "Search buttons, extensions, or keywords" : "按按钮、扩展名或关键词搜索";
        NavigationHint.Text = English ? "Select a feature to read its complete guide." : "点击功能名称查看详细说明。";
        PreviousButton.Content = English ? "Previous" : "上一项";
        NextButton.Content = English ? "Next" : "下一项";
    }

    private void RebuildTree()
    {
        var query = SearchBox.Text.Trim();
        var oldId = _selectedTopic?.Id;
        _visibleTopics = string.IsNullOrWhiteSpace(query)
            ? _topics
            : _topics.Where(topic => topic.Matches(query)).ToArray();
        _rebuilding = true;
        try
        {
            HelpTree.Items.Clear();
            foreach (var group in _visibleTopics.GroupBy(topic => topic.CategoryId))
            {
                var first = group.First();
                var category = new TreeViewItem
                {
                    Header = English ? first.CategoryEn : first.CategoryZh,
                    IsExpanded = true,
                    FontWeight = FontWeights.SemiBold,
                    Padding = new Thickness(5, 4, 5, 4),
                };
                foreach (var topic in group)
                {
                    category.Items.Add(new TreeViewItem
                    {
                        Header = English ? topic.TitleEn : topic.TitleZh,
                        Tag = topic,
                        FontWeight = FontWeights.Normal,
                        Padding = new Thickness(8, 6, 5, 6),
                        ToolTip = English ? topic.LeadEn : topic.LeadZh,
                    });
                }
                HelpTree.Items.Add(category);
            }
        }
        finally { _rebuilding = false; }

        SearchResultText.Text = string.IsNullOrWhiteSpace(query)
            ? (English ? $"{_topics.Count} feature guides" : $"共 {_topics.Count} 个功能说明")
            : (English ? $"{_visibleTopics.Count} matching guides" : $"找到 {_visibleTopics.Count} 个相关说明");
        var selected = _visibleTopics.FirstOrDefault(topic => topic.Id == oldId) ?? _visibleTopics.FirstOrDefault();
        if (selected is null) RenderEmptySearch(); else SelectTopic(selected);
    }

    private void HelpTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (_rebuilding || e.NewValue is not TreeViewItem { Tag: HelpTopic topic }) return;
        SelectTopic(topic);
    }

    private void SelectTopic(HelpTopic topic)
    {
        _selectedTopic = topic;
        var item = FindTopicItem(HelpTree.Items, topic);
        if (item is not null)
        {
            _rebuilding = true;
            item.IsSelected = true;
            item.BringIntoView();
            _rebuilding = false;
        }
        DocumentCategory.Text = English ? topic.CategoryEn : topic.CategoryZh;
        TopicTitle.Text = English ? topic.TitleEn : topic.TitleZh;
        TopicLead.Text = English ? topic.LeadEn : topic.LeadZh;
        DocumentBody.Children.Clear();
        foreach (var section in topic.Sections)
        {
            DocumentBody.Children.Add(new TextBlock
            {
                Text = English ? section.HeadingEn : section.HeadingZh,
                FontSize = 17,
                FontWeight = FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8),
            });
            DocumentBody.Children.Add(new TextBlock
            {
                Text = English ? section.BodyEn : section.BodyZh,
                FontSize = 14,
                LineHeight = 23,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 22),
            });
        }
        var index = _visibleTopics.ToList().IndexOf(topic);
        TopicPosition.Text = English ? $"{Math.Max(1, index + 1)} / {_visibleTopics.Count}" : $"第 {Math.Max(1, index + 1)} / {_visibleTopics.Count} 项";
        PreviousButton.IsEnabled = index > 0;
        NextButton.IsEnabled = index >= 0 && index < _visibleTopics.Count - 1;
        DocumentScroll.ScrollToTop();
    }

    private static TreeViewItem? FindTopicItem(ItemCollection items, HelpTopic topic)
    {
        foreach (var value in items)
        {
            if (value is not TreeViewItem item) continue;
            if (ReferenceEquals(item.Tag, topic)) return item;
            var nested = FindTopicItem(item.Items, topic);
            if (nested is not null) return nested;
        }
        return null;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => RebuildTree();
    private void PreviousButton_Click(object sender, RoutedEventArgs e) => MoveTopic(-1);
    private void NextButton_Click(object sender, RoutedEventArgs e) => MoveTopic(1);

    private void MoveTopic(int offset)
    {
        if (_selectedTopic is null) return;
        var index = _visibleTopics.ToList().IndexOf(_selectedTopic);
        if (index < 0) return;
        SelectTopic(_visibleTopics[Math.Clamp(index + offset, 0, _visibleTopics.Count - 1)]);
    }

    private void RenderEmptySearch()
    {
        DocumentCategory.Text = string.Empty;
        TopicTitle.Text = English ? "No matching feature" : "没有找到相关功能";
        TopicLead.Text = English ? "Try a shorter keyword." : "请尝试使用更短的关键词。";
        DocumentBody.Children.Clear();
        TopicPosition.Text = string.Empty;
        PreviousButton.IsEnabled = NextButton.IsEnabled = false;
    }

    internal string GetTopicTextForChecks(string topicId)
    {
        var matchingTopics = _topics.Where(topic => topic.Id == topicId);
        return string.Join("\n", matchingTopics.SelectMany(topic =>
            new[] { English ? topic.LeadEn : topic.LeadZh }
                .Concat(topic.Sections.Select(section => English ? section.BodyEn : section.BodyZh))));
    }

    private static HelpSection S(string zh, string en, string bodyZh, string bodyEn) => new(zh, en, bodyZh, bodyEn);
    private static HelpTopic T(string id, string categoryId, string categoryZh, string categoryEn,
        string titleZh, string titleEn, string leadZh, string leadEn, params HelpSection[] sections) =>
        new(id, categoryId, categoryZh, categoryEn, titleZh, titleEn, leadZh, leadEn, sections);

    private static IReadOnlyList<HelpTopic> BuildTopics() =>
    [
        T("welcome", "start", "开始使用", "Getting started", "帮助文档怎么用", "How to use this help",
            "每个文件树项目都是一个独立章节。搜索、点击、上一项和下一项都会只改变当前章节。",
            "Every tree item is a separate chapter. Search, selection, Previous, and Next change only the current chapter.",
            S("阅读方法", "Reading", "先看适用场景，再按步骤执行；遇到失败查看限制和排错。涉及密码、外部程序、临时文件或管理员权限时，还要阅读安全边界。本帮助覆盖主窗口、加密解密、文件树、查看器、导出修改、身份、保护条件、安全交付、保险箱、隐私清理和排错。",
                "Start with when to use a feature, then follow its steps. For failures, read limits and troubleshooting. Read safety boundaries when passwords, external programs, temporary files, or administrator access are involved. This guide covers the main window, encryption, decryption, the file tree, viewers, export, editing, identity, protection, delivery, vault, privacy, cleanup, and troubleshooting."),
            S("搜索", "Search", "可以搜索按钮、扩展名或关键词，例如“默认应用”“分片”“Hello”“临时磁盘”“安全交付”和“.nrsplit”。清空搜索框即可恢复完整目录。",
                "Search buttons, extensions, or keywords such as “default program,” “split,” “Hello,” “temporary drive,” “secure delivery,” and “.nrsplit.” Clear the box to restore the full tree.")),

        T("source", "start", "开始使用", "Getting started", "选择来源和操作", "Choose a source and action",
            "输入区域决定本次要保护、还原或打开的内容。",
            "The source area decides what will be protected, restored, or opened.",
            S("步骤", "Steps", "点击“选择文件”或“选择文件夹”，也可以拖放。确认文件树的名称、大小和数量，再选择“加密”或“解密”。处理期间不要移动、改名或修改源文件。",
                "Select Choose file or Choose folder, or drop the content. Check names, sizes, and counts, then choose Encrypt or Decrypt. Do not move, rename, or edit sources during processing."),
            S("文件夹和批量", "Folders and batches", "文件夹会保留目录结构。批量加密适合多个独立来源；每个来源都会检查路径、大小和存在性。",
                "Folders keep their structure. Batch encryption is for independent sources; each source is checked for path, size, and existence."),
            S("失败处理", "Failure", "源文件变化、路径无效或权限不足时会停止并尽量清理未完成输出。原文件不会被加密覆盖，不要把 .part 文件当成成品。",
                "A changed source, invalid path, or denied access stops the operation and cleans incomplete output when possible. Encryption never overwrites the source; never treat a .part file as finished.")),

        T("encrypt", "start", "开始使用", "Getting started", "加密、解密和输出格式", "Encryption, decryption, and output",
            "加密生成新包，解密创建普通副本，原始内容在成功提交前不会被替换。",
            "Encryption creates a new package; decryption creates a regular copy; the source is not replaced before commit succeeds.",
            S("加密步骤", "Encrypt steps", "选择保护模式、密码、压缩、大小隐藏、分片和照片封面，选择发送者身份和身份密码，指定保存位置后点击“开始加密”。成功后程序会重新读取并验证成品。",
                "Choose protection mode, password, compression, size hiding, splitting, and a cover; choose the sender identity and password; choose a destination and select Start encryption. The result is reopened and verified."),
            S("解密步骤", "Decrypt steps", "切换到“解密”，输入所需密码、密匙或设备，选择目标目录后开始。程序先验证，再通过临时目录写入并移动到最终路径；原包不会删除。",
                "Switch to Decrypt, provide the required password, key, or device, choose a destination, and start. NingRan verifies first, writes through staging, then moves the result; the package is not deleted."),
            S("格式", "Formats", ".nrenc 适合移动、上传和备份；加密 .jpg 依赖 NTFS 隐藏数据流，普通看图软件只显示封面；.nrsplit 必须保留完整集合。跨磁盘前把 .jpg 导出为 .nrenc。",
                ".nrenc is portable for moving, uploading, and backup. Encrypted .jpg depends on NTFS alternate data streams and shows only its cover to ordinary viewers. .nrsplit requires all parts. Export .jpg to .nrenc before crossing disks.")),

        T("options", "start", "开始使用", "Getting started", "压缩、大小隐藏和分片", "Compression, padding, and splitting",
            "这些选项分别影响速度、体积、外部可见大小和单文件限制。",
            "These options affect speed, size, visible size, and per-file limits.",
            S("压缩", "Compression", "存储不压缩；最快优先速度；标准跳过通常已压缩格式；完整尝试所有文件并保留较小结果。普通压缩不会降低媒体质量。“最小（有损压缩）”会降低本次新加入的 JPEG 图片画质，选择前请确认。",
                "Store does not compress; Fastest favors speed; Standard skips usually compressed formats; Complete tries all files and keeps the smaller result. Ordinary compression never lowers media quality. Smallest (lossy compression) lowers the quality of JPEG images added in this operation; confirm before choosing it."),
            S("大小隐藏", "Size hiding", "粗略补齐增加有限随机填充；固定补齐尝试约 100 MB、1 GB 或 10 GB。目标小于内容时不会缩小文件，开始前会显示空间估计。",
                "Rough padding adds limited random data; fixed padding targets about 100 MB, 1 GB, or 10 GB. A smaller target never shrinks the file; the estimate appears before starting."),
            S("分片", "Splitting", "勾选分片并选择每片大小。分片边读取边写入，必须同目录保存；缺一片、单独改名或只发送一片都会造成读取失败。",
                "Enable splitting and choose a part size. Parts are written as data is read and must stay together; a missing, renamed, or individually sent part can fail to read.")),

        T("tree", "browse", "查看、修改与导出", "Browse, edit, and export", "文件树和搜索", "File tree and search",
            "文件树是安全打开后的主要工作区，搜索只改变显示。",
            "The file tree is the main workspace after secure open; search changes display only.",
            S("浏览", "Browse", "文件夹可展开和折叠，搜索按名称或内部路径筛选。勾选框用于批量删除，不等于当前查看选择；根内容不能删除。",
                "Folders expand and collapse; search filters names or internal paths. Checkboxes are for batch removal, separate from the current view selection; the root cannot be removed."),
            S("双击", "Double-click", "图片、音频、视频、PDF 和文本按播放器设置打开。普通未知文件在默认应用模式下只临时提取当前项目；打开一个小文件不会先导出整个大包。",
                "Images, audio, video, PDF, and text follow player settings. Unknown regular files are temporarily extracted only in default-program mode; one small item does not export the whole archive."),
            S("修改后", "After edits", "追加、替换或删除完成后等待提交成功再搜索。失败时原包保持完整，不要手工删除加密包尾部。",
                "Wait for commit success after append, replace, or remove before searching. A failure keeps the original; never delete archive bytes manually.")),

        T("default", "browse", "查看、修改与导出", "Browse, edit, and export", "Windows 默认应用", "Windows default program",
            "默认应用只提取当前选中的内部文件，再交给 Windows 文件关联程序。",
            "The default program extracts only the selected item and starts the Windows association.",
            S("步骤", "Steps", "在播放器设置选择“使用默认程序打开”，回到文件树双击文件。程序提取当前项目，然后启动照片、PDF、Office 或其他关联程序。",
                "Select Use the Windows default program, return to the tree, and double-click. NingRan extracts the selected item and starts Photos, a PDF reader, Office, or another association."),
            S("临时文件", "Temporary files", "临时目录只在当前程序运行期间使用。关闭时会检查大小和哈希；外部程序修改后会询问是否写回。请先保存并关闭外部程序。",
                "The temporary directory exists for the current session. On close, size and hash are checked; external changes prompt for write-back. Save and close the external program first."),
            S("严格路由", "Strict routing", "没有关联程序、提取失败或启动失败时只显示错误并停止，不会偷偷改用凝然播放器。严格防护下拒绝外部明文读取也会直接返回。",
                "Missing association, extraction failure, or launch failure shows an error and stops; NingRan does not silently switch to its own player. Refusing external plaintext under Strict Protection also stops.")),

        T("viewers", "browse", "查看、修改与导出", "Browse, edit, and export", "内置查看器和凝然播放器", "Built-in viewer and NingRan Player",
            "查看方式由播放器设置严格决定，图片和 PDF 也遵循同一选择。",
            "Player settings strictly decide the route, including images and PDF.",
            S("内置播放器", "Built-in player", "内置模式在窗口中按需读取图片、音频、视频、PDF 和常见文本，不启动外部凝然播放器，也不先创建普通副本。未知格式可以导出。",
                "Built-in mode reads images, audio, video, PDF, and common text on demand without starting the external player or creating a regular copy first. Unknown formats can be exported."),
            S("凝然播放器", "NingRan Player", "凝然播放器通过受当前用户限制的管道按片段读取。主程序不传递密码、数据密钥或明文路径；高安全窗口不会启动外部查看器。",
                "NingRan Player reads ranges through a current-user-restricted pipe. Passwords, data keys, and plaintext paths are not passed; high-security windows do not start it."),
            S("故障", "Failure", "确认播放器安装位置受信任、版本兼容并关闭残留进程。启动失败时会提示并停止，不会悄悄改用内置查看；如果要换方式，请回到播放器设置明确选择。外部程序仍可能留下缓存、截图和系统记录。",
                "Confirm a trusted install location, a compatible version, and no leftover process. A failed launch shows an error and stops; it never silently switches to the built-in viewer. Return to Player settings and choose another route explicitly when needed. External programs can still leave caches, screenshots, and system records.")),

        T("export-edit", "browse", "查看、修改与导出", "Browse, edit, and export", "导出、追加、替换和删除", "Export, append, replace, and remove",
            "修改会重新加密和签名，原包在成功提交前保持完整。",
            "Edits reencrypt and resign the result; the original stays intact until commit succeeds.",
            S("导出", "Export", "导出 .nrenc 只复制加密内容，不生成明文；导出明文会先写临时位置再移动到目标，同名不会无提示覆盖。交付禁止导出或到期后会拒绝。",
                "Exporting .nrenc copies encrypted content without plaintext. Plaintext export stages then moves the result and never silently overwrites a name. Delivery restrictions and expiry refuse export."),
            S("追加和替换", "Append and replace", "使用追加文件、添加文件夹或替换文件内容。冲突可自动改名、替换、跳过，并可应用到后续冲突。修改需要原包密码、身份密码，必要时需要原密匙。",
                "Use Append files, Add folder, or Replace file content. Conflicts can be renamed, replaced, or skipped and applied to later conflicts. Edits need the archive password, identity password, and original key when required."),
            S("删除和增量", "Remove and incremental updates", "勾选多个项目后删除。旧分段可能保留，所以包体积不会立即变小；提交中断时下次打开会恢复，无法确认时保留上一个完整版本。",
                "Check several items to remove them. Old segments can remain, so size may not shrink immediately. An interrupted commit is recovered on next open; if uncertain, the previous complete version is kept.")),

        T("media", "media", "媒体与文档查看", "Media and document viewing", "图片、音视频、PDF 和文本", "Images, audio/video, PDF, and text",
            "媒体能力取决于编码、关键帧、磁盘速度和硬件，查看器本身不会修改加密内容。",
            "Media behavior depends on codecs, keyframes, disk speed, and hardware; viewers never edit encrypted content.",
            S("图片", "Images", "内置模式不创建普通图片副本；默认应用和外部播放器可能创建临时或缓存。大图缩放会占用内存，无法解码时可先导出测试。",
                "Built-in mode creates no regular image copy; default programs and external players can create temporary or cache data. Large-image zoom uses memory; export to test an undecodable image."),
            S("音视频", "Audio and video", "播放首次只读必要分段，拖动读取新的范围。需要末尾索引的 MP4 会按需读取，不会为了播放内部视频先导出整个 86G 包。",
                "Initial playback reads required ranges and seeking reads new ranges. MP4 end indexes are read on demand; opening internal video does not export an entire 86 GB package first."),
            S("PDF 和文本", "PDF and text", "内置 PDF 按加密会话读取；常见文本可直接查看。编码或超大文本可能影响显示，修改必须通过替换流程提交。",
                "Built-in PDF reads through the encrypted session; common text opens directly. Encoding and very large text can affect display; edits must use the replace workflow.")),

        T("identity", "security", "密码与安全保护", "Passwords and security", "身份、密码和密匙文件", "Identities, passwords, and key files",
            "身份证明发送者，密码和密匙决定解锁；三者不能互相替代。",
            "Identity proves the sender; passwords and keys unlock content; none replaces another.",
            S("身份", "Identity", "创建身份时设置独立密码和名称，立即导出私密备份；公开身份给接收方核验。追加、替换和删除会用新身份重新签名。",
                "Set a separate password and name, then export a private backup immediately; recipients use the public identity for verification. Append, replace, and remove resign with the selected identity."),
            S("密码", "Password", "建议使用至少 16 个字符的口令短语，不要重复使用网站密码。密码不能和加密包放在同一位置，程序没有后台找回按钮。",
                "Use a passphrase of at least 16 characters and do not reuse website passwords. Keep it separate from the archive; there is no backend recovery button."),
            S("密匙", "Key file", "高级模式需要原密匙文件，可以是 .nrkey 或普通文件。内容必须保持一致，备份时保留原文件；丢失任何解锁条件都可能无法恢复。",
                "Advanced mode needs the original key, either .nrkey or a regular file. Keep its content unchanged and preserve the original; losing a factor can make recovery impossible.")),

        T("factors", "security", "密码与安全保护", "Passwords and security", "物理设备、Hello 和自定义组合", "Devices, Hello, and flexible combinations",
            "额外设备条件提高保护，但带来设备绑定、丢失和更换系统风险。",
            "Extra device factors improve protection but add binding, loss, and system-change risks.",
            S("物理设备", "Physical devices", "先登记 U 盘、移动硬盘或 FIDO2，再加入模式。普通移动存储可复制，强度低于 FIDO2；错误设备不会满足条件。",
                "Register a USB/removable drive or FIDO2 key before adding it. Removable storage can be copied and is weaker than FIDO2; an unrelated device does not satisfy it."),
            S("Windows Hello", "Windows Hello", "Hello 只在登记的本机和当前账户使用。重置、重装、换账户或换电脑可能无法恢复，必须保留密码或密匙文件。",
                "Hello works only on the registered computer and account. Resetting, reinstalling, changing accounts, or changing computers can break recovery; keep a password or key file."),
            S("自定义组合", "Flexible mode", "勾选条件必须全部满足，可设置必需设备、至少数量和禁止名单。禁止设备出现会拒绝解锁，规则不是备份。",
                "Every checked factor is required. Set required devices, a minimum count, and a forbidden list. A forbidden device causes refusal; the rule is not a backup.")),

        T("contacts-security", "security", "密码与安全保护", "Passwords and security", "可信联系人、严格防护和高安全打开", "Trusted contacts, Strict Protection, and High-security open",
            "这些功能减少误信、外部读取和普通窗口暴露，但不是绝对保护。",
            "These features reduce mistaken trust, external reads, and ordinary-window exposure, but are not absolute protection.",
            S("可信联系人", "Trusted contacts", "导入公开身份后，通过电话、当面或独立渠道核对安全码。签名不匹配或内容被修改时不会标记可信；新增删除受保护联系人需要管理员确认。",
                "After importing a public identity, verify its code through a separate channel. A mismatch or changed content is not trusted; protected contact changes need administrator approval."),
            S("严格防护", "Strict Protection", "监控发现不符合条件的读取时会记录、停止操作并清理临时明文。极短读取、截图、拍照、管理员工具和同账户已有权限可能超出检测。",
                "The monitor records unapproved reads, stops the operation, and cleans temporary plaintext. Very short reads, screenshots, cameras, admin tools, and existing same-account access can exceed detection."),
            S("高安全打开", "High-security open", "在独立管理员窗口重新输入解锁材料，只允许程序内查看，不导出、不修改、不启动外部播放器。它不是 Windows 最高级受保护进程。",
                "Re-enter unlock material in a separate administrator window. It is view-only, does not export, edit, or start external players, and is not Windows’ highest protected process.")),

        T("delivery", "delivery", "安全交付", "Secure delivery", "创建、接收、有效期和导出规则", "Create, receive, expiry, and export rules",
            "安全交付把资料、说明、发送者验证、有效期和导出规则放入一个 .nrenc。",
            "Secure Delivery puts files, notes, sender verification, expiry, and export rules in one .nrenc.",
            S("创建", "Create", "添加文件和文件夹，填写名称、说明、密码、发送者身份、有效期和是否允许导出。程序检查来源、空间并在写入后重新验证；失败不改原资料。",
                "Add files and folders, enter name, note, password, sender identity, expiry, and export rule. NingRan checks sources and space and re-verifies after writing; failure does not change sources."),
            S("接收", "Receive", "接收方输入交付密码、选择可信联系人并核对安全码后查看文件树。验证完成前不会显示交付说明和文件名。",
                "The recipient enters the delivery password, selects a trusted contact, verifies the code, and then views the tree. Details and names stay hidden until verification completes."),
            S("到期和禁止导出", "Expiry and export disabled", "禁止导出或到期后不能打开、播放或导出内容，但说明、发送者、接收者和文件树仍可查看。截图和录屏不在软件控制范围。",
                "When export is disabled or expired, content cannot be opened, played, or exported, but the note, sender, recipient, and tree remain visible. Screenshots and recording are outside control.")),

        T("vault", "vault", "凝然保险箱", "NingRan Vault", "创建、隐蔽空间和工作区", "Create, concealed space, and workspace",
            "保险箱适合长期整理和编辑，容量固定，使用后必须锁定。",
            "Vault is for long-term organization and editing; capacity is fixed and it must be locked after use.",
            S("创建和打开", "Create and open", "选择位置、名称、固定容量和密码，未使用区写入随机数据。打开后优先挂载临时 Windows 磁盘并打开资源管理器，使用完成点击“锁定并卸载磁盘”。建立隐蔽空间时请同时记录日常和秘密密码。",
                "Choose location, name, fixed capacity, and password; unused space is filled with random data. Opening mounts a temporary Windows drive and Explorer; select Lock and unmount when done. Create concealed space only when you can preserve both everyday and secret passwords."),
            S("隐蔽空间", "Concealed space", "创建时设置日常和秘密密码及容量。日常密码只显示日常空间，秘密密码只显示秘密空间；不能直接切换，必须先锁定。此隐蔽设计不能保证抵抗专业取证，容量比较、屏幕和内存仍可能暴露线索。",
                "Set everyday and secret passwords and capacities during creation. Each password shows only its space; lock before switching. Concealed space cannot guarantee resistance to professional forensics; size comparison, screens, and memory can still reveal clues."),
            S("工作区", "Workspace", "可添加、导入、导出、替换、移动、重命名、删除和安全查看。提交前使用临时写入，失败时保留原保险箱；锁定失败不要强拔磁盘。挂载失败时可以使用软件内备用查看。",
                "You can add, import, export, replace, move, rename, remove, and securely view. Writes use staging and failures keep the original; never unplug if locking fails. If mounting fails, the fallback browser remains available for safe inspection.")),

        T("vault-history", "vault", "凝然保险箱", "NingRan Vault", "升级和历史版本", "Upgrade and history",
            "升级创建独立新文件，历史版本用于比较和恢复，都需要额外空间。",
            "Upgrade creates a separate new file; history compares and restores older states and can need extra space.",
            S("升级", "Upgrade", "选择旧版保险箱、原密码和密匙，再选择新容量和输出位置。原文件不会覆盖或删除，只有新文件重新打开并完整检查后才算成功。",
                "Choose the legacy vault, original password and key, then new capacity and destination. The original is never overwritten or deleted; success follows reopening and checking."),
            S("历史", "History", "可以比较、恢复或永久清除历史版本。恢复写入新状态，永久清除不能撤销。确认新版或恢复结果前保留原文件。",
                "Compare, restore, or permanently delete versions. Restore writes a new state; permanent deletion cannot be undone. Keep the original until the result is confirmed."),
            S("兼容", "Compatibility", "遇到更高版本格式会停止并提示更新，不会猜测读取。不要用未完成升级文件覆盖唯一备份。",
                "A newer format stops with an update message; NingRan never guesses. Never overwrite the only backup with an incomplete upgrade.")),

        T("privacy", "data", "隐私、清理与排错", "Privacy, cleanup, and troubleshooting", "隐私、清理、备份和排错", "Privacy, cleanup, backups, and troubleshooting",
            "本机加密不等于外部程序和 Windows 不会留下副本。",
            "Local encryption does not prevent external programs and Windows from leaving copies.",
            S("临时和外部副本", "Temporary and external copies", "默认应用创建临时文件，保险箱可能挂载临时磁盘，修改和升级创建临时分段。最近记录、缩略图、搜索、休眠、内存、自动保存、杀毒、云同步和截图可能留下凝然无法删除的副本。",
                "Default programs create temporary files, vaults can mount drives, and edits/upgrades create segments. Recent items, thumbnails, search, hibernation, memory, autosave, antivirus, cloud sync, and screenshots can leave copies NingRan cannot delete."),
            S("完整备份", "Complete backup", "备份要包含加密包、身份私密备份、密匙、密码记录和全部分片。备份后在允许的环境中只读打开或完整检查。",
                "A backup must include the archive, private identity backup, key, password record, and every split part. Test it with a read-only open or full check."),
            S("排错", "Troubleshooting", "先查看进度和磁盘活动；大文件验证、压缩、升级和完整检查可能较慢。取消时保留原件，重启后让清理重试。报告错误时不要发送密码、完整密匙或私密备份。",
                "Check progress and disk activity; large-file checks, compression, upgrades, and full checks can be slow. Keep originals when cancelling and let cleanup retry after restart. Never send passwords, full keys, or private backups in an error report.")),
    ];
}

internal sealed record HelpTopic(
    string Id, string CategoryId, string CategoryZh, string CategoryEn,
    string TitleZh, string TitleEn, string LeadZh, string LeadEn,
    IReadOnlyList<HelpSection> Sections)
{
    public bool Matches(string query)
    {
        var values = new[] { CategoryZh, CategoryEn, TitleZh, TitleEn, LeadZh, LeadEn }
            .Concat(Sections.SelectMany(section => new[]
            {
                section.HeadingZh, section.HeadingEn, section.BodyZh, section.BodyEn,
            }));
        return string.Join("\n", values).Contains(query, StringComparison.CurrentCultureIgnoreCase);
    }
}

internal sealed record HelpSection(string HeadingZh, string HeadingEn, string BodyZh, string BodyEn);
