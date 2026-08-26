using System.ComponentModel;
using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using NingRan.Core;
using NingRan.Security;

namespace NingRan.Windows;

public partial class SecurePdfViewerWindow : Window
{
    private const string PdfUrl = "https://ningran-pdf.local/document.pdf";
    private const string BuiltInPdfExtensionHost = "mhjfbmdgcfjbbpaeojofohoefgiehjai";
    private readonly SecureArchiveSession _session;
    private readonly SecureArchiveEntry _entry;
    private string? _browserDirectory;
    private bool _ready;

    public SecurePdfViewerWindow(SecureArchiveSession session, SecureArchiveEntry entry)
    {
        _session = session;
        _entry = entry;
        InitializeComponent();
        FileNameText.Text = entry.Name;
        Title = $"{UiLanguage.Translate("凝然加密 · 安全 PDF 查看")} - {entry.Name}";
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            if (NingRanRuntime.IsProcessElevated())
            {
                throw new InvalidOperationException("高安全管理员窗口禁止启动浏览器组件。请在普通窗口查看 PDF。");
            }
            SecureWebView2Policy.AssertSafeBeforeCreate();
            _browserDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NingRan", "SecurePdf", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_browserDirectory);
            var environment = await CoreWebView2Environment.CreateAsync(null, _browserDirectory,
                new CoreWebView2EnvironmentOptions("--disk-cache-size=0 --disable-application-cache"));
            await PdfBrowser.EnsureCoreWebView2Async(environment);
            SecureWebView2Policy.AssertTrustedBrowserProcess(PdfBrowser.CoreWebView2.BrowserProcessId);
            PdfBrowser.CoreWebView2.Settings.AreDevToolsEnabled = false;
            PdfBrowser.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            PdfBrowser.CoreWebView2.Settings.AreBrowserAcceleratorKeysEnabled = false;
            PdfBrowser.CoreWebView2.Settings.HiddenPdfToolbarItems =
                CoreWebView2PdfToolbarItems.Save |
                CoreWebView2PdfToolbarItems.SaveAs |
                CoreWebView2PdfToolbarItems.Print |
                CoreWebView2PdfToolbarItems.MoreSettings;
            PdfBrowser.CoreWebView2.AddWebResourceRequestedFilter(PdfUrl, CoreWebView2WebResourceContext.All);
            PdfBrowser.CoreWebView2.WebResourceRequested += PdfBrowser_WebResourceRequested;
            PdfBrowser.CoreWebView2.NavigationStarting += PdfBrowser_NavigationStarting;
            PdfBrowser.CoreWebView2.NewWindowRequested += PdfBrowser_NewWindowRequested;
            PdfBrowser.CoreWebView2.LaunchingExternalUriScheme += PdfBrowser_LaunchingExternalUriScheme;
            PdfBrowser.CoreWebView2.DownloadStarting += PdfBrowser_DownloadStarting;
            _ready = true;
            PdfBrowser.CoreWebView2.Navigate(PdfUrl);
        }
        catch (Exception exception)
        {
            var message = UiLanguage.IsEnglish
                ? $"Could not start embedded PDF view: {exception.Message}"
                : $"无法启动内嵌 PDF 查看：{exception.Message}";
            MessageBox.Show(this, message, "凝然加密", MessageBoxButton.OK, MessageBoxImage.Warning);
            Close();
        }
    }

    private static void PdfBrowser_NavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (!IsAllowedPdfNavigation(e.Uri))
        {
            e.Cancel = true;
        }
    }

    private static void PdfBrowser_NewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs e) =>
        e.Handled = true;

    private static void PdfBrowser_LaunchingExternalUriScheme(
        object? sender,
        CoreWebView2LaunchingExternalUriSchemeEventArgs e) => e.Cancel = true;

    private static void PdfBrowser_DownloadStarting(object? sender, CoreWebView2DownloadStartingEventArgs e)
    {
        e.Cancel = true;
        e.Handled = true;
    }

    internal static bool IsAllowedPdfNavigation(string? value)
    {
        if (string.Equals(value, PdfUrl, StringComparison.Ordinal))
        {
            return true;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, "chrome-extension", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, BuiltInPdfExtensionHost, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.AbsolutePath, "/index.html", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 &&
                string.Equals(Uri.UnescapeDataString(parts[0]), "file", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(Uri.UnescapeDataString(parts[1]), PdfUrl, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private void PdfBrowser_WebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
    {
        try
        {
            var (start, length, partial) = ParseRange(e.Request.Headers, _entry.Length);
            var source = _session.OpenEntryReadStream(_entry.RelativePath);
            source.Position = start;
            var stream = new LimitedReadStream(source, length);
            var headers = $"Content-Type: application/pdf\r\nContent-Length: {length}\r\nAccept-Ranges: bytes\r\nCache-Control: no-store, no-cache, must-revalidate\r\n";
            if (partial) headers += $"Content-Range: bytes {start}-{start + length - 1}/{_entry.Length}\r\n";
            e.Response = PdfBrowser.CoreWebView2.Environment.CreateWebResourceResponse(stream, partial ? 206 : 200,
                partial ? "Partial Content" : "OK", headers);
        }
        catch (Exception exception)
        {
            e.Response = PdfBrowser.CoreWebView2.Environment.CreateWebResourceResponse(new MemoryStream(), 503,
                "PDF Unavailable", $"Cache-Control: no-store\r\nX-NingRan-Error: {Uri.EscapeDataString(exception.Message)}\r\n");
        }
    }

    private static (long Start, long Length, bool Partial) ParseRange(CoreWebView2HttpRequestHeaders headers, long total)
    {
        string? value;
        try { value = headers.GetHeader("Range"); } catch { value = null; }
        if (string.IsNullOrWhiteSpace(value)) return (0, total, false);
        if (!value.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("PDF 读取范围不正确。");
        var parts = value[6..].Split(',', 2)[0].Trim().Split('-', 2);
        if (parts.Length != 2) throw new InvalidDataException("PDF 读取范围不正确。");
        if (string.IsNullOrWhiteSpace(parts[0]))
        {
            if (!long.TryParse(parts[1], out var suffix) || suffix <= 0) throw new InvalidDataException("PDF 读取范围不正确。");
            var suffixStart = Math.Max(0, total - suffix);
            return (suffixStart, total - suffixStart, true);
        }
        if (!long.TryParse(parts[0], out var start) || start < 0 || start >= total) throw new InvalidDataException("PDF 读取范围不正确。");
        var end = string.IsNullOrWhiteSpace(parts[1]) ? total - 1 :
            long.TryParse(parts[1], out var requestedEnd) ? Math.Min(requestedEnd, total - 1) : throw new InvalidDataException("PDF 读取范围不正确。");
        if (end < start) throw new InvalidDataException("PDF 读取范围不正确。");
        return (start, end - start + 1, true);
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_ready && PdfBrowser.CoreWebView2 is not null)
        {
            PdfBrowser.CoreWebView2.WebResourceRequested -= PdfBrowser_WebResourceRequested;
            PdfBrowser.CoreWebView2.NavigationStarting -= PdfBrowser_NavigationStarting;
            PdfBrowser.CoreWebView2.NewWindowRequested -= PdfBrowser_NewWindowRequested;
            PdfBrowser.CoreWebView2.LaunchingExternalUriScheme -= PdfBrowser_LaunchingExternalUriScheme;
            PdfBrowser.CoreWebView2.DownloadStarting -= PdfBrowser_DownloadStarting;
        }
        PdfBrowser.Dispose();
        if (!string.IsNullOrWhiteSpace(_browserDirectory))
        {
            try { Directory.Delete(_browserDirectory, true); } catch { }
        }
    }

    private sealed class LimitedReadStream : Stream
    {
        private readonly Stream _source;
        private readonly long _length;
        private long _remaining;

        public LimitedReadStream(Stream source, long length)
        {
            _source = source;
            _length = _remaining = length;
        }

        public override bool CanRead => _source.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => _length - _remaining; set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining <= 0) return 0;
            var read = await _source.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _remaining)], cancellationToken).ConfigureAwait(false);
            _remaining -= read;
            return read;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _source.Dispose(); base.Dispose(disposing); }
    }
}
