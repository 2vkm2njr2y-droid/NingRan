using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Animation;
using Microsoft.Web.WebView2.Core;

namespace NingRan.MediaPlayer;

public partial class MediaPlayerWindow : Window
{
    private const string MediaUrlPrefix = "https://ningran-player.local/media";
    private readonly PlayerOptions _options;
    private string? _browserDirectory;
    private bool _browserReady;
    private bool _closing;
    private bool _fullScreen;
    private bool _problemReported;
    private bool _closingAnimationActive;
    private bool _closingAnimationComplete;

    public MediaPlayerWindow(PlayerOptions options)
    {
        _options = options;
        InitializeComponent();
        Title = $"凝然安全播放器 - {options.Name}";
        TitleText.Text = options.Name;
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
        WindowScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, new DoubleAnimation(0.985, 1, TimeSpan.FromMilliseconds(180)));
        WindowScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, new DoubleAnimation(0.985, 1, TimeSpan.FromMilliseconds(180)));
        try
        {
            _browserDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NingRan", "MediaPlayer", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_browserDirectory);
            var environment = await CoreWebView2Environment.CreateAsync(null, _browserDirectory,
                new CoreWebView2EnvironmentOptions("--disk-cache-size=0 --media-cache-size=0 --disable-application-cache"));
            await MediaBrowser.EnsureCoreWebView2Async(environment);
            MediaBrowser.CoreWebView2.Settings.AreDevToolsEnabled = false;
            MediaBrowser.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            MediaBrowser.CoreWebView2.Settings.AreBrowserAcceleratorKeysEnabled = false;
            MediaBrowser.CoreWebView2.AddWebResourceRequestedFilter($"{MediaUrlPrefix}*", CoreWebView2WebResourceContext.All);
            MediaBrowser.CoreWebView2.WebResourceRequested += MediaBrowser_WebResourceRequested;
            MediaBrowser.CoreWebView2.WebMessageReceived += MediaBrowser_WebMessageReceived;
            MediaBrowser.CoreWebView2.ProcessFailed += MediaBrowser_ProcessFailed;
            MediaBrowser.CoreWebView2.ContainsFullScreenElementChanged += MediaBrowser_ContainsFullScreenElementChanged;
            _browserReady = true;
            MediaBrowser.CoreWebView2.NavigateToString(BuildPlayerHtml());
        }
        catch (Exception exception)
        {
            ReportProblemAndClose($"播放器无法启动：{exception.GetType().Name}：{exception.Message}");
        }
    }

    private void MediaBrowser_WebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
    {
        try
        {
            var (start, length, partial) = ParseRange(e.Request.Headers, _options.Length);
            var stream = new PipeMediaStream(_options, start, length);
            var headers = $"Content-Type: {_options.Mime}\r\nContent-Length: {length}\r\nAccept-Ranges: bytes\r\n" +
                          "Access-Control-Allow-Origin: *\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\n";
            if (partial) headers += $"Content-Range: bytes {start}-{start + length - 1}/{_options.Length}\r\n";
            e.Response = MediaBrowser.CoreWebView2.Environment.CreateWebResourceResponse(stream, partial ? 206 : 200,
                partial ? "Partial Content" : "OK", headers);
        }
        catch (Exception exception)
        {
            e.Response = MediaBrowser.CoreWebView2.Environment.CreateWebResourceResponse(new MemoryStream(), 503,
                "Media Unavailable", $"Cache-Control: no-store\r\nX-NingRan-Error: {Uri.EscapeDataString(exception.Message)}\r\n");
        }
    }

    private void MediaBrowser_WebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            var message = JsonSerializer.Deserialize<PlayerMessage>(e.TryGetWebMessageAsString());
            if (message?.Kind == "problem") ReportProblemAndClose(message.Message ?? "媒体播放发生错误。");
        }
        catch { }
    }

    private void MediaBrowser_ProcessFailed(object? sender, CoreWebView2ProcessFailedEventArgs e) =>
        ReportProblemAndClose($"播放器组件停止响应：{e.ProcessFailedKind}。");

    private void MediaBrowser_ContainsFullScreenElementChanged(object? sender, object e)
    {
        Dispatcher.Invoke(() => SetFullScreen(MediaBrowser.CoreWebView2.ContainsFullScreenElement));
    }

    private void ReportProblemAndClose(string message)
    {
        if (_closing) return;
        MarkProblem(message);
        Dispatcher.BeginInvoke(Close);
    }

    internal void MarkProblem(string message)
    {
        _problemReported = true;
        try { MediaPipeClient.Notify(_options, "problem", message); } catch { }
    }

    private void SetFullScreen(bool fullScreen)
    {
        if (_fullScreen == fullScreen) return;
        _fullScreen = fullScreen;
        TitleRow.Height = fullScreen ? new GridLength(0) : new GridLength(44);
        if (fullScreen) WindowState = WindowState.Maximized;
        MaximizeButton.Content = WindowState == WindowState.Maximized ? "❐" : "□";
    }

    private static (long Start, long Length, bool Partial) ParseRange(CoreWebView2HttpRequestHeaders headers, long total)
    {
        string? value;
        try { value = headers.GetHeader("Range"); } catch { value = null; }
        if (string.IsNullOrWhiteSpace(value)) return (0, total, false);
        if (!value.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("不支持的媒体读取范围。");
        var parts = value[6..].Split(',', 2)[0].Trim().Split('-', 2);
        if (parts.Length != 2) throw new InvalidDataException("媒体读取范围不正确。");
        if (string.IsNullOrWhiteSpace(parts[0]))
        {
            if (!long.TryParse(parts[1], out var suffix) || suffix <= 0) throw new InvalidDataException("媒体读取范围不正确。");
            var start = Math.Max(0, total - suffix);
            return (start, total - start, true);
        }

        if (!long.TryParse(parts[0], out var position) || position < 0 || position >= total) throw new InvalidDataException("媒体读取位置超出范围。");
        var end = string.IsNullOrWhiteSpace(parts[1]) ? total - 1 :
            long.TryParse(parts[1], out var requestedEnd) ? Math.Min(requestedEnd, total - 1) : throw new InvalidDataException("媒体读取范围不正确。");
        if (end < position) throw new InvalidDataException("媒体读取范围不正确。");
        return (position, end - position + 1, true);
    }

    private string BuildPlayerHtml()
    {
        var mediaElement = _options.Kind == "audio" ? "audio" : "video";
        var safeName = System.Security.SecurityElement.Escape(_options.Name) ?? "媒体";
        var source = $"{MediaUrlPrefix}?id={Guid.NewGuid():N}";
        var template = """
<!doctype html><html><head><meta charset="utf-8"><style>
:root{color-scheme:dark} html,body,#stage{width:100%;height:100%;margin:0;overflow:hidden;background:#090b0a;font-family:"Segoe UI",sans-serif} #stage{position:relative;display:flex;align-items:center;justify-content:center} video,audio{max-width:100%;max-height:100%;width:100%;height:100%;object-fit:contain;background:#090b0a;outline:none} audio{height:92px;max-width:760px} #bar{position:absolute;left:18px;right:18px;bottom:16px;display:flex;align-items:center;gap:12px;padding:10px 13px;border-radius:12px;background:rgba(8,12,10,.72);backdrop-filter:blur(9px);transition:opacity .24s ease,transform .24s ease;z-index:4} #stage.hide-bar #bar{opacity:0;transform:translateY(10px);pointer-events:none} button{border:0;color:#fff;background:transparent;font-size:18px;min-width:30px;cursor:pointer} input[type=range]{accent-color:#41b883} #progress{flex:1;cursor:pointer} #time{min-width:96px;font-variant-numeric:tabular-nums;color:#eef7f1;font-size:13px;white-space:nowrap} #preview{position:absolute;display:none;z-index:5;bottom:59px;width:220px;padding:5px;border-radius:8px;background:rgba(8,12,10,.9);box-shadow:0 8px 20px #0008;pointer-events:none} #preview img{display:block;width:220px;height:124px;object-fit:contain;background:#000;border-radius:5px} #preview label{display:block;text-align:center;color:#fff;font-size:12px;margin-top:3px} #hint{position:absolute;color:#b6c9bf;font-size:13px;top:15px;left:18px;opacity:.76;transition:opacity .3s} #stage.playing #hint{opacity:0}
</style></head><body><div id="stage"><{{mediaElement}} id="media" preload="metadata" playsinline crossorigin="anonymous" aria-label="{{safeName}}"><source src="{{source}}" type="{{_options.Mime}}"></{{mediaElement}}><div id="hint">← / → 调整播放进度　双击画面全屏</div><div id="preview"><img><label></label></div><div id="bar"><button id="play" title="播放或暂停">▶</button><span id="time">0:00 / 0:00</span><input id="progress" type="range" min="0" max="1000" value="0" aria-label="播放进度"><input id="volume" type="range" min="0" max="1" step=".05" value="1" aria-label="音量"><button id="fullscreen" title="全屏">⛶</button></div></div><script>
const m=document.getElementById('media'),stage=document.getElementById('stage'),bar=document.getElementById('bar'),play=document.getElementById('play'),progress=document.getElementById('progress'),time=document.getElementById('time'),preview=document.getElementById('preview'),previewImg=preview.querySelector('img'),previewLabel=preview.querySelector('label'),volume=document.getElementById('volume');
const fmt=s=>{s=Number.isFinite(s)?Math.max(0,Math.floor(s)):0;return Math.floor(s/60)+':'+String(s%60).padStart(2,'0')}; let hideTimer=0, wantedPreview=-1, previewBusy=false; const previewVideo=document.createElement('video'); previewVideo.muted=true;previewVideo.preload='auto';previewVideo.crossOrigin='anonymous';previewVideo.src='{{source}}';
function paint(){progress.value=m.duration?Math.round(m.currentTime/m.duration*1000):0;time.textContent=fmt(m.currentTime)+' / '+fmt(m.duration)} function reveal(){stage.classList.remove('hide-bar');clearTimeout(hideTimer);if(document.fullscreenElement)hideTimer=setTimeout(()=>stage.classList.add('hide-bar'),3000)}
play.onclick=()=>m.paused?m.play():m.pause();m.onplay=()=>{play.textContent='❚❚';stage.classList.add('playing')};m.onpause=()=>play.textContent='▶';m.ontimeupdate=paint;m.onloadedmetadata=paint;m.onended=()=>{play.textContent='▶';reveal()};m.onerror=()=>chrome.webview.postMessage(JSON.stringify({kind:'problem',message:'媒体无法解码或读取。'}));
progress.oninput=()=>{if(m.duration)m.currentTime=m.duration*(progress.value/1000)};volume.oninput=()=>m.volume=volume.value;document.addEventListener('keydown',e=>{if(e.key==='ArrowLeft'||e.key==='ArrowRight'){m.currentTime=Math.max(0,Math.min(m.duration||0,m.currentTime+(e.key==='ArrowLeft'?-5:5)));e.preventDefault();reveal()}});stage.ondblclick=()=>document.fullscreenElement?document.exitFullscreen():stage.requestFullscreen();document.getElementById('fullscreen').onclick=()=>document.fullscreenElement?document.exitFullscreen():stage.requestFullscreen();document.addEventListener('fullscreenchange',reveal);stage.addEventListener('mousemove',reveal);reveal();
async function drawPreview(){if(previewBusy||wantedPreview<0)return;previewBusy=true;let at=wantedPreview;wantedPreview=-1;try{if(Math.abs(previewVideo.currentTime-at)>.15){previewVideo.currentTime=at;await new Promise((ok,no)=>{let t=setTimeout(no,1400);previewVideo.onseeked=()=>{clearTimeout(t);ok()};previewVideo.onerror=()=>{clearTimeout(t);no()}})}let c=document.createElement('canvas'),w=220,h=124;c.width=w;c.height=h;let x=c.getContext('2d');x.fillStyle='#000';x.fillRect(0,0,w,h);let r=Math.min(w/(previewVideo.videoWidth||w),h/(previewVideo.videoHeight||h)),dw=(previewVideo.videoWidth||w)*r,dh=(previewVideo.videoHeight||h)*r;x.drawImage(previewVideo,(w-dw)/2,(h-dh)/2,dw,dh);previewImg.src=c.toDataURL('image/jpeg',.72);previewLabel.textContent=fmt(at)}catch{}finally{previewBusy=false;if(wantedPreview>=0)drawPreview()}}
progress.addEventListener('pointermove',e=>{if(!m.duration)return;let r=progress.getBoundingClientRect(),f=Math.max(0,Math.min(1,(e.clientX-r.left)/r.width)),at=m.duration*f;preview.style.display='block';preview.style.left=Math.max(10,Math.min(window.innerWidth-240,e.clientX-110))+'px';wantedPreview=at;drawPreview()});progress.addEventListener('pointerleave',()=>preview.style.display='none');
</script></div></body></html>
""";
        return template
            .Replace("{{mediaElement}}", mediaElement, StringComparison.Ordinal)
            .Replace("{{safeName}}", safeName, StringComparison.Ordinal)
            .Replace("{{source}}", source, StringComparison.Ordinal)
            .Replace("{{_options.Mime}}", _options.Mime, StringComparison.Ordinal);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) { ToggleMaximize(); return; }
        DragMove();
    }

    private async void Minimize_Click(object sender, RoutedEventArgs e)
    {
        await AnimateRootAsync(0.985, 0.35, 130);
        WindowState = WindowState.Minimized;
        WindowScale.ScaleX = WindowScale.ScaleY = 1;
        Root.Opacity = 1;
    }
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private async void ToggleMaximize()
    {
        await AnimateRootAsync(0.99, 0.8, 100);
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        await AnimateRootAsync(1, 1, 150);
    }
    private void Window_StateChanged(object? sender, EventArgs e) => MaximizeButton.Content = WindowState == WindowState.Maximized ? "❐" : "□";

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_closingAnimationComplete)
        {
            e.Cancel = true;
            if (_closingAnimationActive) return;
            _closingAnimationActive = true;
            _closing = true;
            if (!_problemReported)
            {
                try { MediaPipeClient.Notify(_options, "closed", null); } catch { }
            }
            await AnimateRootAsync(0.985, 0, 150);
            _closingAnimationComplete = true;
            Close();
            return;
        }

        _closing = true;
        if (_browserReady && MediaBrowser.CoreWebView2 is not null)
        {
            MediaBrowser.CoreWebView2.WebResourceRequested -= MediaBrowser_WebResourceRequested;
            MediaBrowser.CoreWebView2.WebMessageReceived -= MediaBrowser_WebMessageReceived;
            MediaBrowser.CoreWebView2.ProcessFailed -= MediaBrowser_ProcessFailed;
        }
        MediaBrowser.Dispose();
        if (!string.IsNullOrWhiteSpace(_browserDirectory))
        {
            try { Directory.Delete(_browserDirectory, true); } catch { }
        }
    }

    private Task AnimateRootAsync(double scale, double opacity, int milliseconds)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var duration = new Duration(TimeSpan.FromMilliseconds(milliseconds));
        var opacityAnimation = new DoubleAnimation(opacity, duration) { FillBehavior = FillBehavior.HoldEnd };
        opacityAnimation.Completed += (_, _) => completion.TrySetResult();
        WindowScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, new DoubleAnimation(scale, duration) { FillBehavior = FillBehavior.HoldEnd });
        WindowScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, new DoubleAnimation(scale, duration) { FillBehavior = FillBehavior.HoldEnd });
        Root.BeginAnimation(OpacityProperty, opacityAnimation);
        return completion.Task;
    }
}

public sealed record PlayerOptions(string Pipe, string Token, string Name, long Length, string Mime, string Kind)
{
    public static bool TryParse(string[] args, out PlayerOptions options)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index + 1 < args.Length; index += 2) values[args[index]] = args[index + 1];
        if (!values.TryGetValue("--pipe", out var pipe) || !pipe.StartsWith("NingRan.Media.", StringComparison.Ordinal) ||
            !values.TryGetValue("--token", out var token) || token.Length < 32 ||
            !values.TryGetValue("--name", out var name) || !values.TryGetValue("--length", out var lengthValue) ||
            !long.TryParse(lengthValue, out var length) || length <= 0 ||
            !values.TryGetValue("--mime", out var mime) || !values.TryGetValue("--kind", out var kind) || kind is not ("video" or "audio"))
        {
            options = null!;
            return false;
        }
        options = new PlayerOptions(pipe, token, name, length, mime, kind);
        return true;
    }
}

internal sealed record MediaPipeRequest(string Kind, string? Token, long Start = 0, long Length = 0, string? Message = null);
internal sealed record MediaPipeResponse(bool Success, string? Error = null, long Start = 0, long Length = 0, long TotalLength = 0, string? ContentType = null);
internal sealed record PlayerMessage(string Kind, string? Message);

internal static class MediaPipeClient
{
    private const int MaximumFrameBytes = 16 * 1024;

    public static void Notify(PlayerOptions options, string kind, string? message)
    {
        using var pipe = Connect(options);
        WriteFrame(pipe, new MediaPipeRequest(kind, options.Token, Message: message));
        _ = ReadFrame<MediaPipeResponse>(pipe);
    }

    public static (NamedPipeClientStream Pipe, MediaPipeResponse Response) OpenRead(PlayerOptions options, long start, long length)
    {
        var pipe = Connect(options);
        try
        {
            WriteFrame(pipe, new MediaPipeRequest("read", options.Token, start, length));
            var response = ReadFrame<MediaPipeResponse>(pipe) ?? throw new InvalidDataException("主程序没有回应媒体读取请求。");
            if (!response.Success) throw new IOException(response.Error ?? "主程序拒绝提供媒体内容。");
            return (pipe, response);
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    private static NamedPipeClientStream Connect(PlayerOptions options)
    {
        var pipe = new NamedPipeClientStream(".", options.Pipe, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try { pipe.Connect(5_000); return pipe; }
        catch { pipe.Dispose(); throw; }
    }

    private static void WriteFrame(Stream stream, object message)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message);
        if (bytes.Length > MaximumFrameBytes) throw new InvalidDataException("播放器消息过长。");
        stream.Write(BitConverter.GetBytes(bytes.Length));
        stream.Write(bytes);
        stream.Flush();
    }

    private static T? ReadFrame<T>(Stream stream)
    {
        Span<byte> prefix = stackalloc byte[sizeof(int)];
        stream.ReadExactly(prefix);
        var length = BitConverter.ToInt32(prefix);
        if (length is <= 0 or > MaximumFrameBytes) throw new InvalidDataException("主程序响应长度不正确。");
        var bytes = new byte[length];
        stream.ReadExactly(bytes);
        return JsonSerializer.Deserialize<T>(bytes);
    }
}

internal sealed class PipeMediaStream : Stream
{
    private readonly NamedPipeClientStream _pipe;
    private readonly long _length;
    private long _position;
    private bool _disposed;

    public PipeMediaStream(PlayerOptions options, long start, long length)
    {
        (_pipe, var response) = MediaPipeClient.OpenRead(options, start, length);
        _length = response.Length;
        if (_length != length) throw new InvalidDataException("主程序返回的媒体片段长度不正确。");
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _position; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_position >= _length) return 0;
        var read = await _pipe.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _length - _position)], cancellationToken).ConfigureAwait(false);
        _position += read;
        return read;
    }
    protected override void Dispose(bool disposing) { if (disposing && !_disposed) _pipe.Dispose(); _disposed = true; base.Dispose(disposing); }
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
