using System.IO;
using System.IO.Pipes;

namespace NingRan.MediaPlayer;

/// <summary>
/// 可执行的线协议冒烟测试。它不会打开窗口或写出媒体明文；发布校验可通过
/// NingRan.MediaPlayer.exe --ningran-protocol-self-test 检查握手、目录、读取和关闭通知。
/// </summary>
internal static class ProtocolSelfTest
{
    private const string SelectedPath = "album/video.mp4";
    private const int MediaLength = MediaPipeClient.MaximumReadChunkBytes + 5;

    public static async Task<int> RunAsync()
    {
        if (!PlayerLaunchOptions.TryParse(
                ["--ningran-secure-pipe", "NingRan.Media.selftest", "--ningran-selected", SelectedPath], out _) ||
            PlayerLaunchOptions.TryParse(
                ["--pipe", "NingRan.Media.selftest", "--ningran-selected", SelectedPath], out _)) return 10;

        var pipeName = $"NingRan.Media.{Environment.ProcessId}.{Guid.NewGuid():N}";
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var host = RunFakeHostAsync(pipeName, timeout.Token);
        var result = 0;
        try
        {
            var options = await MediaPipeClient.OpenSessionAsync(new PlayerLaunchOptions(pipeName, SelectedPath)).ConfigureAwait(false);
            var entry = options.Entries.Single(item => item.Id == SelectedPath);
            await using (var stream = new PipeMediaStream(options, entry))
            {
                var bytes = new byte[MediaLength];
                await stream.ReadExactlyAsync(bytes, timeout.Token).ConfigureAwait(false);
                for (var index = 0; index < bytes.Length; index++)
                {
                    if (bytes[index] != (byte)(index % 251)) throw new InvalidDataException("读取内容不一致。");
                }
            }

            MediaPipeClient.Notify(options, entry, "problem", "self-test");
            MediaPipeClient.Notify(options, entry, "closed", null);
            await host.WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"凝然媒体播放器安全连接检查失败：{exception}");
            result = 11;
        }
        finally
        {
            timeout.Cancel();
            try { await host.ConfigureAwait(false); }
            catch when (result != 0) { }
        }

        return result;
    }

    private static async Task RunFakeHostAsync(string pipeName, CancellationToken cancellationToken)
    {
        await ServeAsync(pipeName, cancellationToken, request =>
        {
            Require(request.Kind == "hello" && request.Path == SelectedPath,
                "hello 没有携带正确的所选条目。");
            return new MediaPipeResponse(true);
        }).ConfigureAwait(false);

        await ServeAsync(pipeName, cancellationToken, request =>
        {
            Require(request.Kind == "catalog" && request.Path == SelectedPath,
                "catalog 没有携带正确的所选条目。");
            return new MediaPipeResponse(true, Entries:
            [
                new MediaPipeCatalogEntry(SelectedPath, "video.mp4", MediaLength, "video/mp4", "video"),
                new MediaPipeCatalogEntry("album/audio.mp3", "audio.mp3", 8, "audio/mpeg", "audio"),
            ]);
        }).ConfigureAwait(false);

        await ServeAsync(pipeName, cancellationToken, request =>
        {
            Require(request.Kind == "read" && request.Path == SelectedPath &&
                    request.Start == 0 && request.Length == MediaPipeClient.MaximumReadChunkBytes,
                "read 没有携带正确的条目或读取范围。");
            return new MediaPipeResponse(true, Start: 0, Length: MediaPipeClient.MaximumReadChunkBytes,
                TotalLength: MediaLength, ContentType: "video/mp4");
        }, CreatePayload(0, MediaPipeClient.MaximumReadChunkBytes)).ConfigureAwait(false);

        await ServeAsync(pipeName, cancellationToken, request =>
        {
            Require(request.Kind == "read" && request.Path == SelectedPath &&
                    request.Start == MediaPipeClient.MaximumReadChunkBytes && request.Length == 5,
                "跨片段读取没有从正确位置继续。");
            return new MediaPipeResponse(true, Start: MediaPipeClient.MaximumReadChunkBytes, Length: 5,
                TotalLength: MediaLength, ContentType: "video/mp4");
        }, CreatePayload(MediaPipeClient.MaximumReadChunkBytes, 5)).ConfigureAwait(false);

        await ServeAsync(pipeName, cancellationToken, request =>
        {
            Require(request.Kind == "problem" && request.Path == SelectedPath &&
                    request.Message == "self-test", "problem 没有携带正确的条目。");
            return new MediaPipeResponse(true);
        }).ConfigureAwait(false);

        await ServeAsync(pipeName, cancellationToken, request =>
        {
            Require(request.Kind == "closed" && request.Path == SelectedPath,
                "closed 没有携带正确的条目。");
            return new MediaPipeResponse(true);
        }).ConfigureAwait(false);
    }

    private static async Task ServeAsync(string pipeName, CancellationToken cancellationToken,
        Func<MediaPipeRequest, MediaPipeResponse> respond, byte[]? payload = null)
    {
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        var request = MediaPipeClient.ReadFrame<MediaPipeRequest>(server) ??
                      throw new InvalidDataException("没有收到播放器请求。");
        MediaPipeClient.WriteFrame(server, respond(request));
        if (payload is not null)
        {
            await server.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await server.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }

    private static byte[] CreatePayload(int start, int length)
    {
        var payload = new byte[length];
        for (var index = 0; index < payload.Length; index++) payload[index] = (byte)((start + index) % 251);
        return payload;
    }
}
