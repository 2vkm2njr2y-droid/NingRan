using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace NingRan.Windows;

internal sealed class CoverImagePreparation : IDisposable
{
    private readonly string? _temporaryDirectory;

    private CoverImagePreparation(string path, string? temporaryDirectory)
    {
        Path = path;
        _temporaryDirectory = temporaryDirectory;
    }

    public string Path { get; }

    public static CoverImagePreparation Create(string sourcePath)
    {
        var fullPath = System.IO.Path.GetFullPath(sourcePath);
        if (!File.Exists(fullPath))
        {
            throw new NingRan.Core.NingRanException("请选择存在的封面照片。");
        }

        BitmapFrame frame;
        bool isJpeg;
        using (var input = File.Open(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Span<byte> start = stackalloc byte[2];
            isJpeg = input.Read(start) == start.Length && start[0] == 0xff && start[1] == 0xd8;
            input.Position = 0;
            var decoder = BitmapDecoder.Create(
                input,
                BitmapCreateOptions.PreservePixelFormat,
                BitmapCacheOption.OnLoad);
            if (decoder.Frames.Count == 0)
            {
                throw new NingRan.Core.NingRanException("所选文件不是可以读取的照片。");
            }

            frame = decoder.Frames[0];
        }

        if (frame.PixelWidth is <= 0 or > 50_000 || frame.PixelHeight is <= 0 or > 50_000)
        {
            throw new NingRan.Core.NingRanException("封面照片尺寸不正确或过大。");
        }

        if (isJpeg)
        {
            return new CoverImagePreparation(fullPath, null);
        }

        var temporaryDirectory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            ".ningran-cover-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporaryDirectory);
        var temporaryPath = System.IO.Path.Combine(temporaryDirectory, "cover.jpg");
        try
        {
            BitmapSource outputFrame = frame;
            const double maximumDimension = 4096;
            var scale = Math.Min(1d, maximumDimension / Math.Max(frame.PixelWidth, frame.PixelHeight));
            if (scale < 1d)
            {
                var resized = new TransformedBitmap(frame, new ScaleTransform(scale, scale));
                resized.Freeze();
                outputFrame = resized;
            }

            var encoder = new JpegBitmapEncoder { QualityLevel = 92 };
            encoder.Frames.Add(BitmapFrame.Create(outputFrame));
            using (var output = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.Read,
                       1024 * 1024,
                       FileOptions.WriteThrough))
            {
                encoder.Save(output);
                output.Flush(flushToDisk: true);
            }

            return new CoverImagePreparation(temporaryPath, temporaryDirectory);
        }
        catch
        {
            TryDelete(temporaryPath);
            TryDeleteDirectory(temporaryDirectory);
            throw;
        }
    }

    public void Dispose()
    {
        if (_temporaryDirectory is null)
        {
            return;
        }

        TryDelete(Path);
        TryDeleteDirectory(_temporaryDirectory);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: false); }
        catch { }
    }
}
