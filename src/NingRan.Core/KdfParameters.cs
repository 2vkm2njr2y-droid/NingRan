namespace NingRan.Core;

public sealed record KdfParameters(int MemoryKib, int Iterations, int Parallelism)
{
    private const int MinimumMemoryKib = 8 * 1024;
    private const int MaximumCompatibleMemoryKib = 256 * 1024;
    private const int MaximumCompatibleIterations = 3;
    private const int MaximumCompatibleParallelism = 4;

    public static KdfParameters Production { get; } = new(
        // Keep the default within a practical desktop memory budget. Existing
        // archives keep and validate the parameters stored in their header.
        MemoryKib: 64 * 1024,
        Iterations: 3,
        // The bundled Argon2 implementation is most reliable with one lane
        // across the supported Windows desktop environments.
        Parallelism: 1);

    public static KdfParameters Testing { get; } = new(
        MemoryKib: 8 * 1024,
        Iterations: 1,
        Parallelism: 1);

    public void ValidateForReading()
    {
        if (MemoryKib is < MinimumMemoryKib or > MaximumCompatibleMemoryKib ||
            Iterations is < 1 or > MaximumCompatibleIterations ||
            Parallelism is < 1 or > MaximumCompatibleParallelism)
        {
            throw new InvalidDataException(
                "加密文件中的密码保护参数超出当前版本的安全上限，已在耗用大量内存前停止处理。");
        }
    }
}
