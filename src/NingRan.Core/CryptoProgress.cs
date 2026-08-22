namespace NingRan.Core;

public enum CryptoStage
{
    Preparing,
    DerivingKey,
    Encrypting,
    Verifying,
    Decrypting,
    Finalizing,
}

public sealed record CryptoProgress(
    CryptoStage Stage,
    long CompletedBytes,
    long TotalBytes,
    string Message,
    TimeSpan? EstimatedRemaining = null)
{
    public double Fraction => TotalBytes <= 0
        ? 0
        : Math.Clamp((double)CompletedBytes / TotalBytes, 0, 1);
}
