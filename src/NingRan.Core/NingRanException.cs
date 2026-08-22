namespace NingRan.Core;

public sealed class NingRanException : Exception
{
    public NingRanException(string message)
        : base(message)
    {
    }

    public NingRanException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
