namespace Andalus.Cryptography;

/// <summary />
public class RemoveResult
{
    /// <summary>
    /// Waits for the removal to complete.
    /// </summary>
    public Task? CompleteAsync { get; set; }
}