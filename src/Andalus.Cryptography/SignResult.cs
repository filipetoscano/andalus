namespace Andalus.Cryptography;

/// <summary>
/// The result of a remote signing operation.
/// </summary>
public sealed class SignResult
{
    /// <summary>
    /// DER encoded signature.
    /// </summary>
    public required byte[] Signature { get; set; }

    /// <summary>
    /// Identifier of the specific key version used for signing,
    /// useful for audit trails.
    /// </summary>
    public required string KeyVersion { get; init; }
}