namespace Andalus.Cryptography;

/// <summary>
/// Represents a key.
/// </summary>
/// <remarks>
/// For (remote) HSM, the private material never leaves the HSM boundary:
/// only the identifier and public key are available locally.
/// </remarks>
public sealed class KeyReference
{
    /// <summary>
    /// HSM-specific key identifier (e.g. Key Vault key URI, PKCS#11 handle, ARN).
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// The algorithm family this key belongs to.
    /// </summary>
    public required KeyType KeyType { get; init; }

    /// <summary>
    /// The public key bytes (X.509 SubjectPublicKeyInfo / DER-encoded).
    /// Available locally for verification and KeyInfo embedding.
    /// </summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// Optional certificate chain associated with this key (leaf-first).
    /// Null if the HSM only stores a bare key pair.
    /// </summary>
    public IReadOnlyList<byte[]>? CertificateChain { get; init; }
}