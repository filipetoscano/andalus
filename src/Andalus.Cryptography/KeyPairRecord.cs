namespace Andalus.Cryptography;

/// <summary />
public class KeypairRecord
{
    /// <summary>
    /// HSM-specific key identifier (e.g. Key Vault key URI, PKCS#11 handle, ARN).
    /// </summary>
    /// <remarks>
    /// Provider specific. Unique.
    /// </remarks>
    public required string KeyId { get; set; }

    /// <summary>
    /// The algorithm family/spec this key belongs to.
    /// </summary>
    public required KeyType KeyType { get; set; }

    /// <summary>
    /// Name of the keypair.
    /// </summary>
    /// <remarks>
    /// Provider agnostic. Unique.
    /// </remarks>
    public required string Name { get; set; }

    /// <summary>
    /// Public material, in PEM format.
    /// </summary>
    public required string PublicKeyPem { get; set; }

    /// <summary>
    /// Private material, in PEM format.
    /// </summary>
    public required string PrivateKeyPem { get; set; }

    /// <summary>
    /// Moment when the key was created.
    /// </summary>
    public required DateTimeOffset MomentCreated { get; set; }

    /// <summary>
    /// Moment when the key expires.
    /// </summary>
    public DateTimeOffset? MomentExpiry { get; set; }

    /// <summary>
    /// Collection of tags.
    /// </summary>
    public required Dictionary<string, string> Tags { get; set; }
}