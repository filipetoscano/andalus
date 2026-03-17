namespace Andalus.Cryptography;

/// <summary>
/// Describes how to create a new key pair.
/// </summary>
public sealed class KeyCreationOptions
{
    /// <summary />
    public required KeyType KeyType { get; init; }

    /// <summary>
    /// Logical name / alias for the key inside the HSM.
    /// </summary>
    public required string KeyName { get; init; }

    /// <summary />
    public bool HardwareProtected { get; set; }

    /// <summary>
    /// Whether the private key can be exported. Most production
    /// HSMs should set this to false.
    /// </summary>
    public bool Exportable { get; init; } = false;

    /// <summary>
    /// Optional expiry. Null means no automatic rotation.
    /// </summary>
    public DateTimeOffset? MomentExpiry { get; init; }

    /// <summary>
    /// Vendor-specific metadata (tags, policies, etc.).
    /// </summary>
    public Dictionary<string, string> Tags { get; init; } = new Dictionary<string, string>();
}