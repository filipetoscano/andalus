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

    /// <summary>
    /// Whether the private key should be hardware protected.
    /// </summary>
    /// <remarks>
    /// Not applicable for all providers.
    /// </remarks>
    public bool HardwareProtected { get; set; }

    /// <summary>
    /// Whether the private key can be exported.
    /// </summary>
    /// <remarks>
    /// Most production HSMs should set this to false.
    /// </remarks>
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