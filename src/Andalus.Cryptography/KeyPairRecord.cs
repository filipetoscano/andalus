namespace Andalus.Cryptography;

/// <summary />
public class KeypairRecord
{
    /// <summary />
    /// <remarks>
    /// Unique.
    /// </remarks>
    public required string KeyId { get; set; }

    /// <summary />
    public required KeyType KeyType { get; set; }

    /// <summary />
    /// <remarks>
    /// Unique.
    /// </remarks>
    public required string Name { get; set; }

    /// <summary />
    public required string PublicKeyPem { get; set; }

    /// <summary />
    public required string PrivateKeyPem { get; set; }

    /// <summary />
    public required DateTimeOffset MomentCreated { get; set; }

    /// <summary />
    public DateTimeOffset? MomentExpiry { get; set; }

    /// <summary />
    public required Dictionary<string, string> Tags { get; set; }
}