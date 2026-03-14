namespace Andalus.Cryptography;

/// <summary />
public struct KeyPair
{
    /// <summary />
    public required KeyFamily KeyFamily { get; init; }

    /// <summary />
    public required string PublicPem { get; init; }

    /// <summary />
    public required string PrivatePem { get; init; }
}