using System.Security.Cryptography;

namespace Andalus.Cryptography;

/// <summary />
public class KeyPair
{
    /// <summary />
    public required string PublicPem { get; init; }

    /// <summary />
    public required string PrivatePem { get; init; }


    /// <summary />
    public byte[] GetPublicKeyBytes()
    {
        return Convert.FromBase64String( PublicPem[ PemEncoding.Find( PublicPem ).Base64Data ] );
    }


    /// <summary />
    public byte[] GetPrivateKeyBytes()
    {
        return Convert.FromBase64String( PrivatePem[ PemEncoding.Find( PrivatePem ).Base64Data ] );
    }
}