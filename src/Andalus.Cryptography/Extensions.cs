using System.Security.Cryptography;

namespace Andalus.Cryptography;

/// <summary />
public static class Extensions
{
    /// <summary />
    public static (KeyFamily KeyFamily, HashAlgorithmName HashAlgorithmName) Resolve( this KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 => (KeyFamily.Ecdsa, HashAlgorithmName.SHA256),
            KeyType.EcdsaP384 => (KeyFamily.Ecdsa, HashAlgorithmName.SHA384),
            KeyType.EcdsaP521 => (KeyFamily.Ecdsa, HashAlgorithmName.SHA512),
            KeyType.EcdsaSecp256k1 => (KeyFamily.Ecdsa, HashAlgorithmName.SHA256),

            KeyType.RsaSha256 => (KeyFamily.Rsa, HashAlgorithmName.SHA256),
            KeyType.RsaSha384 => (KeyFamily.Rsa, HashAlgorithmName.SHA384),
            KeyType.RsaSha512 => (KeyFamily.Rsa, HashAlgorithmName.SHA512),

            _ => throw new NotSupportedException( $"No mapping for key type '{keyType}'" ),
        };
    }


    /// <summary />
    public static KeyFamily Family( this KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 => KeyFamily.Ecdsa,
            KeyType.EcdsaP384 => KeyFamily.Ecdsa,
            KeyType.EcdsaP521 => KeyFamily.Ecdsa,
            KeyType.EcdsaSecp256k1 => KeyFamily.Ecdsa,

            KeyType.RsaSha256 => KeyFamily.Rsa,
            KeyType.RsaSha384 => KeyFamily.Rsa,
            KeyType.RsaSha512 => KeyFamily.Rsa,

            _ => throw new NotSupportedException( $"No mapping for key type '{keyType}'" ),
        };
    }


    /// <summary />
    public static HashAlgorithmName HashAlgorithm( this KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 => HashAlgorithmName.SHA256,
            KeyType.EcdsaP384 => HashAlgorithmName.SHA384,
            KeyType.EcdsaP521 => HashAlgorithmName.SHA512,
            KeyType.EcdsaSecp256k1 => HashAlgorithmName.SHA256,

            KeyType.RsaSha256 => HashAlgorithmName.SHA256,
            KeyType.RsaSha384 => HashAlgorithmName.SHA384,
            KeyType.RsaSha512 => HashAlgorithmName.SHA512,

            _ => throw new NotSupportedException( $"No mapping for key type '{keyType}'" ),
        };
    }
}