namespace Andalus.Cryptography;

/// <summary />
public static class Extensions
{
    /// <summary />
    public static KeyFamily Family( this KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 => KeyFamily.Ecdsa,
            KeyType.EcdsaP384 => KeyFamily.Ecdsa,
            KeyType.EcdsaP521 => KeyFamily.Ecdsa,
            KeyType.EcdsaSecp256k1 => KeyFamily.Ecdsa,

            KeyType.Rsa2048 => KeyFamily.Rsa,
            KeyType.Rsa3072 => KeyFamily.Rsa,
            KeyType.Rsa4096 => KeyFamily.Rsa,

            _ => throw new NotSupportedException( $"No mapping for key type '{keyType}'" ),
        };
    }
}