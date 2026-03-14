namespace Andalus.Cryptography;

/// <summary />
public enum KeyType
{
    /// <summary />
    Rsa2048 = 1,

    /// <summary />
    Rsa3072,

    /// <summary />
    Rsa4096,

    /// <summary>
    /// NIST Prime 256
    /// </summary>
    EcdsaP256,

    /// <summary>
    /// NIST Prime 384
    /// </summary>
    EcdsaP384,

    /// <summary>
    /// NIST Prime 521
    /// </summary>
    EcdsaP521,

    /// <summary>
    /// Standards for Efficient Cryptography
    /// </summary>
    EcdsaSecp256k1,
}