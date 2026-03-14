namespace Andalus.Cryptography;

/// <summary />
public enum KeyType
{
    /// <summary>
    /// RSA, with 2048 bit key size
    /// </summary>
    Rsa2048 = 1,

    /// <summary>
    /// RSA, with 3072 bit key size
    /// </summary>
    Rsa3072,

    /// <summary>
    /// RSA, with 4096 bit key size
    /// </summary>
    Rsa4096,

    /// <summary>
    /// ECDsa, with NIST Prime 256 curve
    /// </summary>
    EcdsaP256,

    /// <summary>
    /// ECDsa, with NIST Prime 384 curve
    /// </summary>
    EcdsaP384,

    /// <summary>
    /// ECDsa, with NIST Prime 521 curve
    /// </summary>
    EcdsaP521,

    /// <summary>
    /// ECDsa, with SECP K1 curve
    /// </summary>
    /// <remarks>
    /// SECP = Standards for Efficient Cryptography
    /// </remarks>
    EcdsaSecp256k1,
}