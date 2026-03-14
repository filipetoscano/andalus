namespace Andalus.Cryptography;

/// <summary />
public enum KeyType
{
    /// <summary />
    RsaSha256 = 1,

    /// <summary />
    RsaSha384,

    /// <summary />
    RsaSha512,

    /// <summary />
    EcdsaP256,

    /// <summary />
    EcdsaP384,

    /// <summary />
    EcdsaP521,

    /// <summary />
    EcdsaSecp256k1,
}