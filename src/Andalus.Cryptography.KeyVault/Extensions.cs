using Azure.Security.KeyVault.Keys;

namespace Andalus.Cryptography;

/// <summary />
public static class Extensions
{
    /// <summary />
    public static KeyVaultKeyIdentifier ToKeyVaultIdentifier( this KeyReference value )
    {
        return new KeyVaultKeyIdentifier( new Uri( value.KeyId ) ); ;
    }
}
