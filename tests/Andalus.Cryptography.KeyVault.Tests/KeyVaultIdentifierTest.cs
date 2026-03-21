namespace Andalus.Cryptography.KeyVault.Tests;

public class KeyVaultIdentifierTest
{
    /// <summary />
    [Fact]
    public void ToKeyVaultIdentifier()
    {
        var keyRef = new KeyReference()
        {
            KeyId = "https://keyvault.vault.azure.net/keys/dev001/1e69839a-ff68-40f8-9516-22d2c048ba44",
            KeyType = KeyType.Rsa2048,
        };

        var actual = keyRef.ToKeyVaultIdentifier();

        Assert.Equal( "https://keyvault.vault.azure.net/", actual.VaultUri.ToString() );
        Assert.Equal( "dev001", actual.Name );
        Assert.Equal( "1e69839a-ff68-40f8-9516-22d2c048ba44", actual.Version );
    }


    /// <summary />
    [Fact]
    public void ToKeyVaultIdentifier_NoVersion()
    {
        var keyRef = new KeyReference()
        {
            KeyId = "https://keyvault.vault.azure.net/keys/dev001",
            KeyType = KeyType.Rsa2048,
        };

        var actual = keyRef.ToKeyVaultIdentifier();

        Assert.Equal( "https://keyvault.vault.azure.net/", actual.VaultUri.ToString() );
        Assert.Equal( "dev001", actual.Name );
        Assert.Null( actual.Version );
    }
}
