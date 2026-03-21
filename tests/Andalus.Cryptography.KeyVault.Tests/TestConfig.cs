namespace Andalus.Cryptography.KeyVault.Tests;

/// <summary />
internal class TestConfig
{
    /// <summary />
    internal static bool Enabled
    {
        get
        {
            return false;
        }
    }


    /// <summary />
    internal static Uri VaultId
    {
        get
        {
            var url = Environment.GetEnvironmentVariable( "KEYVAULT_VAULT" ) ?? throw new InvalidOperationException();

            return new Uri( url );
        }
    }
}