using Azure.Core;

namespace Andalus.Cryptography.KeyVault;

/// <summary />
public class KeyVaultCryptoProviderOptions
{
    /// <summary />
    public required Uri VaultId { get; init; }

    /// <summary />
    public TokenCredential? TokenCredential { get; set; }
}