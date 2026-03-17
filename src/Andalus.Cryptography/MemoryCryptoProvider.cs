namespace Andalus.Cryptography;

/// <summary />
public class MemoryCryptoProvider : KeyStoreCryptoProvider, ICryptoProvider
{
    /// <summary />
    public MemoryCryptoProvider()
        : base( new MemoryKeyStore() )
    {
    }
}