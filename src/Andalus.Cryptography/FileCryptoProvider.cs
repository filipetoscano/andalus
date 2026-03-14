namespace Andalus.Cryptography;

/// <summary />
public class FileCryptoProvider : KeyStoreCryptoProvider, ICryptoProvider
{
    /// <summary />
    public FileCryptoProvider( FilesystemKeyStoreOptions options )
        : base( new FilesystemKeyStore( options ) )
    {
    }
}