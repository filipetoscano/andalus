namespace Andalus.Cryptography;

/// <summary />
public interface IKeyStore
{
    /// <summary />
    Task CreateAsync( KeypairRecord record, CancellationToken cancellationToken );

    /// <summary />
    Task<RemoveResult> RemoveAsync( string keyId, CancellationToken cancellationToken );

    /// <summary />
    Task<KeypairRecord> RetrieveAsync( string keyId, CancellationToken cancellationToken );
}