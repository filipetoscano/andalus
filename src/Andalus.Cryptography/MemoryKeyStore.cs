using System.Collections.Concurrent;

namespace Andalus.Cryptography;

/// <summary />
public class MemoryKeyStore : IKeyStore
{
    private readonly ConcurrentDictionary<string, KeypairRecord> _store;


    /// <summary />
    public MemoryKeyStore()
    {
        _store = new ConcurrentDictionary<string, KeypairRecord>();
    }


    /// <inheritdoc />
    public Task CreateAsync( KeypairRecord record, CancellationToken cancellationToken )
    {
        _store.AddOrUpdate( record.KeyId, record, ( k, v ) =>
        {
            record.MomentCreated = v.MomentCreated;

            return record;
        } );

        return Task.CompletedTask;
    }


    /// <inheritdoc />
    public Task<RemoveResult> RemoveAsync( string keyId, CancellationToken cancellationToken )
    {
        _store.Remove( keyId, out _ );

        return Task.FromResult( new RemoveResult() );
    }


    /// <inheritdoc />
    public Task<KeypairRecord> RetrieveAsync( string keyId, CancellationToken cancellationToken )
    {
        var v = _store.GetValueOrDefault( keyId );

        if ( v == null )
            throw new KeyNotFoundException( $"Key '{keyId}' not found." );

        return Task.FromResult( v );
    }
}