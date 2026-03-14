using System.Text.Json;
using System.Text.Json.Serialization;

namespace Andalus.Cryptography;

/// <summary />
public class FilesystemKeyStore : IKeyStore
{
    private readonly string _root;


    /// <summary />
    public FilesystemKeyStore( FilesystemKeyStoreOptions options )
    {
        _root = Path.Combine( Environment.CurrentDirectory, options.RootDirectory );
        Directory.CreateDirectory( _root );
    }


    /// <inheritdoc />
    public async Task CreateAsync( KeypairRecord record, CancellationToken cancellationToken )
    {
        var dirpath = Path.Combine( _root, record.KeyId );
        Directory.CreateDirectory( dirpath );

        var fmet = Path.Combine( dirpath, "metadata.json" );
        var fkey = Path.Combine( dirpath, "private.txt" );
        var fpub = Path.Combine( dirpath, "public.txt" );

        await File.WriteAllTextAsync( fkey, record.PrivateKeyPem );
        await File.WriteAllTextAsync( fpub, record.PublicKeyPem );


        /*
         * 
         */
        var meta = new KeypairMetadata()
        {
            KeyType = record.KeyType,
            KeyName = record.Name,
            MomentCreated = record.MomentCreated,
            MomentExpiry = record.MomentExpiry,
            Tags = record.Tags,
        };

        var json = JsonSerializer.Serialize( meta, _jso );
        await File.WriteAllTextAsync( fmet, json );
    }


    /// <inheritdoc />
    public Task<RemoveResult> RemoveAsync( string keyId, CancellationToken cancellationToken )
    {
        var dirpath = Path.Combine( _root, keyId );
        Directory.Delete( dirpath, true );

        return Task.FromResult( new RemoveResult() );
    }


    /// <inheritdoc />
    public async Task<KeypairRecord> RetrieveAsync( string keyId, CancellationToken cancellationToken )
    {
        var dirpath = Path.Combine( _root, keyId );
        var fmet = Path.Combine( dirpath, "metadata.json" );
        var fkey = Path.Combine( dirpath, "private.txt" );
        var fpub = Path.Combine( dirpath, "public.txt" );

        var json = await File.ReadAllTextAsync( fmet );
        var meta = JsonSerializer.Deserialize<KeypairMetadata>( json, _jso )!;

        var privateKey = await File.ReadAllTextAsync( fkey );
        var publicKey = await File.ReadAllTextAsync( fpub );

        return new KeypairRecord()
        {
            KeyId = keyId,
            KeyType = meta.KeyType,
            Name = meta.KeyName,
            MomentCreated = meta.MomentCreated,
            MomentExpiry = meta.MomentExpiry,
            PrivateKeyPem = privateKey,
            PublicKeyPem = publicKey,
            Tags = meta.Tags,
        };
    }


    /// <summary />
    private static readonly JsonSerializerOptions _jso = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };


    /// <summary />
    internal sealed class KeypairMetadata
    {
        /// <summary />
        public required string KeyName { get; init; }

        /// <summary />
        public required KeyType KeyType { get; init; }

        /// <summary />
        public required DateTimeOffset MomentCreated { get; init; }

        /// <summary />
        public DateTimeOffset? MomentExpiry { get; init; }

        /// <summary />
        public required Dictionary<string, string> Tags { get; init; }
    }
}