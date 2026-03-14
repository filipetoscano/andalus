using System.Security.Cryptography;
using System.Text.Json;

namespace Andalus.Cryptography;

/// <summary />
public class FileCryptoProvider : ICryptoProvider
{
    private readonly FileCryptoProviderOptions _options;
    private readonly string _root;


    /// <summary />
    public FileCryptoProvider( FileCryptoProviderOptions options )
    {
        _options = options;

        _root = Path.Combine( Environment.CurrentDirectory, _options.RootDirectory );
        Directory.CreateDirectory( _root );
    }


    /// <inheritdoc />
    public async Task<KeyReference> CreateKeyPairAsync( KeyCreationOptions options, CancellationToken cancellationToken = default )
    {
        var keyId = Guid.NewGuid().ToString();
        var keyDir = Path.Combine( _root, keyId );
        Directory.CreateDirectory( keyDir );

        KeyPair kp = options.KeyType switch
        {
            KeyType.EcdsaSecp256k1 => CreateEcKey( ECCurve.CreateFromValue( "1.3.132.0.10" ), keyDir ),
            KeyType.EcdsaP256 => CreateEcKey( ECCurve.NamedCurves.nistP256, keyDir ),
            KeyType.EcdsaP384 => CreateEcKey( ECCurve.NamedCurves.nistP384, keyDir ),
            KeyType.EcdsaP521 => CreateEcKey( ECCurve.NamedCurves.nistP521, keyDir ),

            KeyType.RsaSha256 => CreateRsaKey( options.RsaKeySizeBits ?? 256 * 8, keyDir ),
            KeyType.RsaSha384 => CreateRsaKey( options.RsaKeySizeBits ?? 384 * 8, keyDir ),
            KeyType.RsaSha512 => CreateRsaKey( options.RsaKeySizeBits ?? 512 * 8, keyDir ),
            _ => throw new NotSupportedException( $"Key type '{options.KeyType}' is not supported." )
        };

        var metadata = new KeyMetadata()
        {
            KeyName = options.KeyName,
            KeyFamily = kp.KeyFamily,
            KeyType = options.KeyType,
            MomentCreated = DateTimeOffset.UtcNow,
            MomentExpiry = options.MomentExpiry,
            Tags = new Dictionary<string, string>( options.Metadata ),
        };

        await File.WriteAllTextAsync( GetPrivateKeyPath( keyId ), kp.PrivatePem, cancellationToken );
        await File.WriteAllTextAsync( GetPublicKeyPath( keyId ), kp.PublicPem, cancellationToken );
        await WriteMetadataAsync( keyId, metadata, cancellationToken );


        /*
         * 
         */
        //var publicKey = Convert.FromBase64String( PemEncoding.Find( kp.PublicPem ).Base64Data.ToString() );

        return new KeyReference()
        {
            KeyId = keyId,
            KeyType = options.KeyType,
            PublicKey = [],
        };
    }


    /// <inheritdoc />
    public async Task<KeyReference> ImportKeyPairAsync(
        KeyCreationOptions options,
        KeyPair keyPair,
        CancellationToken cancellationToken = default )
    {
        var keyId = Guid.NewGuid().ToString();
        var keyDir = Path.Combine( _root, keyId );
        Directory.CreateDirectory( keyDir );

        var metadata = new KeyMetadata()
        {
            KeyName = options.KeyName,
            KeyFamily = keyPair.KeyFamily,
            KeyType = options.KeyType,
            MomentCreated = DateTimeOffset.UtcNow,
            MomentExpiry = options.MomentExpiry,
            Tags = new Dictionary<string, string>( options.Metadata ),
        };

        await File.WriteAllTextAsync( GetPrivateKeyPath( keyId ), keyPair.PrivatePem, cancellationToken );
        await File.WriteAllTextAsync( GetPublicKeyPath( keyId ), keyPair.PublicPem, cancellationToken );
        await WriteMetadataAsync( keyId, metadata, cancellationToken );

        return new KeyReference()
        {
            KeyId = keyId,
            KeyType = options.KeyType,
            PublicKey = [],
        };
    }


    /// <inheritdoc />
    public async Task<SignResult> SignHashAsync( string keyId, ReadOnlyMemory<byte> hash, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default )
    {
        var metadata = await ReadMetadataAsync( keyId, cancellationToken );

        var privatePem = await File.ReadAllTextAsync(
            GetPrivateKeyPath( keyId ),
            cancellationToken );

        byte[] signature;

        if ( metadata.KeyFamily == KeyFamily.Rsa )
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem( privatePem );

            signature = rsa.SignHash(
                hash.ToArray(),
                hashAlgorithm,
                RSASignaturePadding.Pkcs1 );
        }
        else
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem( privatePem );

            signature = ecdsa.SignHash(
                hash.ToArray(),
                DSASignatureFormat.Rfc3279DerSequence );
        }

        return new SignResult()
        {
            Signature = signature,
            KeyVersion = keyId,
        };
    }


    /// <inheritdoc />
    public async Task<bool> VerifyHashAsync( string keyId, ReadOnlyMemory<byte> hash, ReadOnlyMemory<byte> signature, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default )
    {
        var metadata = await ReadMetadataAsync( keyId, cancellationToken );

        var publicPem = await File.ReadAllTextAsync(
            GetPublicKeyPath( keyId ),
            cancellationToken );

        if ( metadata.KeyFamily == KeyFamily.Rsa )
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem( publicPem );

            return rsa.VerifyHash(
                hash.ToArray(),
                signature.ToArray(),
                hashAlgorithm,
                RSASignaturePadding.Pkcs1 );
        }
        else
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem( publicPem );

            return ecdsa.VerifyHash(
                hash.ToArray(),
                signature.ToArray(),
                DSASignatureFormat.Rfc3279DerSequence );
        }
    }



    /// <inheritdoc />
    public Task RemoveKeyPairAsync( string keyId, CancellationToken cancellationToken = default )
    {
        var keyDir = Path.Combine( _root, keyId );
        Directory.Delete( keyDir, true );

        return Task.CompletedTask;
    }




    /// <summary />
    private static KeyPair CreateEcKey( ECCurve curve, string keyDir )
    {
        using var ecdsa = ECDsa.Create( curve );

        var privatePem = ecdsa.ExportECPrivateKeyPem();
        var publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();

        return new KeyPair()
        {
            KeyFamily = KeyFamily.Ecdsa,
            PrivatePem = privatePem,
            PublicPem = publicPem,
        };
    }


    /// <summary />
    private static KeyPair CreateRsaKey( int keySizeBits, string keyDir )
    {
        using var rsa = RSA.Create( keySizeBits );

        var privatePem = rsa.ExportRSAPrivateKeyPem();
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();

        return new KeyPair()
        {
            KeyFamily = KeyFamily.Rsa,
            PrivatePem = privatePem,
            PublicPem = publicPem,
        };
    }


    /// <summary />
    private string GetPrivateKeyPath( string keyId ) => Path.Combine( _root, keyId, "private.pem" );

    /// <summary />
    private string GetPublicKeyPath( string keyId ) => Path.Combine( _root, keyId, "public.pem" );


    /// <summary />
    private async Task WriteMetadataAsync( string keyId, KeyMetadata meta, CancellationToken cancellationToken )
    {
        var path = Path.Combine( _root, keyId, "metadata.json" );

        await File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize( meta, _jsonOptions ),
            cancellationToken );
    }


    /// <summary />
    private async Task<KeyMetadata> ReadMetadataAsync( string keyId, CancellationToken cancellationToken )
    {
        var path = Path.Combine( _root, keyId, "metadata.json" );

        if ( File.Exists( path ) == false )
            throw new CryptographicException( $"Key '{keyId}' not found." );

        var json = await File.ReadAllTextAsync( path, cancellationToken );

        return JsonSerializer.Deserialize<KeyMetadata>( json, _jsonOptions )
            ?? throw new CryptographicException( $"Invalid metadata for key '{keyId}'." );
    }


    /// <summary />
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };


    /// <summary />
    private sealed class KeyMetadata
    {
        /// <summary />
        public required string KeyName { get; init; }

        /// <summary />
        public required KeyFamily KeyFamily { get; set; }

        /// <summary />
        public required KeyType KeyType { get; init; }

        /// <summary />
        public DateTimeOffset MomentCreated { get; init; }

        /// <summary />
        public DateTimeOffset? MomentExpiry { get; init; }

        /// <summary />
        public Dictionary<string, string> Tags { get; init; } = new();
    }
}