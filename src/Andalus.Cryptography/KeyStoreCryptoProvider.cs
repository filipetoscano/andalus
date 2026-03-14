using System.Security.Cryptography;

namespace Andalus.Cryptography;

/// <summary />
public class KeyStoreCryptoProvider : ICryptoProvider
{
    private readonly IKeyStore _store;


    /// <summary />
    public KeyStoreCryptoProvider( IKeyStore store )
    {
        _store = store;
    }


    /// <inheritdoc />
    public Task<KeyReference> CreateKeyPairAsync( KeyCreationOptions options, CancellationToken cancellationToken = default )
    {
        KeyPair kp = options.KeyType switch
        {
            KeyType.EcdsaSecp256k1 => CreateEcKey( ECCurve.CreateFromValue( "1.3.132.0.10" ) ),
            KeyType.EcdsaP256 => CreateEcKey( ECCurve.NamedCurves.nistP256 ),
            KeyType.EcdsaP384 => CreateEcKey( ECCurve.NamedCurves.nistP384 ),
            KeyType.EcdsaP521 => CreateEcKey( ECCurve.NamedCurves.nistP521 ),

            KeyType.Rsa2048 => CreateRsaKey( 2048 ),
            KeyType.Rsa3072 => CreateRsaKey( 3072 ),
            KeyType.Rsa4096 => CreateRsaKey( 4096 ),
            _ => throw new NotSupportedException()
        };

        return ImportKeyPairAsync( options, kp, cancellationToken );
    }


    /// <inheritdoc />
    public async Task<byte[]> GetPublicKeyAsync( KeyReference key, CancellationToken cancellationToken = default )
    {
        var rec = await _store.RetrieveAsync( key.KeyId, cancellationToken );

        var field = PemEncoding.Find( rec.PublicKeyPem );

        if ( rec.PublicKeyPem[ field.Label ] is not "PUBLIC KEY" )
            throw new InvalidOperationException( $"Expected 'PUBLIC KEY' PEM block, found '{rec.PublicKeyPem[ field.Label ]}'." );

        return Convert.FromBase64String( rec.PublicKeyPem[ field.Base64Data ] );
    }


    /// <inheritdoc />
    public async Task<KeyReference> ImportKeyPairAsync(
        KeyCreationOptions options,
        KeyPair keyPair,
        CancellationToken cancellationToken = default )
    {
        var rec = new KeypairRecord()
        {
            KeyId = Guid.NewGuid().ToString(),
            KeyType = options.KeyType,
            Name = options.KeyName,
            PrivateKeyPem = keyPair.PrivatePem,
            PublicKeyPem = keyPair.PublicPem,
            MomentCreated = DateTime.UtcNow,
            MomentExpiry = options.MomentExpiry,
            Tags = options.Tags,
        };

        await _store.CreateAsync( rec, cancellationToken );

        return new KeyReference()
        {
            KeyId = rec.KeyId,
            KeyType = options.KeyType,
        };
    }


    /// <inheritdoc />
    public Task<RemoveResult> RemoveKeyPairAsync(
        KeyReference key,
        CancellationToken cancellationToken = default )
    {
        return _store.RemoveAsync( key.KeyId, cancellationToken );
    }


    /// <inheritdoc />
    public async Task<SignResult> SignHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        var family = key.KeyType.Family();
        var rec = await _store.RetrieveAsync( key.KeyId, cancellationToken );

        byte[] signature;

        if ( family == KeyFamily.Rsa )
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem( rec.PrivateKeyPem );

            signature = rsa.SignHash(
                hash.ToArray(),
                hashAlgorithm,
                RSASignaturePadding.Pkcs1 );
        }
        else
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem( rec.PrivateKeyPem );

            signature = ecdsa.SignHash(
                hash.ToArray(),
                DSASignatureFormat.Rfc3279DerSequence );
        }

        return new SignResult()
        {
            Signature = signature,
            KeyVersion = key,
        };
    }


    /// <inheritdoc />
    public async Task<bool> VerifyHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        ReadOnlyMemory<byte> signature,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        var family = key.KeyType.Family();
        var rec = await _store.RetrieveAsync( key.KeyId, cancellationToken );

        if ( family == KeyFamily.Rsa )
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem( rec.PublicKeyPem );

            return rsa.VerifyHash(
                hash.ToArray(),
                signature.ToArray(),
                hashAlgorithm,
                RSASignaturePadding.Pkcs1 );
        }
        else
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem( rec.PublicKeyPem );

            return ecdsa.VerifyHash(
                hash.ToArray(),
                signature.ToArray(),
                DSASignatureFormat.Rfc3279DerSequence );
        }
    }


    /// <summary />
    private static KeyPair CreateEcKey( ECCurve curve )
    {
        using var ecdsa = ECDsa.Create( curve );

        var privatePem = ecdsa.ExportECPrivateKeyPem();
        var publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();

        return new KeyPair()
        {
            PrivatePem = privatePem,
            PublicPem = publicPem,
        };
    }


    /// <summary />
    private static KeyPair CreateRsaKey( int keySizeBits )
    {
        using var rsa = RSA.Create( keySizeBits );

        var privatePem = rsa.ExportRSAPrivateKeyPem();
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();

        return new KeyPair()
        {
            PrivatePem = privatePem,
            PublicPem = publicPem,
        };
    }
}