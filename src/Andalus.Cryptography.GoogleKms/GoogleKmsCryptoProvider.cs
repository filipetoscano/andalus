using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using System.Security.Cryptography;

namespace Andalus.Cryptography.GoogleKms;

/// <summary />
public class GoogleKmsCryptoProvider : ICryptoProvider
{
    private readonly KeyManagementServiceClient _kms;
    private readonly KeyRingName _keyRing;


    /// <summary />
    public GoogleKmsCryptoProvider( GoogleKmsCryptoProviderOptions options )
    {
        _kms = options.KmsClient ?? KeyManagementServiceClient.Create();

        _keyRing = new KeyRingName(
            options.ProjectId,
            options.LocationId,
            options.KeyRingId );
    }


    /// <inheritdoc />
    public async Task<KeyReference> CreateKeyPairAsync(
        KeyCreationOptions options,
        CancellationToken cancellationToken = default )
    {
        var algorithm = MapKeyType( options.KeyType );
        var protection = ProtectionLevel.Hsm;

        var cryptoKey = new CryptoKey
        {
            Purpose = CryptoKey.Types.CryptoKeyPurpose.AsymmetricSign,
            VersionTemplate = new CryptoKeyVersionTemplate
            {
                Algorithm = algorithm,
                ProtectionLevel = protection,
            },
            Labels = { options.Metadata.ToDictionary( kv => kv.Key, kv => kv.Value ) },
        };

        if ( options.MomentExpiry.HasValue == true )
        {
            var ts = options.MomentExpiry.Value - DateTimeOffset.UtcNow;
            cryptoKey.DestroyScheduledDuration = Duration.FromTimeSpan( ts );
        }

        var created = await _kms.CreateCryptoKeyAsync(
            _keyRing,
            options.KeyName,
            cryptoKey,
            cancellationToken.ToCallSettings() );

        // The first version is created automatically
        var versionName = new CryptoKeyVersionName(
            _keyRing.ProjectId,
            _keyRing.LocationId,
            _keyRing.KeyRingId,
            options.KeyName,
            "1" );

        // Wait for the version to be enabled
        CryptoKeyVersion version;

        do
        {
            version = await _kms.GetCryptoKeyVersionAsync( versionName, cancellationToken.ToCallSettings() );

            if ( version.State == CryptoKeyVersion.Types.CryptoKeyVersionState.PendingGeneration )
                await Task.Delay( 500, cancellationToken );
        }
        while ( version.State == CryptoKeyVersion.Types.CryptoKeyVersionState.PendingGeneration );

        return new KeyReference
        {
            KeyId = versionName.ToString(),
            KeyType = options.KeyType,
        };
    }


    /// <inheritdoc />
    public async Task<byte[]> GetPublicKeyAsync( KeyReference key, CancellationToken cancellationToken = default )
    {
        var versionName = CryptoKeyVersionName.Parse( key.KeyId );
        var publicKey = await _kms.GetPublicKeyAsync( versionName, cancellationToken.ToCallSettings() );

        var pemBytes = ConvertPemToBytes( publicKey.Pem );

        return pemBytes;
    }


    /// <inheritdoc />
    public Task<KeyReference> ImportKeyPairAsync( KeyCreationOptions options, KeyPair keyPair, CancellationToken cancellationToken = default )
    {
        throw new NotImplementedException();
    }


    /// <inheritdoc />
    public Task<RemoveResult> RemoveKeyPairAsync( KeyReference key, CancellationToken cancellationToken = default )
    {
        throw new NotImplementedException();
    }


    /// <inheritdoc />
    public async Task<SignResult> SignHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        var versionName = CryptoKeyVersionName.Parse( key.KeyId );

        var digest = WrapDigest( hash, hashAlgorithm );

        var response = await _kms.AsymmetricSignAsync(
            versionName,
            digest,
            cancellationToken.ToCallSettings() );

        return new SignResult
        {
            KeyVersion = response.Name,
            Signature = response.Signature.ToByteArray(),
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
        var versionName = CryptoKeyVersionName.Parse( key.KeyId );
        var family = key.KeyType.Family();

        // Retrieve the public key from KMS
        var publicKey = await _kms.GetPublicKeyAsync(
            versionName,
            cancellationToken.ToCallSettings() );

        var pemBytes = ConvertPemToBytes( publicKey.Pem );

        if ( family == KeyFamily.Ecdsa )
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo( pemBytes, out _ );

            return ecdsa.VerifyHash(
                hash.Span,
                signature.Span,
                DSASignatureFormat.Rfc3279DerSequence );
        }
        else
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo( pemBytes, out _ );

            return rsa.VerifyHash(
                hash.ToArray(),
                signature.ToArray(),
                hashAlgorithm,
                RSASignaturePadding.Pkcs1 );
        }
    }


    /// <summary />
    private static CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm MapKeyType( KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256,
            KeyType.EcdsaP384 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384,
            KeyType.EcdsaSecp256k1 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignSecp256K1Sha256,

            KeyType.Rsa2048 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs12048Sha256,
            KeyType.Rsa3072 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs13072Sha256,
            KeyType.Rsa4096 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs14096Sha512,

            _ => throw new NotSupportedException( $"Key type '{keyType}' is not supported." )
        };
    }


    /// <summary />
    private static Digest WrapDigest( ReadOnlyMemory<byte> hash, HashAlgorithmName hashAlgorithm )
    {
        var digest = new Digest();

        switch ( hashAlgorithm.Name )
        {
            case "SHA256":
                digest.Sha256 = ByteString.CopyFrom( hash.Span );
                break;

            case "SHA384":
                digest.Sha384 = ByteString.CopyFrom( hash.Span );
                break;

            case "SHA512":
                digest.Sha512 = ByteString.CopyFrom( hash.Span );
                break;

            default:
                throw new NotSupportedException( $"Hash algorithm '{hashAlgorithm.Name}' is not supported." );
        }

        return digest;
    }


    /// <summary />
    private static byte[] ConvertPemToBytes( string pem )
    {
        var field = PemEncoding.Find( pem );

        if ( pem[ field.Label ] is not "PUBLIC KEY" )
            throw new InvalidOperationException( $"Expected 'PUBLIC KEY' PEM block, found '{pem[ field.Label ]}'." );

        return Convert.FromBase64String( pem[ field.Base64Data ] );
    }
}