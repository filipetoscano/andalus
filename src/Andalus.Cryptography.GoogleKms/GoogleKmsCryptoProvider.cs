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

        // Retrieve the public key
        var publicKey = await _kms.GetPublicKeyAsync( versionName, cancellationToken.ToCallSettings() );

        return new KeyReference
        {
            KeyId = versionName.ToString(),
            KeyType = options.KeyType,
            PublicKey = ConvertPemToBytes( publicKey.Pem ),
        };
    }


    /// <inheritdoc />
    public Task<KeyReference> ImportKeyPairAsync( KeyCreationOptions options, KeyPair keyPair, CancellationToken cancellationToken = default )
    {
        throw new NotImplementedException();
    }


    /// <inheritdoc />
    public async Task<SignResult> SignHashAsync(
        string keyId,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        var versionName = CryptoKeyVersionName.Parse( keyId );

        var digest = WrapDigest( hash, hashAlgorithm );

        var response = await _kms.AsymmetricSignAsync(
            versionName,
            digest,
            cancellationToken.ToCallSettings() );

        return new SignResult
        {
            KeyVersion = response.Name,
            Signature = response.Signature.ToByteArray(),
            Format = KeySignatureFormat.Der,
        };
    }


    /// <inheritdoc />
    public async Task<bool> VerifyHashAsync(
        string keyId,
        ReadOnlyMemory<byte> hash,
        ReadOnlyMemory<byte> signature,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        var versionName = CryptoKeyVersionName.Parse( keyId );

        // Retrieve the public key from KMS
        var publicKey = await _kms.GetPublicKeyAsync(
            versionName,
            cancellationToken.ToCallSettings() );

        var pemBytes = ConvertPemToBytes( publicKey.Pem );

        // Determine key type from the algorithm
        var algorithm = publicKey.Algorithm;

        if ( IsEcAlgorithm( algorithm ) )
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo( pemBytes, out _ );

            // GCP returns DER signatures, ECDsa.VerifyHash expects IEEE P1363 by default
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


    /// <inheritdoc />
    public Task RemoveKeyPairAsync( string keyId, CancellationToken cancellationToken = default )
    {
        throw new NotImplementedException();
    }


    /// <summary />
    private static bool IsEcAlgorithm( CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm algorithm )
    {
        return algorithm switch
        {
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256 => true,
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384 => true,
            CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignSecp256K1Sha256 => true,
            _ => false,
        };
    }


    /// <summary />
    private static CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm MapKeyType( KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP256Sha256,
            KeyType.EcdsaP384 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignP384Sha384,
            KeyType.EcdsaSecp256k1 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.EcSignSecp256K1Sha256,

            KeyType.RsaSha256 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs12048Sha256,
            KeyType.RsaSha384 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs13072Sha256,
            KeyType.RsaSha512 => CryptoKeyVersion.Types.CryptoKeyVersionAlgorithm.RsaSignPkcs14096Sha512,

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