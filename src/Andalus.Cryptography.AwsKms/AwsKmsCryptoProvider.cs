using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using System.Security.Cryptography;

namespace Andalus.Cryptography.AwsKms;

/// <summary />
public class AwsKmsCryptoProvider : ICryptoProvider
{
    private readonly AmazonKeyManagementServiceClient _kms;


    /// <summary />
    public AwsKmsCryptoProvider( AwsKmsCryptoProviderOptions options )
    {
        _kms = options.KmsClient ?? new AmazonKeyManagementServiceClient();
    }


    /// <inheritdoc />
    public async Task<KeyReference> CreateKeyPairAsync(
        KeyCreationOptions options,
        CancellationToken cancellationToken = default )
    {
        var keySpec = MapKeyType( options.KeyType );

        var request = new CreateKeyRequest
        {
            KeySpec = keySpec,
            KeyUsage = KeyUsageType.SIGN_VERIFY,
            Description = options.KeyName,
            Tags = options.Metadata
                .Select( kv => new Tag { TagKey = kv.Key, TagValue = kv.Value } )
                .ToList(),
        };

        var response = await _kms.CreateKeyAsync( request, cancellationToken );


        // Create an alias so the key can be referenced by name
        await _kms.CreateAliasAsync( new CreateAliasRequest
        {
            AliasName = $"alias/{options.KeyName}",
            TargetKeyId = response.KeyMetadata.KeyId,
        }, cancellationToken );

        return new KeyReference
        {
            KeyId = response.KeyMetadata.Arn,
            KeyType = options.KeyType,
        };
    }


    /// <inheritdoc />
    public async Task<byte[]> GetPublicKeyAsync( KeyReference key, CancellationToken cancellationToken = default )
    {
        var response = await _kms.GetPublicKeyAsync( new GetPublicKeyRequest
        {
            KeyId = key.KeyId,
        }, cancellationToken );

        return response.PublicKey.ToArray();
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
        HashAlgorithmName? hashAlgorithm = null,
        CancellationToken cancellationToken = default )
    {
        var algorithm = MapSigningAlgorithm( key.KeyType, hashAlgorithm );

        var request = new SignRequest
        {
            KeyId = key.KeyId,
            Message = new MemoryStream( hash.ToArray() ),
            MessageType = MessageType.DIGEST,
            SigningAlgorithm = algorithm,
        };

        var response = await _kms.SignAsync( request, cancellationToken );

        return new SignResult
        {
            KeyVersion = response.KeyId,
            Signature = response.Signature.ToArray(),
        };
    }


    /// <inheritdoc />
    public async Task<bool> VerifyHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        ReadOnlyMemory<byte> signature,
        HashAlgorithmName? hashAlgorithm = null,
        CancellationToken cancellationToken = default )
    {
        var algorithm = MapSigningAlgorithm( key.KeyType, hashAlgorithm );

        var request = new VerifyRequest
        {
            KeyId = key.KeyId,
            Message = new MemoryStream( hash.ToArray() ),
            MessageType = MessageType.DIGEST,
            SigningAlgorithm = algorithm,
            Signature = new MemoryStream( signature.ToArray() ),
        };

        var response = await _kms.VerifyAsync( request, cancellationToken );

        return response.SignatureValid ?? false;
    }


    /// <summary />
    private static KeySpec MapKeyType( KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 => KeySpec.ECC_NIST_P256,
            KeyType.EcdsaP384 => KeySpec.ECC_NIST_P384,
            KeyType.EcdsaP521 => KeySpec.ECC_NIST_P521,
            KeyType.EcdsaSecp256k1 => KeySpec.ECC_SECG_P256K1,

            KeyType.RsaSha256 => KeySpec.RSA_2048,
            KeyType.RsaSha384 => KeySpec.RSA_3072,
            KeyType.RsaSha512 => KeySpec.RSA_4096,

            _ => throw new NotSupportedException( $"Key type '{keyType}' is not supported." )
        };
    }


    /// <summary />
    private static SigningAlgorithmSpec MapSigningAlgorithm( KeyType keyType, HashAlgorithmName? hashAlgorithm )
    {
        var m = keyType.Resolve();
        var han = hashAlgorithm ?? m.HashAlgorithmName;

        if ( m.KeyFamily == KeyFamily.Ecdsa )
        {
            return han.Name switch
            {
                "SHA256" => SigningAlgorithmSpec.ECDSA_SHA_256,
                "SHA384" => SigningAlgorithmSpec.ECDSA_SHA_384,
                "SHA512" => SigningAlgorithmSpec.ECDSA_SHA_512,

                _ => throw new NotSupportedException( $"Hash algorithm '{han.Name}' is not supported for ECDsa." )
            };
        }

        if ( m.KeyFamily == KeyFamily.Rsa )
        {
            return han.Name switch
            {
                "SHA256" => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
                "SHA384" => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384,
                "SHA512" => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512,

                _ => throw new NotSupportedException( $"Hash algorithm '{han.Name}' is not supported for RSA." )
            };
        }

        throw new NotSupportedException( $"No support for key family '{m.KeyFamily}'" );
    }
};