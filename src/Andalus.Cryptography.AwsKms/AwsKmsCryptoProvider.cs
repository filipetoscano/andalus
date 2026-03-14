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


        // Retrieve the public key
        var pubKeyResponse = await _kms.GetPublicKeyAsync( new GetPublicKeyRequest
        {
            KeyId = response.KeyMetadata.KeyId,
        }, cancellationToken );


        return new KeyReference
        {
            KeyId = response.KeyMetadata.Arn,
            KeyType = options.KeyType,
            PublicKey = pubKeyResponse.PublicKey.ToArray(),
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
        var algorithm = MapSigningAlgorithm( hashAlgorithm );

        var request = new SignRequest
        {
            KeyId = keyId,
            Message = new MemoryStream( hash.ToArray() ),
            MessageType = MessageType.DIGEST,
            SigningAlgorithm = algorithm,
        };

        var response = await _kms.SignAsync( request, cancellationToken );

        return new SignResult
        {
            KeyVersion = response.KeyId,
            Signature = response.Signature.ToArray(),
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
        var algorithm = MapSigningAlgorithm( hashAlgorithm );

        var request = new VerifyRequest
        {
            KeyId = keyId,
            Message = new MemoryStream( hash.ToArray() ),
            MessageType = MessageType.DIGEST,
            SigningAlgorithm = algorithm,
            Signature = new MemoryStream( signature.ToArray() ),
        };

        var response = await _kms.VerifyAsync( request, cancellationToken );

        return response.SignatureValid ?? false;
    }


    /// <inheritdoc />
    public Task RemoveKeyPairAsync( string keyId, CancellationToken cancellationToken = default )
    {
        throw new NotImplementedException();
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
    private static SigningAlgorithmSpec MapSigningAlgorithm( HashAlgorithmName hashAlgorithm )
    {
        return hashAlgorithm.Name switch
        {
            "SHA256" => SigningAlgorithmSpec.ECDSA_SHA_256,
            "SHA384" => SigningAlgorithmSpec.ECDSA_SHA_384,
            "SHA512" => SigningAlgorithmSpec.ECDSA_SHA_512,

            _ => throw new NotSupportedException( $"Hash algorithm '{hashAlgorithm.Name}' is not supported." )
        };
    }
};