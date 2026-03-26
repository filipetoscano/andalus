using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
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
            Tags = options.Tags
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
    public async Task<KeyReference> ImportKeyPairAsync(
        KeyCreationOptions options,
        KeyPair keyPair,
        CancellationToken cancellationToken = default )
    {
        var keySpec = MapKeyType( options.KeyType );
        var family = options.KeyType.Family();


        /*
         * #1. Create an empty key shell with EXTERNAL origin
         */
        var createResponse = await _kms.CreateKeyAsync( new CreateKeyRequest
        {
            KeySpec = keySpec,
            KeyUsage = KeyUsageType.SIGN_VERIFY,
            Origin = OriginType.EXTERNAL,
            Description = options.KeyName,
            Tags = options.Tags
                .Select( kv => new Tag { TagKey = kv.Key, TagValue = kv.Value } )
                .ToList(),
        }, cancellationToken );

        var keyId = createResponse.KeyMetadata.KeyId;
        var keyArn = createResponse.KeyMetadata.Arn;

        try
        {
            await _kms.CreateAliasAsync( new CreateAliasRequest
            {
                AliasName = $"alias/{options.KeyName}",
                TargetKeyId = keyId,
            }, cancellationToken );


            /*
             * #2. Get wrapping parameters.
             * ECDSA keys are small enough to wrap directly with RSAES_OAEP_SHA_256.
             * RSA private keys exceed the OAEP payload limit and require the two-layer
             * RSA_AES_KEY_WRAP scheme.
             */
            var wrappingAlgorithm = family == KeyFamily.Rsa
                ? AlgorithmSpec.RSA_AES_KEY_WRAP_SHA_256
                : AlgorithmSpec.RSAES_OAEP_SHA_256;

            var paramsResponse = await _kms.GetParametersForImportAsync( new GetParametersForImportRequest
            {
                KeyId = keyId,
                WrappingAlgorithm = wrappingAlgorithm,
                WrappingKeySpec = WrappingKeySpec.RSA_4096,
            }, cancellationToken );

            var wrappingPublicKeyDer = paramsResponse.PublicKey.ToArray();
            var importToken = paramsResponse.ImportToken.ToArray();


            /*
             * #3. Convert private key PEM to PKCS#8 DER (format KMS requires).
             * EC keys are stored as SEC1 ("EC PRIVATE KEY"); RSA as PKCS#1 ("RSA PRIVATE KEY").
             */
            var pkcs8 = ToPkcs8Der( keyPair, family );


            /*
             * #4. Wrap key material
             */
            var wrappedKey = family == KeyFamily.Rsa
                ? WrapRsaKeyMaterial( pkcs8, wrappingPublicKeyDer )
                : WrapEcKeyMaterial( pkcs8, wrappingPublicKeyDer );


            /*
             * #5. — Import
             */
            await _kms.ImportKeyMaterialAsync( new ImportKeyMaterialRequest
            {
                KeyId = keyId,
                ImportToken = new MemoryStream( importToken ),
                EncryptedKeyMaterial = new MemoryStream( wrappedKey ),
                ExpirationModel = ExpirationModelType.KEY_MATERIAL_DOES_NOT_EXPIRE,
            }, cancellationToken );

            return new KeyReference()
            {
                KeyId = keyArn,
                KeyType = options.KeyType,
            };
        }
        catch
        {
            // Delete the empty shell so it does not litter the account
            try
            {
                await _kms.ScheduleKeyDeletionAsync( new ScheduleKeyDeletionRequest
                {
                    KeyId = keyId,
                    PendingWindowInDays = 7,
                }, CancellationToken.None );
            }
            catch
            {
                // Ignore
            }

            throw;
        }
    }


    /// <summary>
    /// Converts the private key PEM in <paramref name="keyPair"/> to unencrypted PKCS#8 DER,
    /// the format AWS KMS requires for import.
    /// </summary>
    private static byte[] ToPkcs8Der( KeyPair keyPair, KeyFamily family )
    {
        if ( family == KeyFamily.Ecdsa )
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey( keyPair.GetPrivateKeyBytes(), out _ );

            return ecdsa.ExportPkcs8PrivateKey();
        }
        else
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey( keyPair.GetPrivateKeyBytes(), out _ );

            return rsa.ExportPkcs8PrivateKey();
        }
    }


    /// <summary>
    /// ECDSA path: encrypts PKCS#8 DER directly with RSA-OAEP-SHA256
    /// using the KMS-provided wrapping public key.
    /// </summary>
    private static byte[] WrapEcKeyMaterial( byte[] pkcs8, byte[] wrappingPublicKeyDer )
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo( wrappingPublicKeyDer, out _ );

        return rsa.Encrypt( pkcs8, RSAEncryptionPadding.OaepSHA256 );
    }


    /// <summary>
    /// RSA path: two-layer wrap.
    /// 1. Generate an ephemeral AES-256 key.
    /// 2. Wrap PKCS#8 DER with AES Key Wrap + Padding (RFC 5649).
    /// 3. Encrypt the AES key with the KMS wrapping public key via RSA-OAEP-SHA256.
    /// 4. Return: [encrypted AES key][AES-wrapped key material].
    /// </summary>
    private static byte[] WrapRsaKeyMaterial( byte[] pkcs8, byte[] wrappingPublicKeyDer )
    {
        var aesKey = RandomNumberGenerator.GetBytes( 32 );

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo( wrappingPublicKeyDer, out _ );

            var encryptedAesKey = rsa.Encrypt( aesKey, RSAEncryptionPadding.OaepSHA256 );

            // RFC 5649 handles arbitrary-length input (PKCS#8 is not guaranteed 8-byte aligned)
            var engine = new AesWrapPadEngine();
            engine.Init( true, new KeyParameter( aesKey ) );

            var wrappedKeyMaterial = engine.Wrap( pkcs8, 0, pkcs8.Length );

            var result = new byte[ encryptedAesKey.Length + wrappedKeyMaterial.Length ];
            encryptedAesKey.CopyTo( result, 0 );
            wrappedKeyMaterial.CopyTo( result, encryptedAesKey.Length );

            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory( aesKey );
        }
    }


    /// <inheritdoc />
    public async Task<RemoveResult> RemoveKeyPairAsync( KeyReference key, CancellationToken cancellationToken = default )
    {
        var request = new ScheduleKeyDeletionRequest
        {
            KeyId = key.KeyId,
            PendingWindowInDays = 7,
        };

        try
        {
            var response = await _kms.ScheduleKeyDeletionAsync( request, cancellationToken );

            // TODO: Use response.DeletionDate
            return new RemoveResult();
        }
        catch ( NotFoundException )
        {
            // TODO: Throw KeyNotFound
            throw;
        }
        catch ( KMSInvalidStateException ex )
        {
            throw new InvalidOperationException( "Key is already pending deletion, or disabled", ex );
        }
    }


    /// <inheritdoc />
    public async Task<SignResult> SignHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
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
        HashAlgorithmName hashAlgorithm,
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

            KeyType.Rsa2048 => KeySpec.RSA_2048,
            KeyType.Rsa3072 => KeySpec.RSA_3072,
            KeyType.Rsa4096 => KeySpec.RSA_4096,

            _ => throw new NotSupportedException( $"Key type '{keyType}' is not supported." )
        };
    }


    /// <summary />
    private static SigningAlgorithmSpec MapSigningAlgorithm( KeyType keyType, HashAlgorithmName hashAlgorithm )
    {
        var family = keyType.Family();
        var han = hashAlgorithm.Name;

        if ( family == KeyFamily.Rsa )
        {
            return han switch
            {
                "SHA256" => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
                "SHA384" => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384,
                "SHA512" => SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512,

                _ => throw new NotSupportedException( $"Hash algorithm '{han}' is not supported for RSA." )
            };
        }
        else
        {
            return han switch
            {
                "SHA256" => SigningAlgorithmSpec.ECDSA_SHA_256,
                "SHA384" => SigningAlgorithmSpec.ECDSA_SHA_384,
                "SHA512" => SigningAlgorithmSpec.ECDSA_SHA_512,

                _ => throw new NotSupportedException( $"Hash algorithm '{han}' is not supported for ECDsa." )
            };
        }
    }
};