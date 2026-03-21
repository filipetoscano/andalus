using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;

namespace Andalus.Cryptography.KeyVault;

/// <summary />
public class KeyVaultCryptoProvider : ICryptoProvider
{
    private readonly TokenCredential _credential;
    private readonly KeyClient _kc;


    /// <summary />
    public KeyVaultCryptoProvider( KeyVaultCryptoProviderOptions options )
    {
        _credential = options.TokenCredential ?? new DefaultAzureCredential();

        _kc = new KeyClient(
            options.VaultId,
            _credential
        );
    }


    /// <inheritdoc />
    public async Task<KeyReference> CreateKeyPairAsync( KeyCreationOptions options, CancellationToken cancellationToken = default )
    {
        KeyVaultKey key = options.KeyType switch
        {
            KeyType.EcdsaP256 => await CreateEcKeyAsync( options, KeyCurveName.P256, cancellationToken ),
            KeyType.EcdsaP384 => await CreateEcKeyAsync( options, KeyCurveName.P384, cancellationToken ),
            KeyType.EcdsaP521 => await CreateEcKeyAsync( options, KeyCurveName.P521, cancellationToken ),
            KeyType.EcdsaSecp256k1 => await CreateEcKeyAsync( options, KeyCurveName.P256K, cancellationToken ),

            KeyType.Rsa2048 => await CreateRsaKeyAsync( options, 2048, cancellationToken ),
            KeyType.Rsa3072 => await CreateRsaKeyAsync( options, 3072, cancellationToken ),
            KeyType.Rsa4096 => await CreateRsaKeyAsync( options, 4096, cancellationToken ),

            _ => throw new NotSupportedException( $"Key type '{options.KeyType}' is not supported." )
        };

        return new KeyReference()
        {
            KeyId = key.Id.ToString(),
            KeyType = options.KeyType,
        };
    }


    /// <inheritdoc />
    public async Task<byte[]> GetPublicKeyAsync( KeyReference key, CancellationToken cancellationToken = default )
    {
        var family = key.KeyType.Family();
        var kid = new KeyVaultKeyIdentifier( new Uri( key.KeyId ) );

        var kv = await _kc.GetKeyAsync( kid.Name, kid.Version, cancellationToken );

        if ( family == KeyFamily.Ecdsa )
        {
            using var ecdsa = kv.Value.Key.ToECDsa( false );
            return ecdsa.ExportSubjectPublicKeyInfo();
        }
        else
        {
            using var rsa = kv.Value.Key.ToRSA( false );
            return rsa.ExportSubjectPublicKeyInfo();
        }
    }


    /// <inheritdoc />
    public async Task<KeyReference> ImportKeyPairAsync( KeyCreationOptions options, KeyPair keyPair, CancellationToken cancellationToken = default )
    {
        var family = options.KeyType.Family();
        JsonWebKey jwk;

        if ( family == KeyFamily.Ecdsa )
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey( keyPair.GetPrivateKeyBytes(), out _ );

            jwk = new JsonWebKey( ecdsa, includePrivateParameters: true );
        }
        else
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey( keyPair.GetPrivateKeyBytes(), out _ );

            jwk = new JsonWebKey( rsa, includePrivateParameters: true );
        }


        /*
         * 
         */
        var importOptions = new ImportKeyOptions( options.KeyName, jwk )
        {
            HardwareProtected = options.HardwareProtected,
        };

        importOptions.Properties.Enabled = true;
        importOptions.Properties.ExpiresOn = options.MomentExpiry;
        importOptions.Properties.Exportable = options.Exportable;
        ApplyMetadata( importOptions.Properties.Tags, options.Tags );

        var key = await _kc.ImportKeyAsync( importOptions, cancellationToken );

        return new KeyReference()
        {
            KeyId = key.Value.Id.ToString(),
            KeyType = options.KeyType,
        };
    }


    /// <inheritdoc />
    public async Task<RemoveResult> RemoveKeyPairAsync( KeyReference key, CancellationToken cancellationToken = default )
    {
        var kid = new KeyVaultKeyIdentifier( new Uri( key.KeyId ) );

        var op = await _kc.StartDeleteKeyAsync( kid.Name, cancellationToken );

        return new RemoveResult()
        {
            CompleteAsync = op.WaitForCompletionAsync().AsTask(),
        };
    }


    /// <inheritdoc />
    public async Task<SignResult> SignHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        var family = key.KeyType.Family();
        var bytes = hash.ToArray();
        var sigAlgo = ToSignatureAlgorithm( key.KeyType, hashAlgorithm );

        if ( family == KeyFamily.Ecdsa )
            CheckHashAlgorithm( key.KeyType, hashAlgorithm );


        /*
         * 
         */
        var kid = new KeyVaultKeyIdentifier( new Uri( key.KeyId ) );
        var client = _kc.GetCryptographyClient( kid.Name, kid.Version );
        var result = await client.SignAsync( sigAlgo, bytes, cancellationToken );


        /*
         * 
         */
        byte[] signature;

        if ( family == KeyFamily.Ecdsa )
            signature = SignatureFormat.ConvertIeeeP1363ToDer( result.Signature, key.KeyType.CurveOrder() );
        else
            signature = result.Signature;

        return new SignResult()
        {
            KeyVersion = kid.Version,
            Signature = signature,
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
        var hashBytes = hash.ToArray();
        var signBytes = signature.ToArray();
        var sigAlgo = ToSignatureAlgorithm( key.KeyType, hashAlgorithm );

        if ( family == KeyFamily.Ecdsa )
        {
            CheckHashAlgorithm( key.KeyType, hashAlgorithm );
            signBytes = SignatureFormat.ConvertDerToIeeeP1363( signBytes, key.KeyType.CurveOrder() );
        }


        /*
         * 
         */
        var kid = new KeyVaultKeyIdentifier( new Uri( key.KeyId ) );
        var client = _kc.GetCryptographyClient( kid.Name, kid.Version );
        var result = await client.VerifyAsync( sigAlgo, hashBytes, signBytes, cancellationToken );

        return result.IsValid;
    }


    /// <summary>
    /// For ECDsa keys, KeyVault follows RFC 7518 (JWA) where the ES* algorithms pair
    /// the key/curve with the hash algorithm.
    /// </summary>
    /// <remarks>
    /// This is not the case with RSA, where any hash can be used regardless of the
    /// key size.
    /// </remarks>
    private void CheckHashAlgorithm( KeyType keyType, HashAlgorithmName hashAlgorithm )
    {
        if ( keyType == KeyType.EcdsaP256 && hashAlgorithm.Name != "SHA256" )
            throw new ArgumentOutOfRangeException( "KeyVault requires SHA-256 for EcdsaP256 keys" );

        if ( keyType == KeyType.EcdsaSecp256k1 && hashAlgorithm.Name != "SHA256" )
            throw new ArgumentOutOfRangeException( "KeyVault requires SHA-256 for EcdsaSecp256k1 keys" );

        if ( keyType == KeyType.EcdsaP384 && hashAlgorithm.Name != "SHA384" )
            throw new ArgumentOutOfRangeException( "KeyVault requires SHA-384 for EcdsaP384 keys" );

        if ( keyType == KeyType.EcdsaP521 && hashAlgorithm.Name != "SHA512" )
            throw new ArgumentOutOfRangeException( "KeyVault requires SHA-512 for EcdsaP521 keys" );
    }


    /// <summary />
    private async Task<KeyVaultKey> CreateEcKeyAsync(
        KeyCreationOptions options,
        KeyCurveName curve,
        CancellationToken cancellationToken )
    {
        var ecOptions = new CreateEcKeyOptions( options.KeyName, hardwareProtected: options.HardwareProtected )
        {
            CurveName = curve,
            Enabled = true,
            ExpiresOn = options.MomentExpiry,
            Exportable = options.Exportable,
        };

        ApplyMetadata( ecOptions.Tags, options.Tags );

        return await _kc.CreateEcKeyAsync( ecOptions, cancellationToken );
    }


    /// <summary />
    private async Task<KeyVaultKey> CreateRsaKeyAsync(
        KeyCreationOptions options,
        int keySize,
        CancellationToken cancellationToken )
    {
        var rsaOptions = new CreateRsaKeyOptions( options.KeyName, hardwareProtected: options.HardwareProtected )
        {
            KeySize = keySize,
            Enabled = true,
            ExpiresOn = options.MomentExpiry,
            Exportable = options.Exportable,
        };

        ApplyMetadata( rsaOptions.Tags, options.Tags );

        return await _kc.CreateRsaKeyAsync( rsaOptions, cancellationToken );
    }


    /// <summary />
    private static SignatureAlgorithm ToSignatureAlgorithm( KeyType keyType, HashAlgorithmName hashAlgorithm )
    {
        var family = keyType.Family();

        if ( family == KeyFamily.Ecdsa )
        {
            return keyType switch
            {
                KeyType.EcdsaP256 => SignatureAlgorithm.ES256,
                KeyType.EcdsaP384 => SignatureAlgorithm.ES384,
                KeyType.EcdsaP521 => SignatureAlgorithm.ES512,
                KeyType.EcdsaSecp256k1 => SignatureAlgorithm.ES256K,
                _ => throw new NotSupportedException( $"Key type '{keyType}' is not supported." ),
            };
        }
        else
        {
            return hashAlgorithm.Name switch
            {
                "SHA256" => SignatureAlgorithm.RS256,
                "SHA384" => SignatureAlgorithm.RS384,
                "SHA512" => SignatureAlgorithm.RS512,
                _ => throw new NotSupportedException( $"Hash algorithm '{hashAlgorithm.Name}' is not supported." ),
            };
        }
    }


    /// <summary />
    private static void ApplyMetadata( IDictionary<string, string> into, IDictionary<string, string> metadata )
    {
        foreach ( var (key, value) in metadata )
        {
            into[ key ] = value;
        }
    }
}