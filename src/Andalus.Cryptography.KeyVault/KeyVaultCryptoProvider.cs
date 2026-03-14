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

        var kv = await _kc.GetKeyAsync( kid.Name, kid.Version );

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
    public Task<KeyReference> ImportKeyPairAsync( KeyCreationOptions options, KeyPair keyPair, CancellationToken cancellationToken = default )
    {
        throw new NotImplementedException();
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


        /*
         * 
         */
        var kid = new KeyVaultKeyIdentifier( new Uri( key.KeyId ) );
        var client = _kc.GetCryptographyClient( kid.Name, kid.Version );
        var result = await client.SignAsync( SignatureAlgorithm.ES256K, bytes, cancellationToken );


        /*
         * 
         */
        byte[] signature;

        if ( family == KeyFamily.Ecdsa )
            signature = SignatureFormat.ConvertIeeeP1363ToDer( result.Signature );
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

        if ( family == KeyFamily.Ecdsa )
            signBytes = SignatureFormat.ConvertDerToIeeeP1363( signBytes );


        /*
         * 
         */
        var kid = new KeyVaultKeyIdentifier( new Uri( key.KeyId ) );
        var client = _kc.GetCryptographyClient( kid.Name, kid.Version );
        var result = await client.VerifyAsync( SignatureAlgorithm.ES256K, hashBytes, signBytes, cancellationToken );

        return result.IsValid;
    }


    /// <summary />
    private async Task<KeyVaultKey> CreateEcKeyAsync(
        KeyCreationOptions options,
        KeyCurveName curve,
        CancellationToken cancellationToken )
    {
        var ecOptions = new CreateEcKeyOptions( options.KeyName, hardwareProtected: true )
        {
            CurveName = curve,
            Enabled = true,
            ExpiresOn = options.MomentExpiry,
            Exportable = options.Exportable,
        };

        ApplyMetadata( ecOptions, options.Metadata );

        return await _kc.CreateEcKeyAsync( ecOptions, cancellationToken );
    }


    /// <summary />
    private async Task<KeyVaultKey> CreateRsaKeyAsync(
        KeyCreationOptions options,
        int keySize,
        CancellationToken cancellationToken )
    {
        var rsaOptions = new CreateRsaKeyOptions( options.KeyName, hardwareProtected: true )
        {
            KeySize = keySize,
            Enabled = true,
            ExpiresOn = options.MomentExpiry,
            Exportable = options.Exportable,
        };

        ApplyMetadata( rsaOptions, options.Metadata );

        return await _kc.CreateRsaKeyAsync( rsaOptions, cancellationToken );
    }


    /// <summary />
    private static void ApplyMetadata( CreateKeyOptions keyOptions, IDictionary<string, string> metadata )
    {
        foreach ( var (key, value) in metadata )
        {
            keyOptions.Tags[ key ] = value;
        }
    }
}