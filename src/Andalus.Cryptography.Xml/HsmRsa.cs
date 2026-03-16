using System.Security.Cryptography;

namespace Andalus.Cryptography.Xml;

/// <summary>
/// RSA proxy that delegates signing to the crypto provider.
/// </summary>
/// <remarks>
/// SignedXml expects RSA signatures in PKCS#1 v1.5 format.
/// </remarks>
public sealed class HsmRsa : RSA
{
    private readonly ICryptoProvider _provider;
    private readonly KeyReference _key;


    /// <summary>
    /// Initializes a new instance of the <see cref="HsmRsa" /> class.
    /// </summary>
    /// <param name="provider">Crypto provider.</param>
    /// <param name="key">Key reference.</param>
    public HsmRsa( ICryptoProvider provider, KeyReference key )
    {
        _provider = provider;
        _key = key;

        LegalKeySizesValue = [ new KeySizes( 2048, 4096, 0 ) ];
        KeySize = key.KeyType switch
        {
            KeyType.Rsa2048 => 2048,
            KeyType.Rsa3072 => 3072,
            KeyType.Rsa4096 => 4096,
            _ => throw new ArgumentException( $"Unsupported key type: {key.KeyType}", nameof( key ) )
        };
    }


    /// <inheritdoc />
    public override byte[] SignHash(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding )
    {
        if ( padding != RSASignaturePadding.Pkcs1 )
            throw new NotSupportedException( $"Unsupported padding: {padding}" );

        var result = _provider
            .SignHashAsync( _key, hash, hashAlgorithm )
            .GetAwaiter().GetResult();

        return result.Signature;
    }


    /// <inheritdoc />
    protected override byte[] HashData( Stream data, HashAlgorithmName hashAlgorithm )
    {
        return hashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData( data ),
            "SHA384" => SHA384.HashData( data ),
            "SHA512" => SHA512.HashData( data ),
            _ => throw new NotSupportedException()
        };
    }


    /// <inheritdoc />
    public override RSAParameters ExportParameters( bool includePrivateParameters )
        => throw new NotSupportedException( "HSM keys are not exportable." );


    /// <inheritdoc />
    public override void ImportParameters( RSAParameters parameters )
        => throw new NotSupportedException();


    /// <inheritdoc />
    public override bool VerifyHash(
        byte[] hash, byte[] signature,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding )
        => throw new NotSupportedException( "Use VerifyHashAsync on the provider." );
}