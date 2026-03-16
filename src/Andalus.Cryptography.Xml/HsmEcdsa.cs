using System.Security.Cryptography;

namespace Andalus.Cryptography.Xml;

/// <summary>
/// ECDsa proxy that delegates signing to the crypto provider.
/// </summary>
/// <remarks>
/// SignedXml expects ECDSA signatures in IEEE P1363 format.
/// </remarks>
public sealed class HsmEcdsa : ECDsa
{
    private readonly ICryptoProvider _provider;
    private readonly KeyReference _key;
    private readonly HashAlgorithmName _hashAlgorithm;


    /// <summary>
    /// Initializes a new instance of the <see cref="HsmEcdsa" /> class.
    /// </summary>
    /// <param name="provider">Crypto provider.</param>
    /// <param name="key">Key reference.</param>
    /// <param name="hashAlgorithm">Hash algorithm.</param>
    public HsmEcdsa( ICryptoProvider provider, KeyReference key, HashAlgorithmName? hashAlgorithm = null )
    {
        _provider = provider;
        _key = key;

        _hashAlgorithm = hashAlgorithm ?? key.KeyType switch
        {
            KeyType.EcdsaP384 => HashAlgorithmName.SHA384,
            KeyType.EcdsaP521 => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };

        LegalKeySizesValue = [ new KeySizes( 256, 521, 0 ) ];
        KeySize = key.KeyType switch
        {
            KeyType.EcdsaP256 => 256,
            KeyType.EcdsaP384 => 384,
            KeyType.EcdsaP521 => 521,
            KeyType.EcdsaSecp256k1 => 256,
            _ => throw new ArgumentException( $"Unsupported key type: {key.KeyType}", nameof( key ) )
        };
    }


    /// <inheritdoc />
    public override byte[] SignHash( byte[] hash )
    {
        var result = _provider
            .SignHashAsync( _key, hash, _hashAlgorithm )
            .GetAwaiter().GetResult();

        // Provider returns DER; SignedXml expects IEEE P1363 for ECDSA
        return SignatureFormat.ConvertDerToIeeeP1363( result.Signature, _key.KeyType.CurveOrder() );
    }


    /// <inheritdoc />
    protected override byte[] HashData( Stream data, HashAlgorithmName hashAlgorithm )
    {
        if ( _hashAlgorithm != hashAlgorithm )
            throw new InvalidOperationException( $"Hash algorithm mismatch: expected '{_hashAlgorithm.Name}', called with '{hashAlgorithm.Name}'" );

        return hashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData( data ),
            "SHA384" => SHA384.HashData( data ),
            "SHA512" => SHA512.HashData( data ),
            _ => throw new NotSupportedException()
        };
    }


    /// <inheritdoc />
    public override ECParameters ExportParameters( bool includePrivateParameters )
        => throw new NotSupportedException( "HSM keys are not exportable." );


    /// <inheritdoc />
    public override ECParameters ExportExplicitParameters( bool includePrivateParameters )
        => throw new NotSupportedException( "HSM keys are not exportable." );


    /// <inheritdoc />
    public override void ImportParameters( ECParameters parameters )
        => throw new NotSupportedException();


    /// <inheritdoc />
    public override void GenerateKey( ECCurve curve )
        => throw new NotSupportedException();


    /// <inheritdoc />
    public override bool VerifyHash( byte[] hash, byte[] signature )
        => throw new NotSupportedException( "Use VerifyHashAsync on the provider." );
}