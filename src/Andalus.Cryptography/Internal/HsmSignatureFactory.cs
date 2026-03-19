using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

namespace Andalus.Cryptography.Internal;

/// <summary />
internal sealed class HsmSignatureFactory : ISignatureFactory
{
    private readonly ICryptoProvider _provider;
    private readonly KeyReference _key;
    private readonly HashAlgorithmName _hashAlgorithmName;
    private readonly CancellationToken _cancellationToken;


    /// <summary />
    public HsmSignatureFactory(
        ICryptoProvider provider,
        KeyReference key,
        CancellationToken cancellationToken )
    {
        _provider = provider;
        _key = key;
        _hashAlgorithmName = CertificateUtils.MapHashAlgorithm( key.KeyType );
        _cancellationToken = cancellationToken;
    }


    /// <summary>
    /// The algorithm identifier written into the certificate's signatureAlgorithm field.
    /// </summary>
    public object AlgorithmDetails
    {
        get => CertificateUtils.MapSignatureAlgorithm( _key.KeyType, _hashAlgorithmName );
    }


    /// <summary />
    public IStreamCalculator<IBlockResult> CreateCalculator()
        => new HsmStreamCalculator( _provider, _key, _hashAlgorithmName, _cancellationToken );
}