using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

namespace Andalus.Cryptography.Internal;

/// <summary>
/// Collects TBS bytes, computes SHA-256 locally, then calls
/// <see cref="ICryptoProvider.SignHashAsync"/> and returns the DER-encoded signature.
/// </summary>
internal sealed class HsmStreamCalculator : IStreamCalculator<IBlockResult>
{
    private readonly ICryptoProvider _provider;
    private readonly KeyReference _key;
    private readonly CancellationToken _cancellationToken;
    private readonly HashAlgorithmName _hashAlgorithmName;
    private readonly MemoryStream _buffer = new();


    /// <summary />
    public HsmStreamCalculator(
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithmName,
        CancellationToken cancellationToken )
    {
        _provider = provider;
        _key = key;
        _hashAlgorithmName = hashAlgorithmName;
        _cancellationToken = cancellationToken;
    }


    /// <summary>
    /// BouncyCastle writes the TBS (to-be-signed) certificate bytes here.
    /// </summary>
    public Stream Stream => _buffer;


    /// <summary>
    /// Called by BouncyCastle after all TBS bytes have been written.
    /// Hashes locally, signs remotely, returns the signature.
    /// </summary>
    public IBlockResult GetResult()
    {
        var tbsBytes = _buffer.ToArray();
        var hash = HashUtils.HashData( _hashAlgorithmName, tbsBytes );

        var signResult = _provider
            .SignHashAsync( _key, hash, _hashAlgorithmName, _cancellationToken )
            .GetAwaiter()
            .GetResult();

        return new SimpleBlockResult( signResult.Signature );
    }
}