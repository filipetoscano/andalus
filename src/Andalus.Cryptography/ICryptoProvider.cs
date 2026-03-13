using System.Security.Cryptography;

namespace Andalus.Cryptography;

/// <summary>
/// Core abstraction over any remote HSM that holds non-exportable keys.
/// Implementations: Azure Key Vault, AWS CloudHSM, Thales Luna,
/// PKCS#11, Google Cloud KMS, etc.
/// </summary>
public interface ICryptoProvider
{
    /// <summary>
    /// Creates a new key pair in the HSM and returns a reference
    /// containing the key identifier and public portion.
    /// </summary>
    Task<KeyReference> CreateKeyPairAsync(
        KeyCreationOptions options,
        CancellationToken cancellationToken = default );


    /// <summary>
    /// Signs a pre-computed hash remotely. The hash is computed locally;
    /// only the compact digest crosses the wire.
    /// </summary>
    /// <param name="keyId">The HSM key identifier (from <see cref="KeyReference.KeyId"/>).</param>
    /// <param name="hash">The digest bytes to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SignResult> SignHashAsync(
        string keyId,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default );


    /// <summary>
    /// Verifies a signature against a hash. Implementations may verify
    /// locally using the public key or delegate to the HSM.
    /// </summary>
    /// <param name="keyId">Key identifier.</param>
    /// <param name="hash">Digest bytes.</param>
    /// <param name="signature">Signature bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> VerifyHashAsync(
        string keyId,
        ReadOnlyMemory<byte> hash,
        ReadOnlyMemory<byte> signature,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default );
}