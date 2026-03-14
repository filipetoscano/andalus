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
    /// Creates a new key pair in the HSM.
    /// </summary>
    /// <param name="options">Key creation options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Key reference.</returns>
    Task<KeyReference> CreateKeyPairAsync(
        KeyCreationOptions options,
        CancellationToken cancellationToken = default );


    /// <summary>
    /// Retrieves the ASN public key.
    /// </summary>
    /// <param name="key">Key reference.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns></returns>
    Task<byte[]> GetPublicKeyAsync(
        KeyReference key,
        CancellationToken cancellationToken = default );


    /// <summary>
    /// Imports a keypair into the HSM.
    /// </summary>
    /// <param name="options">Key creation options.</param>
    /// <param name="keyPair">Public/private key pair.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Key reference.</returns>
    Task<KeyReference> ImportKeyPairAsync(
        KeyCreationOptions options,
        KeyPair keyPair,
        CancellationToken cancellationToken = default );


    /// <summary>
    /// Removes a key pair from an HSM.
    /// </summary>
    /// <param name="key">Key reference.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns></returns>
    Task RemoveKeyPairAsync(
        KeyReference key,
        CancellationToken cancellationToken = default );


    /// <summary>
    /// Signs a pre-computed hash remotely. The hash is computed locally;
    /// only the compact digest crosses the wire.
    /// </summary>
    /// <param name="key">Key reference.</param>
    /// <param name="hash">The hash/digest bytes to sign.</param>
    /// <param name="hashAlgorithm"></param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SignResult> SignHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName? hashAlgorithm = null,
        CancellationToken cancellationToken = default );


    /// <summary>
    /// Verifies a signature against a hash. Implementations may verify
    /// locally using the public key or delegate to the HSM.
    /// </summary>
    /// <param name="key">Key reference.</param>
    /// <param name="hash">Digest bytes.</param>
    /// <param name="signature">Signature bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> VerifyHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        ReadOnlyMemory<byte> signature,
        HashAlgorithmName? hashAlgorithm = null,
        CancellationToken cancellationToken = default );
}