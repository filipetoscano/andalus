namespace Andalus.Cryptography.BouncyHsm;

/// <summary />
public class BouncyHsmCryptoProviderOptions
{
    /// <summary>
    /// BouncyHsm REST API / PKCS#11 endpoint
    /// </summary>
    /// <remarks>
    /// Default: https://localhost:5000/
    /// </remarks>
    public Uri? Endpoint { get; init; }

    /// <summary>
    /// Slot ID of the token to use.
    /// </summary>
    public required int SlotId { get; init; }

    /// <summary>
    /// User PIN for the token.
    /// </summary>
    public required string UserPin { get; init; }
}