namespace Andalus.Cryptography.BouncyHsm;

/// <summary />
public class BouncyHsmCryptoProviderOptions
{
    /// <summary>
    /// Slot ID of the token to use.
    /// </summary>
    public required int SlotId { get; init; }

    /// <summary>
    /// User PIN for the token.
    /// </summary>
    public required string UserPin { get; init; }
}