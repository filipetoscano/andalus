namespace Andalus.Cryptography.Pkcs11;

/// <summary />
public sealed class Pkcs11CryptoProviderOptions
{
    /// <summary>
    /// Path to the vendor's native PKCS#11 shared library.
    /// Examples:
    ///   Linux (Luna):     /usr/safenet/lunaclient/lib/libCryptoki2_64.so
    ///   Linux (SoftHSMv2): /usr/lib/softhsm/libsofthsm2.so
    ///   Linux (BouncyHsm): runtimes/linux-x64/native/libBouncyHsm.Pkcs11Lib.so
    ///   Windows (Luna):   C:\Program Files\SafeNet\LunaClient\cryptoki.dll
    /// </summary>
    public required string LibraryPath { get; init; }

    /// <summary>
    /// Slot ID of the token to use.
    /// </summary>
    public required int SlotId { get; init; }

    /// <summary>
    /// User PIN for the token.
    /// </summary>
    public required string UserPin { get; init; }
}