using System.Runtime.InteropServices;

namespace Andalus.Cryptography.BouncyHsm;

/// <summary>
/// PKCS#11 crypto provider pre-configured to use the native library
/// bundled inside the <c>BouncyHsm.Client</c> NuGet package.
/// Intended for development and integration testing only.
/// </summary>
public class BouncyHsmCryptoProvider : Pkcs11.Pkcs11CryptoProvider
{
    /// <summary />
    public BouncyHsmCryptoProvider( BouncyHsmCryptoProviderOptions options )
        : base( new Pkcs11.Pkcs11CryptoProviderOptions
        {
            LibraryPath = ResolvePkcs11LibraryPath(),
            SlotId = options.SlotId,
            UserPin = options.UserPin,
        } )
    {
    }


    /// <summary>
    /// Resolves the path to the native PKCS#11 library bundled in
    /// the BouncyHsm.Client NuGet package, based on the current
    /// runtime platform.
    /// </summary>
    private static string ResolvePkcs11LibraryPath()
    {
        var baseDir = AppContext.BaseDirectory;

        var (rid, fileName) = GetPlatformInfo();

        var path = Path.Combine( baseDir, "runtimes", rid, "native", fileName );

        if ( File.Exists( path ) )
            return path;

        var fallback = Path.Combine( baseDir, fileName );

        if ( File.Exists( fallback ) )
            return fallback;

        throw new PlatformNotSupportedException(
            $"BouncyHsm PKCS#11 library not found. Expected at '{path}'. " +
            $"Ensure the BouncyHsm.Client NuGet package is referenced." );
    }


    private static (string rid, string fileName) GetPlatformInfo()
    {
        if ( RuntimeInformation.IsOSPlatform( OSPlatform.Windows ) )
        {
            return RuntimeInformation.OSArchitecture switch
            {
                Architecture.X64 => ("win-x64", "BouncyHsm.Pkcs11Lib.dll"),
                Architecture.X86 => ("win-x86", "BouncyHsm.Pkcs11Lib.dll"),
                _ => throw new PlatformNotSupportedException(
                    $"Windows {RuntimeInformation.OSArchitecture} is not supported by BouncyHsm." )
            };
        }

        if ( RuntimeInformation.IsOSPlatform( OSPlatform.Linux ) )
        {
            return ("linux-x64", "libBouncyHsm.Pkcs11Lib.so");
        }

        throw new PlatformNotSupportedException(
            $"Platform '{RuntimeInformation.RuntimeIdentifier}' is not supported by BouncyHsm." );
    }
}