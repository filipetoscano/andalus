using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Andalus.Cryptography.Pkcs11;

/// <summary />
internal sealed class SharedPkcs11Library
{
    /// <summary />
    private int _refCount;

    /// <summary />
    public IPkcs11Library Library { get; }


    /// <summary />
    internal SharedPkcs11Library( string path, Pkcs11InteropFactories factories )
    {
        Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            factories,
            path,
            AppType.MultiThreaded );
    }


    /// <summary />
    public void AddRef() => Interlocked.Increment( ref _refCount );


    /// <summary />
    public int Release() => Interlocked.Decrement( ref _refCount );
}