using Andalus.Cryptography.Xml.Internals;
using System.Security.Cryptography;

namespace Andalus.Cryptography.Xml.Tests.Internals;

/// <summary />
public class HsmEcdsaTests
{
    /// <summary />
    [Fact]
    public void ExportParameters()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmEcdsa( prov, "Key#EcdsaP256" );

        Assert.Throws<NotSupportedException>( () => algo.ExportParameters( false ) );
    }


    /// <summary />
    [Fact]
    public void ExportExplicitParameters()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmEcdsa( prov, "Key#EcdsaP256" );

        Assert.Throws<NotSupportedException>( () => algo.ExportExplicitParameters( false ) );
    }


    /// <summary />
    [Fact]
    public void ImportParameters()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmEcdsa( prov, "Key#EcdsaP256" );

        Assert.Throws<NotSupportedException>( () => algo.ImportParameters( default! ) );
    }


    /// <summary />
    [Fact]
    public void GenerateKey()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmEcdsa( prov, "Key#EcdsaP256" );

        Assert.Throws<NotSupportedException>( () => algo.GenerateKey( ECCurve.NamedCurves.nistP256 ) );
    }


    /// <summary />
    [Fact]
    public void VerifyHash()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmEcdsa( prov, "Key#EcdsaP256" );

        var hash = new byte[ 32 ];
        var sign = new byte[ 32 ];

        Assert.Throws<NotSupportedException>( () => algo.VerifyHash( hash, sign ) );
    }
}