using Andalus.Cryptography.Xml.Internals;
using System.Security.Cryptography;

namespace Andalus.Cryptography.Xml.Tests.Internals;

/// <summary />
public class HsmRsaTests
{
    /// <summary />
    [Fact]
    public void ExportParameters()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmRsa( prov, "Key#Rsa2048" );

        Assert.Throws<NotSupportedException>( () => algo.ExportParameters( false ) );
    }


    /// <summary />
    [Fact]
    public void ImportParameters()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmRsa( prov, "Key#Rsa2048" );

        Assert.Throws<NotSupportedException>( () => algo.ImportParameters( default! ) );
    }


    /// <summary />
    [Fact]
    public void VerifyHash()
    {
        var prov = new MemoryCryptoProvider();
        var algo = new HsmRsa( prov, "Key#Rsa2048" );

        var hash = new byte[ 32 ];
        var sign = new byte[ 32 ];

        Assert.Throws<NotSupportedException>( () =>
            algo.VerifyHash( hash, sign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1 ) );
    }
}