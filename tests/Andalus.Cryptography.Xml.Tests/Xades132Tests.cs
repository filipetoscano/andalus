using Microsoft.Extensions.DependencyInjection;
using System.Xml;

namespace Andalus.Cryptography.Xml.Tests;

/// <summary />
[Collection( nameof( Fixture ) )]
public class Xades132Tests
{
    private readonly Fixture _f;
    private readonly ICryptoProvider _cp;


    /// <summary />
    public Xades132Tests( Fixture fixture )
    {
        _f = fixture;
        _cp = fixture.Services.GetRequiredService<ICryptoProvider>();
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1 )]
    [InlineData( KeyType.EcdsaP256 )]
    [InlineData( KeyType.EcdsaP384 )]
    [InlineData( KeyType.EcdsaP521 )]
    [InlineData( KeyType.Rsa2048 )]
    [InlineData( KeyType.Rsa3072 )]
    [InlineData( KeyType.Rsa4096 )]
    public void Ok( KeyType keyType )
    {
        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root />" );

        var b = _f.Get( keyType );

        var elem = Xades132.BuildXadesObject( doc, b.Certificate );

        Assert.NotNull( elem );
    }
}