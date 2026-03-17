using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Xml;

namespace Andalus.Cryptography.Xml.Tests;

/// <summary />
public class XmlDigSigTests : IClassFixture<Fixture>
{
    private readonly Fixture _f;
    private readonly ICryptoProvider _cp;


    /// <summary />
    public XmlDigSigTests( Fixture fixture )
    {
        _f = fixture;
        _cp = fixture.Services.GetRequiredService<ICryptoProvider>();
    }


    /// <summary />
    [Theory]
    [InlineData( SignatureType.Enveloped )]
    [InlineData( SignatureType.Enveloping )]
    public void Roundtrip( SignatureType signatureType )
    {
        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root>
    <another />
    <bites>
        <the />
        <dust />
    </bites>
</root>" );

        var signed = XmlDigSig.Sign( signatureType, doc, _cp, _f.EcdsaKey, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
        } );

        XmlDigSig.VerifyAll( signed );
    }
}