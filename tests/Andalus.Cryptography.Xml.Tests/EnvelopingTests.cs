using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Xml;

namespace Andalus.Cryptography.Xml.Tests;

/// <summary />
[Collection( nameof( Fixture ) )]
public class EnvelopingTests
{
    private readonly Fixture _f;
    private readonly ICryptoProvider _cp;


    /// <summary />
    public EnvelopingTests( Fixture fixture )
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
        doc.LoadXml( @"<root>
    <another />
    <bites>
        <the />
        <dust />
    </bites>
</root>" );


        /*
         * 
         */
        var b = _f.Get( keyType );

        var signed = XmlDigSig.Sign( SignatureType.Enveloping, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.Issuer,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1, KeyType.EcdsaP256 )]
    public void DoubleSignature( KeyType key1, KeyType key2 )
    {
        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root>
    <another />
    <bites>
        <the />
        <dust />
    </bites>
</root>" );


        /*
         * 
         */
        var b1 = _f.Get( key1 );
        var b2 = _f.Get( key2 );

        var first = XmlDigSig.Sign( SignatureType.Enveloping, doc, _cp, b1.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Certificate = b1.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        } );

        var second = XmlDigSig.Sign( SignatureType.Enveloping, first, _cp, b2.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Certificate = b2.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( second );

        Assert.True( isValid );
    }
}