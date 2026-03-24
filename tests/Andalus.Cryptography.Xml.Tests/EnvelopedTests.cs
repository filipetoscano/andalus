using Andalus.Cryptography.Xml.Placements;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Xml;

namespace Andalus.Cryptography.Xml.Tests;

/// <summary />
[Collection( nameof( Fixture ) )]
public class EnvelopedTests
{
    private readonly Fixture _f;
    private readonly ICryptoProvider _cp;


    /// <summary />
    public EnvelopedTests( Fixture fixture )
    {
        _f = fixture;
        _cp = fixture.Services.GetRequiredService<ICryptoProvider>();
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1, "SHA256" )]
    [InlineData( KeyType.EcdsaP256, "SHA256" )]
    [InlineData( KeyType.EcdsaP384, "SHA384" )]
    [InlineData( KeyType.EcdsaP521, "SHA512" )]
    [InlineData( KeyType.Rsa2048, "SHA256" )]
    [InlineData( KeyType.Rsa3072, "SHA384" )]
    [InlineData( KeyType.Rsa4096, "SHA512" )]
    public void Ok( KeyType keyType, string hashAlgorithm )
    {
        var han = new HashAlgorithmName( hashAlgorithm );

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

        var signed = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b.KeyReference, han, new XmlDigSigOptions()
        {
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1, "SHA256" )]
    [InlineData( KeyType.EcdsaP256, "SHA256" )]
    [InlineData( KeyType.EcdsaP384, "SHA384" )]
    [InlineData( KeyType.EcdsaP521, "SHA512" )]
    [InlineData( KeyType.Rsa2048, "SHA256" )]
    [InlineData( KeyType.Rsa3072, "SHA384" )]
    [InlineData( KeyType.Rsa4096, "SHA512" )]
    public void WithoutCertificate( KeyType keyType, string hashAlgorithm )
    {
        var han = new HashAlgorithmName( hashAlgorithm );

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

        var signed = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b.KeyReference, han, new XmlDigSigOptions()
        {
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed, b.Certificate );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1, KeyType.EcdsaP256 )]
    [InlineData( KeyType.Rsa2048, KeyType.EcdsaP256 )]
    public void DoubleSignature( KeyType key1, KeyType key2 )
    {
        var exclude = new XPathExclusion()
        {
            XPath = "not(ancestor-or-self::ds:Signature)",
            Namespaces = new()
            {
                { "ds", "http://www.w3.org/2000/09/xmldsig#" }
            },
        };


        /*
         * 
         */
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

        var first = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b1.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            EnvelopedSignaturePlacement = new LastChildPlacement(),
            Certificate = b1.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
            ReferenceTransforms = [ exclude.ToTransform() ],
        } );

        var second = XmlDigSig.Sign( SignatureType.Enveloped, first, _cp, b2.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            EnvelopedSignaturePlacement = new LastChildPlacement(),
            Certificate = b2.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
            ReferenceTransforms = [ exclude.ToTransform() ],
        } );


        /*
         * 
         */
        var result = XmlDigSig.Verify( second );

        Assert.True( result.IsValid );
    }
}