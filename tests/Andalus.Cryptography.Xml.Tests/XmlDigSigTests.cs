using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
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
    [InlineData( KeyType.EcdsaSecp256k1, "SHA256" )]
    [InlineData( KeyType.EcdsaP256, "SHA256" )]
    [InlineData( KeyType.EcdsaP384, "SHA384" )]
    [InlineData( KeyType.EcdsaP521, "SHA512" )]
    [InlineData( KeyType.Rsa2048, "SHA256" )]
    [InlineData( KeyType.Rsa3072, "SHA384" )]
    [InlineData( KeyType.Rsa4096, "SHA512" )]
    public void EnvelopedOk( KeyType keyType, string hashAlgorithm )
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
            AddKeyInfo = KeyInfoPart.Certificate,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed );

        Assert.True( isValid );
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
    public void EnvelopingOk( KeyType keyType )
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
            AddKeyInfo = KeyInfoPart.Certificate,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed );

        Assert.True( isValid );
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
    public void DetachedOk( KeyType keyType )
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

        var signature = XmlDigSig.Sign( SignatureType.Detached, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyDetached( doc, signature );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( SignatureType.Enveloped )]
    [InlineData( SignatureType.Enveloping )]
    public void ExcludeOk( SignatureType signatureType )
    {
        /*
         * 
         */
        var aux = new XmlDocument() { PreserveWhitespace = true };
        aux.LoadXml( @"<XPath xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">not(ancestor-or-self::extra)</XPath>" );

        var excludeExtra = new XmlDsigXPathTransform();
        excludeExtra.LoadInnerXml( aux.SelectNodes( " //* " )! );


        /*
         * 
         */
        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root>
    <fill />
</root>" );


        /*
         * 
         */
        var b = _f.Get( KeyType.EcdsaSecp256k1 );

        var signed = XmlDigSig.Sign( signatureType, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
            ReferenceTransforms = new List<Transform>()
            {
                excludeExtra,
            },
        } );

        // Failing here?
        var signedOk = XmlDigSig.VerifyAll( signed );

        if ( signedOk == false )
            throw new InvalidOperationException( $"Unexpected" );


        /*
         * 
         */
        var fillElem = doc.SelectSingleNode( " //fill " )!;
        fillElem.AppendChild( doc.CreateElement( "extra" ) );
        fillElem.AppendChild( doc.CreateElement( "extra" ) );

        var ok2 = XmlDigSig.VerifyAll( signed );
        Assert.True( ok2 );
    }
}