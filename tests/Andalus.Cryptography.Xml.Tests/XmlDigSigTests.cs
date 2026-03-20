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
    [InlineData( SignatureType.Enveloped )]
    [InlineData( SignatureType.Enveloping )]
    [InlineData( SignatureType.Detached )]
    public void SignatureOk( SignatureType signatureType )
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
        var b = _f.Get( KeyType.EcdsaSecp256k1 );

        var signed = XmlDigSig.Sign( signatureType, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        } );


        /*
         * 
         */
        bool isValid;

        if ( signatureType == SignatureType.Detached )
            isValid = XmlDigSig.VerifyDetached( doc, signed );
        else
            isValid = XmlDigSig.VerifyAll( signed );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( SignatureType.Enveloped )]
    [InlineData( SignatureType.Enveloping )]
    [InlineData( SignatureType.Detached )]
    public void WithNamespace( SignatureType signatureType )
    {
        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root xmlns=""urn:andalus"">
    <another />
    <bites>
        <the />
        <dust />
    </bites>
</root>" );


        /*
         * 
         */
        var b = _f.Get( KeyType.EcdsaSecp256k1 );

        var signed = XmlDigSig.Sign( signatureType, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        } );


        /*
         * 
         */
        bool isValid;

        if ( signatureType == SignatureType.Detached )
            isValid = XmlDigSig.VerifyDetached( doc, signed );
        else
            isValid = XmlDigSig.VerifyAll( signed );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( SignatureType.Enveloped )]
    [InlineData( SignatureType.Enveloping )]
    public void Exclusion( SignatureType signatureType )
    {
        /*
         * 
         */
        var aux = new XmlDocument() { PreserveWhitespace = true };
        aux.LoadXml( "<XPath xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>not(ancestor-or-self::extra)</XPath>" );

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
                // excludeExtra,
            },
        } );

        // Failing here?
        var signedOk = XmlDigSig.VerifyAll( signed );
        Assert.True( signedOk );


        /*
         * 
         */
        //var fillElem = doc.SelectSingleNode( " //fill " )!;
        //fillElem.AppendChild( doc.CreateElement( "extra" ) );
        //fillElem.AppendChild( doc.CreateElement( "extra" ) );

        //var ok2 = XmlDigSig.VerifyAll( signed );
        //Assert.True( ok2 );
    }
}