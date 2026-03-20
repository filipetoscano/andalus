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
    public void EnvelopedOk_WithoutCertificate( KeyType keyType, string hashAlgorithm )
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
    public void EnvelopedOk_DoubleSignature( KeyType key1, KeyType key2 )
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
        bool isValid = XmlDigSig.VerifyAll( second );

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
    public void EnvelopingOk_DoubleSignature( KeyType key1, KeyType key2 )
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
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyDetached( doc, signature );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( XmlCanonicalization.XmlDsigC14NTransform )]
    [InlineData( XmlCanonicalization.XmlDsigC14NWithCommentsTransform )]
    [InlineData( XmlCanonicalization.XmlDsigC14N11Transform )]
    [InlineData( XmlCanonicalization.XmlDsigC14N11WithCommentsTransform )]
    [InlineData( XmlCanonicalization.XmlDsigExcC14NTransform )]
    [InlineData( XmlCanonicalization.XmlDsigExcC14NWithCommentsTransform )]
    public void Canonicalization( XmlCanonicalization canonicalization )
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
        var b = _f.Get( KeyType.EcdsaP256 );

        var signed = XmlDigSig.Sign( SignatureType.Enveloping, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Canonicalization = canonicalization,
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        } );


        /*
         * 
         */
        var mgr = new XmlNamespaceManager( new NameTable() );
        mgr.AddNamespace( "ds", "http://www.w3.org/2000/09/xmldsig#" );


        /*
         * 
         */
        var expected = canonicalization.ToAlgorithmUrl();


        /*
         * ds:CanonicalizationMethod
         */
        var canonAttr = (XmlAttribute) signed.SelectSingleNode( " //ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm ", mgr )!;
        Assert.Equal( expected, canonAttr.Value );


        /*
         * Last transform
         */
        var transformAttr = (XmlAttribute) signed.SelectSingleNode( " //ds:Signature//ds:Transforms/ds:Transform[ last() ]/@Algorithm ", mgr )!;
        Assert.Equal( expected, transformAttr.Value );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed );

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
        var exclude = new XPathExclusion()
        {
            XPath = "not(ancestor-or-self::extra)",
        };


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
                exclude.ToTransform(),
            },
        } );

        // Failing here?
        var signedOk = XmlDigSig.VerifyAll( signed );

        if ( signedOk == false )
            throw new InvalidOperationException( $"Expected fresh signature to be valid" );


        /*
         * Adding 'extra' under fill should not cause the signature to break,
         * due to the exclusion added above.
         */
        var fillElem = doc.SelectSingleNode( " //fill " )!;
        fillElem.AppendChild( doc.CreateElement( "extra" ) );
        fillElem.AppendChild( doc.CreateElement( "extra" ) );

        var ok2 = XmlDigSig.VerifyAll( signed );
        Assert.True( ok2 );
    }


    /// <summary />
    [Theory]
    [InlineData( SignatureType.Enveloped )]
    [InlineData( SignatureType.Enveloping )]
    public void ExcludeWithNamespaceOk( SignatureType signatureType )
    {
        /*
         * 
         */
        var exclude = new XPathExclusion()
        {
            XPath = "not(ancestor-or-self::xt:extra)",
            Namespaces = new()
            {
                { "xt", "urn:extra" }
            },
        };


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
                exclude.ToTransform(),
            },
        } );

        // Failing here?
        var signedOk = XmlDigSig.VerifyAll( signed );

        if ( signedOk == false )
            throw new InvalidOperationException( $"Expected fresh signature to be valid" );


        /*
         * Adding 'extra' under fill should not cause the signature to break,
         * due to the exclusion added above.
         */
        var fillElem = doc.SelectSingleNode( " //fill " )!;
        fillElem.AppendChild( doc.CreateElement( "extra", "urn:extra" ) );
        fillElem.AppendChild( doc.CreateElement( "extra", "urn:extra" ) );

        var ok2 = XmlDigSig.VerifyAll( signed );
        Assert.True( ok2 );
    }
}