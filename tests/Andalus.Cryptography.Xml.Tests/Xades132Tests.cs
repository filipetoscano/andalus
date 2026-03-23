using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
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
    public void BuildXadesObject_Ok( KeyType keyType )
    {
        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root />" );

        var b = _f.Get( keyType );

        var elem = Xades132.BuildXadesObject( doc, b.Certificate );

        Assert.NotNull( elem );
    }


    /// <summary />
    [Theory]
    [InlineData( XmlCanonicalization.XmlDsigC14NTransform, null )]
    [InlineData( XmlCanonicalization.XmlDsigC14NTransform, XmlCanonicalization.XmlDsigC14NTransform )]
    [InlineData( XmlCanonicalization.XmlDsigExcC14NTransform, null )]
    [InlineData( XmlCanonicalization.XmlDsigExcC14NTransform, XmlCanonicalization.XmlDsigC14NTransform )]
    public void Enveloped_Ok( XmlCanonicalization canon, XmlCanonicalization? xades )
    {
        var b = _f.Get( KeyType.EcdsaP256 );

        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root><child>data</child></root>" );

        var options = new XmlDigSigOptions
        {
            Canonicalization = canon,
            XadesCanonicalization = xades,
            Profile = SignatureProfile.Xades132,
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        };

        var signed = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, options );


        /*
         * 
         */
        Assert.True( XmlDigSig.VerifyAll( signed ) );
        AssertXadesStructure( signed );
    }


    /// <summary />
    [Theory]
    [InlineData( XmlCanonicalization.XmlDsigC14NTransform )]
    [InlineData( XmlCanonicalization.XmlDsigExcC14NTransform )]
    public void Enveloping_Ok( XmlCanonicalization canon )
    {
        var b = _f.Get( KeyType.Rsa2048 );

        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root><child>data</child></root>" );

        var options = new XmlDigSigOptions
        {
            Canonicalization = canon,
            Profile = SignatureProfile.Xades132,
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        };

        var signed = XmlDigSig.Sign( SignatureType.Enveloping, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, options );


        /*
         * 
         */
        Assert.True( XmlDigSig.VerifyAll( signed ) );
        AssertXadesStructure( signed );
    }


    /// <summary />
    [Theory]
    [InlineData( XmlCanonicalization.XmlDsigC14NTransform )]
    [InlineData( XmlCanonicalization.XmlDsigExcC14NTransform )]
    public void Detached_Ok( XmlCanonicalization canon )
    {
        var b = _f.Get( KeyType.Rsa2048 );

        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.LoadXml( @"<root><child>data</child></root>" );

        var options = new XmlDigSigOptions
        {
            Canonicalization = canon,
            Profile = SignatureProfile.Xades132,
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate,
        };

        var detached = XmlDigSig.Sign( SignatureType.Detached, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, options );


        /*
         *
         */
        Assert.True( XmlDigSig.VerifyDetached( doc, detached ) );
        AssertXadesStructure( detached );
    }


    /// <summary />
    private static void AssertXadesStructure( XmlDocument signedDoc )
    {
        var sig = signedDoc.SelectSingleNode( "//ds:Signature", XmlNs.Manager ) as XmlElement;
        Assert.NotNull( sig );

        // ds:Signature must have an Id
        var sigId = sig!.GetAttribute( "Id" );
        Assert.False( string.IsNullOrEmpty( sigId ) );

        // Two references: one for content, one for xades:SignedProperties
        var refs = sig.SelectNodes( "ds:SignedInfo/ds:Reference", XmlNs.Manager )!;
        Assert.Equal( 2, refs.Count );

        var xadesRef = sig.SelectSingleNode(
            "ds:SignedInfo/ds:Reference[@Type='http://uri.etsi.org/01903#SignedProperties']",
            XmlNs.Manager ) as XmlElement;
        Assert.NotNull( xadesRef );

        // QualifyingProperties must be present with correct Target
        var qp = sig.SelectSingleNode( "//x132:QualifyingProperties", XmlNs.Manager ) as XmlElement;
        Assert.NotNull( qp );
        Assert.Equal( "#" + sigId, qp!.GetAttribute( "Target" ) );

        // xades:SignedProperties must contain SigningTime and SigningCertificate
        var sp = qp.SelectSingleNode( "x132:SignedProperties", XmlNs.Manager );
        Assert.NotNull( sp );

        Assert.NotNull( sp!.SelectSingleNode( "x132:SignedSignatureProperties/x132:SigningTime", XmlNs.Manager ) );
        Assert.NotNull( sp.SelectSingleNode( "x132:SignedSignatureProperties/x132:SigningCertificate", XmlNs.Manager ) );
    }
}