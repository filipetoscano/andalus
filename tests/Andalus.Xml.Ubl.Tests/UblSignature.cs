using Andalus.Cryptography;
using Andalus.Cryptography.Xml;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;

namespace Andalus.Xml.Ubl.Tests;

/// <summary />
[Collection( nameof( Fixture ) )]
public class UblSignature
{
    private readonly Fixture _f;
    private readonly ICryptoProvider _cp;


    /// <summary />
    public UblSignature( Fixture fixture )
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
    public void SignIssuer( KeyType keyType )
    {
        var doc = _f.Load( "MicroDocument.xml" );


        /*
         * 
         */
        var issuer = new UblExtensionPlacement( "Issuer", "9123456" );


        /*
         * 
         */
        var b = _f.Get( keyType );

        var signed = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            EnvelopedSignaturePlacement = issuer,
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
    [InlineData( KeyType.EcdsaSecp256k1, KeyType.EcdsaP256 )]
    [InlineData( KeyType.Rsa2048, KeyType.Rsa4096 )]
    public void DoubleSignature( KeyType issuer, KeyType buyer )
    {
        var doc = _f.Load( "MicroDocument.xml" );


        /*
         * 
         */
        var placement1 = new UblExtensionPlacement( "Issuer", "9123456" );
        var placement2 = new UblExtensionPlacement( "Buyer", "9999999" );

        var b1 = _f.Get( issuer );
        var b2 = _f.Get( buyer );


        /*
         * 
         */
        var signedByIssuer = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b1.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            EnvelopedSignaturePlacement = placement1,
            Certificate = b1.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );

        if ( XmlDigSig.VerifyAll( signedByIssuer ) == false )
            throw new InvalidOperationException( "Signature must be valid after signing" );


        /*
         * 
         */
        var signedByBuyer = XmlDigSig.Sign( SignatureType.Enveloped, signedByIssuer, _cp, b2.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            EnvelopedSignaturePlacement = placement2,
            Certificate = b2.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signedByBuyer );

        Assert.True( isValid );
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1, KeyType.EcdsaP256, KeyType.EcdsaP384 )]
    [InlineData( KeyType.Rsa2048, KeyType.Rsa3072, KeyType.Rsa4096 )]
    public void TripleSignature( KeyType issuer, KeyType buyer, KeyType other )
    {
        var doc = _f.Load( "MicroDocument.xml" );


        /*
         * 
         */
        var placement1 = new UblExtensionPlacement( "Issuer", "9123456" );
        var placement2 = new UblExtensionPlacement( "Buyer", "9999999" );
        var placement3 = new UblExtensionPlacement( "Other", "5555555" );

        var b1 = _f.Get( issuer );
        var b2 = _f.Get( buyer );
        var b3 = _f.Get( other );


        /*
         * 
         */
        var signed1 = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b1.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            EnvelopedSignaturePlacement = placement1,
            Certificate = b1.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );

        if ( XmlDigSig.VerifyAll( signed1 ) == false )
            throw new InvalidOperationException( "Signature must be valid after signing #1" );


        /*
         * 
         */
        var signed2 = XmlDigSig.Sign( SignatureType.Enveloped, signed1, _cp, b2.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            EnvelopedSignaturePlacement = placement2,
            Certificate = b2.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );

        if ( XmlDigSig.VerifyAll( signed2 ) == false )
            throw new InvalidOperationException( "Signature must be valid after signing #2" );


        /*
         * 
         */
        var signed3 = XmlDigSig.Sign( SignatureType.Enveloped, signed2, _cp, b3.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            EnvelopedSignaturePlacement = placement3,
            Certificate = b3.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed3 );

        Assert.True( isValid );
    }
}