using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Xml;

namespace Andalus.Cryptography.Xml.Tests;

/// <summary />
[Collection( nameof( Fixture ) )]
public class DetachedTests
{
    private readonly Fixture _f;
    private readonly ICryptoProvider _cp;


    /// <summary />
    public DetachedTests( Fixture fixture )
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
    [InlineData( KeyType.EcdsaSecp256k1 )]
    [InlineData( KeyType.EcdsaP256 )]
    [InlineData( KeyType.EcdsaP384 )]
    [InlineData( KeyType.EcdsaP521 )]
    [InlineData( KeyType.Rsa2048 )]
    [InlineData( KeyType.Rsa3072 )]
    [InlineData( KeyType.Rsa4096 )]
    public void InvalidWhenChanged( KeyType keyType )
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

        if ( XmlDigSig.VerifyDetached( doc, signature ) == false )
            throw new InvalidOperationException( "Signature must be valid after signing" );


        /*
         * 
         */
        var elem = doc.CreateElement( "breaks" );
        doc.SelectSingleNode( " //another " )!.AppendChild( elem );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyDetached( doc, signature );
        Assert.False( isValid );
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
    public void WithoutCertificate( KeyType keyType )
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
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyDetached( doc, signature, b.Certificate );

        Assert.True( isValid );
    }
}