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
        var placement = new UblExtensionPlacement( "Issuer", "9123456" );



        /*
         * 
         */
        var b = _f.Get( keyType );

        var signed = XmlDigSig.Sign( SignatureType.Enveloped, doc, _cp, b.KeyReference, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            EnvelopedSignaturePlacement = placement,
            Certificate = b.Certificate,
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.SubjectName,
        } );


        /*
         * 
         */
        bool isValid = XmlDigSig.VerifyAll( signed );

        Assert.True( isValid );
    }
}