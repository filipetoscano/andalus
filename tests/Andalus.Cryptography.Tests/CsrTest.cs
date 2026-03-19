using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Pkcs;

namespace Andalus.Cryptography.Tests;

/// <summary />
public class CsrSignerTests
{
    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1 )]
    [InlineData( KeyType.EcdsaP256 )]
    [InlineData( KeyType.EcdsaP384 )]
    [InlineData( KeyType.EcdsaP521 )]
    [InlineData( KeyType.Rsa2048 )]
    [InlineData( KeyType.Rsa3072 )]
    [InlineData( KeyType.Rsa4096 )]
    public async Task CreateWithMinimalData( KeyType keyType )
    {
        var (p, kr, csr) = await CreateCsr( keyType, new CsrData()
        {
            CommonName = "Common Name",
        } );

        var subject = csr.GetCertificationRequestInfo().Subject.ToString();

        Assert.Contains( "CN=Common Name", subject );
        Assert.DoesNotContain( "C=", subject );
        Assert.DoesNotContain( "O=", subject );
        Assert.DoesNotContain( "OU=", subject );
        Assert.DoesNotContain( "L=", subject );
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
    public async Task CreateWithFullData( KeyType keyType )
    {
        var data = new CsrData()
        {
            CommonName = "Common Name",
            Country = "PT",
            Locality = "Caldas da Rainha",
            Organization = "Organization",
            OrganizationalUnit = "IT Department",
            OrganizationIdentifier = "123123123",
            BusinessCategory = "Tax Services",
            SerialNumber = Guid.NewGuid().ToString(),
            Additional = new Dictionary<string, string>
            {
                [ "1.3.6.1.4.1.99999.1" ] = "One",
                [ "1.3.6.1.4.1.99999.2" ] = "Two"
            }
        };

        var (p, kr, csr) = await CreateCsr( keyType, data );

        var subject = csr.GetCertificationRequestInfo().Subject.ToString();

        Assert.Contains( "CN=" + data.CommonName, subject );
        Assert.Contains( "C=" + data.Country, subject );
        Assert.Contains( "O=" + data.Organization, subject );
        Assert.Contains( "OU=" + data.OrganizationalUnit, subject );
        Assert.Contains( "L=" + data.Locality, subject );
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
    public async Task SelfSign( KeyType keyType )
    {
        var (p, kr, csr) = await CreateCsr( keyType, new CsrData()
        {
            CommonName = "Common Name",
        } );

        var x = await X509.SelfSignAsync( csr, p, kr, 365 );
    }


    /// <summary />
    private async Task<(ICryptoProvider CryptoProvider,
        KeyReference KeyRef,
        Pkcs10CertificationRequest CSR)> CreateCsr( KeyType keyType, CsrData data )
    {
        var p = new MemoryCryptoProvider();
        var keyRef = await p.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = nameof( CreateWithMinimalData ) + "-" + keyType.ToString(),
            KeyType = keyType,
            MomentExpiry = DateTime.MaxValue,
        } );


        /*
         * 
         */
        var cs = new CsrSigner();
        var csr = await cs.CreateAsync( p, keyRef, data );


        /*
         * 
         */
        var expectedCurveOid = keyType switch
        {
            KeyType.EcdsaSecp256k1 => SecObjectIdentifiers.SecP256k1,
            KeyType.EcdsaP256 => X9ObjectIdentifiers.Prime256v1,
            KeyType.EcdsaP384 => SecObjectIdentifiers.SecP384r1,
            KeyType.EcdsaP521 => SecObjectIdentifiers.SecP521r1,
            _ => null
        };

        var spki = csr.GetCertificationRequestInfo().SubjectPublicKeyInfo;

        if ( expectedCurveOid != null )
        {
            var curveOid = (DerObjectIdentifier) spki.Algorithm.Parameters;
            Assert.Equal( expectedCurveOid, curveOid );
        }
        else
        {
            Assert.Equal( PkcsObjectIdentifiers.RsaEncryption, spki.Algorithm.Algorithm );
        }


        /*
         * 
         */
        Assert.NotNull( csr );
        Assert.True( csr.Verify() );

        return (p, keyRef, csr);
    }
}