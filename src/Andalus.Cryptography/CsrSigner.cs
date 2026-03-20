using Andalus.Cryptography.Internal;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;

namespace Andalus.Cryptography;

/// <summary />
public class CsrSigner
{
    /// <summary />
    public static async Task<Pkcs10CertificationRequest> CreateAsync(
        ICryptoProvider provider, KeyReference key,
        CsrData data,
        CancellationToken cancellationToken = default )
    {
        var subject = BuildSubject( data );
        var hashAlgorithm = CertificateUtils.MapHashAlgorithm( key.KeyType );
        var signatureAlgorithm = CertificateUtils.MapSignatureAlgorithm( key.KeyType, hashAlgorithm );

        // Retrieve the public key from the HSM
        var publicKeyBytes = await provider.GetPublicKeyAsync( key, cancellationToken );
        var publicKeyInfo = SubjectPublicKeyInfo.GetInstance( publicKeyBytes );

        // Build the TBS (to-be-signed) CertificationRequestInfo
        var requestInfo = new CertificationRequestInfo(
            subject,
            publicKeyInfo,
            data.Attributes );

        // Hash the TBS locally
        var tbsBytes = requestInfo.GetDerEncoded();
        var hash = HashUtils.HashData( hashAlgorithm, tbsBytes );

        // Sign via the HSM (abstraction always returns DER signature)
        var signResult = await provider.SignHashAsync( key, hash, hashAlgorithm, cancellationToken );

        // Assemble the final PKCS#10 structure
        var csrSequence = new DerSequence(
            requestInfo,
            signatureAlgorithm,
            new DerBitString( signResult.Signature ) );

        return new Pkcs10CertificationRequest( csrSequence.GetDerEncoded() );
    }


    /// <summary />
    private static X509Name BuildSubject( CsrData data )
    {
        var oids = new List<DerObjectIdentifier>();
        var vals = new List<string>();


        /*
         * Note: RFC 5280 convention is general-to-specific ordering, and which
         * is expected by most Certificate Authorities, such as: C > L > O > OU > CN
         */

        if ( string.IsNullOrEmpty( data.Country ) == false )
        {
            oids.Add( X509Name.C );
            vals.Add( data.Country );
        }

        if ( string.IsNullOrEmpty( data.Locality ) == false )
        {
            oids.Add( X509Name.L );
            vals.Add( data.Locality );
        }

        if ( string.IsNullOrEmpty( data.BusinessCategory ) == false )
        {
            oids.Add( X509Name.BusinessCategory );
            vals.Add( data.BusinessCategory );
        }

        if ( string.IsNullOrEmpty( data.Organization ) == false )
        {
            oids.Add( X509Name.O );
            vals.Add( data.Organization );
        }

        if ( string.IsNullOrEmpty( data.OrganizationIdentifier ) == false )
        {
            oids.Add( X509Name.OrganizationIdentifier );
            vals.Add( data.OrganizationIdentifier );
        }

        if ( string.IsNullOrEmpty( data.OrganizationalUnit ) == false )
        {
            oids.Add( X509Name.OU );
            vals.Add( data.OrganizationalUnit );
        }

        if ( string.IsNullOrEmpty( data.SerialNumber ) == false )
        {
            oids.Add( X509Name.SerialNumber );
            vals.Add( data.SerialNumber );
        }

        oids.Add( X509Name.CN );
        vals.Add( data.CommonName );

        if ( data.Additional != null )
        {
            foreach ( var kv in data.Additional )
            {
                oids.Add( new DerObjectIdentifier( kv.Key ) );
                vals.Add( kv.Value );
            }
        }

        return new X509Name( oids, vals );
    }
}