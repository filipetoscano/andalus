using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Pkcs;
using System.Security.Cryptography;

namespace Andalus.Cryptography;

/// <summary />
public class CsrSigner
{
    /// <summary />
    public async Task<Pkcs10CertificationRequest> CreateAsync(
        ICryptoProvider provider, KeyReference key,
        CsrData data,
        CancellationToken cancellationToken = default )
    {
        var subject = BuildSubject( data );
        var signatureAlgorithm = MapSignatureAlgorithm( key.KeyType );
        var hashAlgorithm = MapHashAlgorithm( key.KeyType );

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
        var hash = HashData( tbsBytes, hashAlgorithm );

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


    /// <summary />
    private static AlgorithmIdentifier MapSignatureAlgorithm( KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 or KeyType.EcdsaSecp256k1 => new AlgorithmIdentifier( X9ObjectIdentifiers.ECDsaWithSha256 ),
            KeyType.EcdsaP384 => new AlgorithmIdentifier( X9ObjectIdentifiers.ECDsaWithSha384 ),
            KeyType.EcdsaP521 => new AlgorithmIdentifier( X9ObjectIdentifiers.ECDsaWithSha512 ),
            KeyType.Rsa2048 => new AlgorithmIdentifier( PkcsObjectIdentifiers.Sha256WithRsaEncryption, DerNull.Instance ),
            KeyType.Rsa3072 => new AlgorithmIdentifier( PkcsObjectIdentifiers.Sha384WithRsaEncryption, DerNull.Instance ),
            KeyType.Rsa4096 => new AlgorithmIdentifier( PkcsObjectIdentifiers.Sha512WithRsaEncryption, DerNull.Instance ),

            _ => throw new NotSupportedException( $"Key type '{keyType}' is not supported." )
        };
    }


    /// <summary />
    private static HashAlgorithmName MapHashAlgorithm( KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 or KeyType.EcdsaSecp256k1 => HashAlgorithmName.SHA256,
            KeyType.EcdsaP384 => HashAlgorithmName.SHA384,
            KeyType.EcdsaP521 => HashAlgorithmName.SHA512,

            KeyType.Rsa2048 => HashAlgorithmName.SHA256,
            KeyType.Rsa3072 => HashAlgorithmName.SHA384,
            KeyType.Rsa4096 => HashAlgorithmName.SHA512,

            _ => throw new NotSupportedException( $"Key type '{keyType}' is not supported." )
        };
    }


    /// <summary />
    private static byte[] HashData( byte[] data, HashAlgorithmName algorithm )
    {
        return algorithm.Name switch
        {
            "SHA256" => SHA256.HashData( data ),
            "SHA384" => SHA384.HashData( data ),
            "SHA512" => SHA512.HashData( data ),
            _ => throw new NotSupportedException( $"Hash '{algorithm.Name}' not supported." )
        };
    }
}