using Andalus.Cryptography.Internal;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Andalus.Cryptography;

/// <summary />
public class X509
{
    private static readonly SecureRandom _sr = new SecureRandom();


    /// <summary />
    public static async Task<X509Certificate> SelfSignAsync(
        ICryptoProvider provider,
        KeyReference key,
        Pkcs10CertificationRequest csr,
        int validityDays = 365,
        Action<X509V3CertificateGenerator>? modify = null,
        CancellationToken cancellationToken = default )
    {
        /*
         * 
         */
        if ( csr.Verify() == false )
            throw new InvalidOperationException( "CSR signature verification failed." );


        /*
         * Extract subject and public key from the CSR
         */
        var csrInfo = csr.GetCertificationRequestInfo();
        var subjectDN = csrInfo.Subject;
        var publicKey = csr.GetPublicKey();


        /*
         * Build the certificate
         */
        var certGenerator = new X509V3CertificateGenerator();

        certGenerator.SetSerialNumber( SerialNumber() );
        certGenerator.SetIssuerDN( subjectDN );
        certGenerator.SetSubjectDN( subjectDN );
        certGenerator.SetNotBefore( DateTime.UtcNow );
        certGenerator.SetNotAfter( DateTime.UtcNow.AddDays( validityDays ) );
        certGenerator.SetPublicKey( publicKey );


        /*
         * Optional: carry over any requested extensions from the CSR
         */
        var extensions = csr.GetRequestedExtensions();

        if ( extensions != null )
        {
            foreach ( var oid in extensions.ExtensionOids )
            {
                var ext = extensions.GetExtension( (DerObjectIdentifier) oid );
                certGenerator.AddExtension( (DerObjectIdentifier) oid, ext.IsCritical, ext.GetParsedValue() );
            }
        }


        /*
         * Add basic constraints (CA:true for a self-signed root)
         */
        certGenerator.AddExtension( X509Extensions.BasicConstraints, true, new BasicConstraints( true ) );


        /*
         * Add Subject Key Identifier
         */
        var pubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo( publicKey );
        var ski = X509ExtensionUtilities.CreateSubjectKeyIdentifier( pubKeyInfo );

        certGenerator.AddExtension( X509Extensions.SubjectKeyIdentifier, false, ski );


        /*
         * Run customizations
         */
        if ( modify != null )
            modify( certGenerator );



        /* 
         * Sign
         */
        var signatureFactory = new HsmSignatureFactory( provider, key, cancellationToken );
        var cert = certGenerator.Generate( signatureFactory );


        /*
         * Sanity check
         */
        cert.Verify( publicKey );

        return cert;
    }


    /// <summary />
    public static async Task<X509Certificate> SignAsync(
        ICryptoProvider provider,
        KeyReference key,
        X509Certificate certificate,
        Pkcs10CertificationRequest csr,
        int validityDays = 365,
        Action<X509V3CertificateGenerator>? modify = null,
        CancellationToken cancellationToken = default )
    {
        /*
         * Verify CSR signature
         */
        if ( csr.Verify() == false )
            throw new InvalidOperationException( "CSR signature verification failed." );


        /*
         * Extract subject and public key from the CSR
         */
        var csrInfo = csr.GetCertificationRequestInfo();
        var subjectDN = csrInfo.Subject;
        var publicKey = csr.GetPublicKey();


        /*
         * Build the certificate
         */
        var certGenerator = new X509V3CertificateGenerator();

        certGenerator.SetSerialNumber( SerialNumber() );
        certGenerator.SetIssuerDN( certificate.SubjectDN );
        certGenerator.SetSubjectDN( subjectDN );
        certGenerator.SetNotBefore( DateTime.UtcNow );
        certGenerator.SetNotAfter( DateTime.UtcNow.AddDays( validityDays ) );
        certGenerator.SetPublicKey( publicKey );


        /*
         * Optional: carry over any requested extensions from the CSR
         */
        var extensions = csr.GetRequestedExtensions();

        if ( extensions != null )
        {
            foreach ( var oid in extensions.ExtensionOids )
            {
                var ext = extensions.GetExtension( (DerObjectIdentifier) oid );
                certGenerator.AddExtension( (DerObjectIdentifier) oid, ext.IsCritical, ext.GetParsedValue() );
            }
        }


        /*
         * Basic constraints (CA:false for end-entity)
         */
        certGenerator.AddExtension( X509Extensions.BasicConstraints, true, new BasicConstraints( false ) );


        /*
         * Subject Key Identifier (from the CSR's public key)
         */
        var subjectPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo( publicKey );
        var ski = X509ExtensionUtilities.CreateSubjectKeyIdentifier( subjectPubKeyInfo );

        certGenerator.AddExtension( X509Extensions.SubjectKeyIdentifier, false, ski );


        /*
         * Authority Key Identifier (from the CA certificate's public key)
         */
        var issuerPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo( certificate.GetPublicKey() );
        var aki = X509ExtensionUtilities.CreateAuthorityKeyIdentifier( issuerPubKeyInfo );

        certGenerator.AddExtension( X509Extensions.AuthorityKeyIdentifier, false, aki );


        /*
         * Run customizations
         */
        if ( modify != null )
            modify( certGenerator );


        /*
         * Sign with the CA's private key
         */
        var signatureFactory = new HsmSignatureFactory( provider, key, cancellationToken );
        var cert = certGenerator.Generate( signatureFactory );


        /*
         * Sanity check: verify the issued cert against the CA's public key
         */
        cert.Verify( certificate.GetPublicKey() );

        return cert;
    }


    /// <summary />
    private static BigInteger SerialNumber()
    {
        /*
         * .NET XmlSerializer interprets xs:integer as a long. As such
         * generate serial numbers within the [ 0, long.Max ] range.
         */
        return BigInteger.ValueOf( Math.Abs( _sr.NextLong() ) );
    }
}