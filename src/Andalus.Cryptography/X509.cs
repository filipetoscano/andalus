using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Andalus.Cryptography;

/// <summary />
public class X509
{
    /// <summary />
    public static X509Certificate SelfSign( Pkcs10CertificationRequest csr, AsymmetricKeyParameter privateKey, int validityDays = 365 )
    {
        // 1. Verify the CSR signature first
        if ( !csr.Verify() )
            throw new InvalidOperationException( "CSR signature verification failed." );

        // 2. Extract subject and public key from the CSR
        var csrInfo = csr.GetCertificationRequestInfo();
        var subjectDN = csrInfo.Subject;
        var publicKey = csr.GetPublicKey();

        // 3. Build the certificate
        var certGenerator = new X509V3CertificateGenerator();

        certGenerator.SetSerialNumber( BigInteger.ProbablePrime( 120, new Random() ) );
        certGenerator.SetIssuerDN( subjectDN );
        certGenerator.SetSubjectDN( subjectDN );
        certGenerator.SetNotBefore( DateTime.UtcNow );
        certGenerator.SetNotAfter( DateTime.UtcNow.AddDays( validityDays ) );
        certGenerator.SetPublicKey( publicKey );

        // 4. Optional: carry over any requested extensions from the CSR
        var extensions = csr.GetRequestedExtensions();  // may be null
        if ( extensions != null )
        {
            foreach ( var oid in extensions.ExtensionOids )
            {
                var ext = extensions.GetExtension( (DerObjectIdentifier) oid );
                certGenerator.AddExtension(
                    (DerObjectIdentifier) oid, ext.IsCritical, ext.GetParsedValue() );
            }
        }

        // 5. Add basic constraints (CA:true for a self-signed root)
        certGenerator.AddExtension(
            X509Extensions.BasicConstraints, true, new BasicConstraints( true ) );

        // 6. Add Subject Key Identifier
        var pubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo( publicKey );
        var ski = X509ExtensionUtilities.CreateSubjectKeyIdentifier( pubKeyInfo );

        certGenerator.AddExtension(
            X509Extensions.SubjectKeyIdentifier, false, ski );

        // 7. Sign — pick the signature algorithm to match your key type
        //    For ECDSA/secp256k1: "SHA256withECDSA"
        //    For RSA:             "SHA256withRSA"
        var signatureFactory = new Asn1SignatureFactory( "SHA256withECDSA", privateKey );
        var cert = certGenerator.Generate( signatureFactory );

        // 8. Sanity check
        cert.Verify( publicKey );

        return cert;
    }
}
