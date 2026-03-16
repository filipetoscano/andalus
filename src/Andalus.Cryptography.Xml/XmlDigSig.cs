using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class XmlDigSig
{
    /// <summary />
    static XmlDigSig()
    {
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha256SignatureDescription ), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" );
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha384SignatureDescription ), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" );
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha512SignatureDescription ), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" );
    }


    /// <summary>
    /// Generates a signature
    /// </summary>
    public static XmlElement GenerateSignature(
        XmlDocument doc,
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithm,
        XmlDigSigOptions? options )
    {
        if ( doc.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        // Create a proxy AsymmetricAlgorithm that delegates to the provider
        using var proxy = CreateSigningProxy( provider, key, hashAlgorithm );

        SignedXml signedXml = new SignedXml( doc );
        signedXml.SigningKey = proxy;
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = ToSignatureMethod( key.KeyType.Family(), hashAlgorithm );

        // Reference to the document
        Reference docRef = new Reference( "" );
        docRef.AddTransform( new XmlDsigEnvelopedSignatureTransform() );
        docRef.AddTransform( new XmlDsigExcC14NTransform() );
        docRef.DigestMethod = ToDigestMethod( hashAlgorithm );
        signedXml.AddReference( docRef );

        // Key Info
        if ( options != null && options.AddKeyInfo != KeyInfoPart.None )
        {
            if ( options.Certificate is null )
                throw new InvalidOperationException( "Certificate is required when adding key info." );

            var x509Data = new KeyInfoX509Data();

            if ( options.AddKeyInfo.HasFlag( KeyInfoPart.Certificate ) == true )
                x509Data.AddCertificate( options.Certificate );

            if ( options.AddKeyInfo.HasFlag( KeyInfoPart.IssuerSerial ) == true )
                x509Data.AddIssuerSerial( options.Certificate.Issuer, options.Certificate.SerialNumber );

            if ( options.AddKeyInfo.HasFlag( KeyInfoPart.SubjectName ) == true )
                x509Data.AddSubjectName( options.Certificate.Subject );

            var keyInfo = new KeyInfo();
            keyInfo.AddClause( x509Data );

            signedXml.KeyInfo = keyInfo;
        }

        signedXml.ComputeSignature();


        /*
         * 
         */
        XmlElement xmlSig = signedXml.GetXml();
        return (XmlElement) doc.ImportNode( xmlSig, true );
    }



    /// <summary>
    /// Creates a proxy <see cref="AsymmetricAlgorithm"/> that delegates
    /// <c>SignHash</c> to the <see cref="ICryptoProvider"/>. This lets
    /// <see cref="SignedXml.ComputeSignature"/> use the HSM transparently.
    /// </summary>
    private static AsymmetricAlgorithm CreateSigningProxy(
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithm )
    {
        return key.KeyType.Family() switch
        {
            KeyFamily.Ecdsa => new HsmEcdsa( provider, key, hashAlgorithm ),
            KeyFamily.Rsa => new HsmRsa( provider, key ),

            _ => throw new NotSupportedException( $"Key type '{key.KeyType}' is not supported." )
        };
    }


    /// <summary />
    private static string ToDigestMethod( HashAlgorithmName hashAlgorithm )
    {
        return hashAlgorithm.Name switch
        {
            "SHA256" => SignedXml.XmlDsigSHA256Url,
            "SHA384" => SignedXml.XmlDsigSHA384Url,
            "SHA512" => SignedXml.XmlDsigSHA512Url,
            _ => throw new NotSupportedException( $"Hash algorithm '{hashAlgorithm.Name}' is not supported." ),
        };
    }


    /// <summary />
    private static string ToSignatureMethod( KeyFamily keyFamily, HashAlgorithmName hashAlgorithm )
    {
        if ( keyFamily == KeyFamily.Ecdsa )
        {
            return hashAlgorithm.Name switch
            {
                "SHA256" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                "SHA512" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                _ => throw new NotSupportedException( $"Hash algorithm '{hashAlgorithm.Name}' is not supported." ),
            };
        }
        else
        {
            return hashAlgorithm.Name switch
            {
                "SHA256" => SignedXml.XmlDsigRSASHA256Url,
                "SHA384" => SignedXml.XmlDsigRSASHA384Url,
                "SHA512" => SignedXml.XmlDsigRSASHA512Url,
                _ => throw new NotSupportedException( $"Hash algorithm '{hashAlgorithm.Name}' is not supported." ),
            };
        }
    }
}