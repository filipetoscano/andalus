using Andalus.Cryptography.Xml.Algorithms;
using Andalus.Cryptography.Xml.Internals;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class XmlDigSig
{
    /// <summary />
    static XmlDigSig()
    {
        CryptoConfigConfiguration.Register();
    }


    /// <summary>
    /// Verifies all <c>&lt;Signature&gt;</c> elements in the document.
    /// Returns <c>true</c> if all signatures are valid.
    /// </summary>
    public static bool VerifyAll( XmlDocument document )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        var signatureNodes = document.SelectNodes( " //ds:Signature ", Ns.Manager );

        if ( signatureNodes == null || signatureNodes.Count == 0 )
            return false;

        foreach ( XmlElement signatureElement in signatureNodes )
        {
            var signedXml = new SignedXml( document );
            signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11Transform.AlgorithmUri );
            signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11WithCommentsTransform.AlgorithmUri );
            signedXml.SafeCanonicalizationMethods.Add( SignedXml.XmlDsigXPathTransformUrl );

            signedXml.LoadXml( signatureElement );

            if ( signedXml.CheckSignature() == false )
                return false;
        }

        return true;
    }


    /// <summary>
    /// Verifies all signatures against an explicit certificate.
    /// </summary>
    public static bool VerifyAll( XmlDocument document, X509Certificate2 certificate )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        var signatureNodes = document.SelectNodes( " //ds:Signature ", Ns.Manager );

        if ( signatureNodes == null || signatureNodes.Count == 0 )
            return false;

        foreach ( XmlElement signatureElement in signatureNodes )
        {
            var signedXml = new SignedXml( document );
            signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11Transform.AlgorithmUri );
            signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11WithCommentsTransform.AlgorithmUri );
            signedXml.SafeCanonicalizationMethods.Add( SignedXml.XmlDsigXPathTransformUrl );

            signedXml.LoadXml( signatureElement );

            if ( signedXml.CheckSignature( certificate, true ) == false )
                return false;
        }

        return true;
    }


    /// <summary>
    /// Verifies a detached signature.
    /// </summary>
    public static bool VerifyDetached( XmlDocument document, XmlDocument detached )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        if ( detached.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );


        /*
         * 
         */
        var signatureElement = detached.DocumentElement;

        if ( signatureElement == null )
            return false;

        var signedXml = new SignedXml( document );
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11Transform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11WithCommentsTransform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( SignedXml.XmlDsigXPathTransformUrl );

        signedXml.LoadXml( signatureElement );

        return signedXml.CheckSignature();
    }


    /// <summary>
    /// Verifies a detached signature against an explicit certificate.
    /// </summary>
    public static bool VerifyDetached( XmlDocument document, XmlDocument detached, X509Certificate2 certificate )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        if ( detached.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );


        /*
         * 
         */
        var signatureElement = detached.DocumentElement;

        if ( signatureElement == null )
            return false;

        var signedXml = new SignedXml( document );
        signedXml.SafeCanonicalizationMethods.Add( SignedXml.XmlDsigXPathTransformUrl );
        signedXml.LoadXml( signatureElement );

        return signedXml.CheckSignature( certificate, true );
    }


    /// <summary />
    public static XmlDocument Sign(
        SignatureType signatureType,
        XmlDocument document,
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithm,
        XmlDigSigOptions? options = null
    )
    {
        if ( signatureType == SignatureType.Enveloped )
            return SignEnveloped( document, provider, key, hashAlgorithm, options );

        if ( signatureType == SignatureType.Enveloping )
            return SignEnveloping( document, provider, key, hashAlgorithm, options );

        if ( signatureType == SignatureType.Detached )
            return SignDetached( document, provider, key, hashAlgorithm, options );

        throw new ArgumentOutOfRangeException( nameof( signatureType ) );
    }


    /// <summary />
    public static XmlDocument SignEnveloped(
        XmlDocument document,
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithm,
        XmlDigSigOptions? options = null )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );


        /*
         * 
         */
        var enveloped = options?.EnvelopedSignaturePlacement ?? new Placements.FirstChildPlacement();
        enveloped.EnsureLocation( document );


        /*
         * 
         */
        var docRef = CreateReference( "", options, enveloped: true );


        /*
         * 
         */
        var signedXml = new SignedXml( document );
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11Transform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11WithCommentsTransform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( SignedXml.XmlDsigXPathTransformUrl );
        signedXml.AddReference( docRef );


        /*
         * 
         */
        var xmlSig = ComputeSignature( signedXml, provider, key, hashAlgorithm, options );
        var docSig = (XmlElement) document.ImportNode( xmlSig, true );

        enveloped.PlaceSignature( document, docSig );

        return document;
    }


    /// <summary />
    public static XmlDocument SignEnveloping(
        XmlDocument document,
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithm,
        XmlDigSigOptions? options = null )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        if ( document.DocumentElement == null )
            throw new InvalidOperationException( "Expected XML document to have a document element" );


        /*
         * 
         */
        var doc = new XmlDocument { PreserveWhitespace = true };

        var signedXml = new SignedXml();
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11Transform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11WithCommentsTransform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( SignedXml.XmlDsigXPathTransformUrl );

        string objectId = "signed-" + Guid.NewGuid().ToString();
        var dataObject = new DataObject( objectId, "", "", (XmlElement) doc.ImportNode( document.DocumentElement, true ) );
        signedXml.AddObject( dataObject );


        /*
         * 
         */
        var objRef = CreateReference( $"#{objectId}", options );
        signedXml.AddReference( objRef );


        /*
         * 
         */
        var xmlSig = ComputeSignature( signedXml, provider, key, hashAlgorithm, options );
        doc.AppendChild( doc.ImportNode( xmlSig, true ) );

        return doc;
    }


    /// <summary />
    public static XmlDocument SignDetached(
        XmlDocument document,
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithm,
        XmlDigSigOptions? options = null )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );


        /*
         * 
         */
        var extRef = CreateReference( "", options );

        var signedXml = new SignedXml( document );
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11Transform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( XmlDsigC14N11WithCommentsTransform.AlgorithmUri );
        signedXml.SafeCanonicalizationMethods.Add( SignedXml.XmlDsigXPathTransformUrl );

        signedXml.AddReference( extRef );


        /*
         * 
         */
        var signature = ComputeSignature( signedXml, provider, key, hashAlgorithm, options );

        var doc = new XmlDocument() { PreserveWhitespace = true };
        var root = doc.ImportNode( signature, true );
        doc.AppendChild( root );

        return doc;
    }


    /// <summary />
    private static Reference CreateReference( string uri, XmlDigSigOptions? options, bool enveloped = false )
    {
        var reference = new Reference( uri );

        if ( enveloped == true )
            reference.AddTransform( new XmlDsigEnvelopedSignatureTransform() );


        /*
         * 
         */
        if ( options?.ReferenceTransforms != null )
        {
            foreach ( var transform in options.ReferenceTransforms )
                reference.AddTransform( transform );
        }


        /*
         * 
         */
        var canon = options?.Canonicalization ?? XmlCanonicalization.XmlDsigC14NTransform;
        Transform trans = canon switch
        {
            XmlCanonicalization.XmlDsigC14NTransform => new XmlDsigC14NTransform(),
            XmlCanonicalization.XmlDsigC14NWithCommentsTransform => new XmlDsigC14NWithCommentsTransform(),

            XmlCanonicalization.XmlDsigC14N11Transform => new XmlDsigC14N11Transform(),
            XmlCanonicalization.XmlDsigC14N11WithCommentsTransform => new XmlDsigC14N11WithCommentsTransform(),

            XmlCanonicalization.XmlDsigExcC14NTransform => new XmlDsigExcC14NTransform(),
            XmlCanonicalization.XmlDsigExcC14NWithCommentsTransform => new XmlDsigExcC14NWithCommentsTransform(),

            _ => throw new NotSupportedException( $"Xml canonicalization '{canon}' is not supported" ),
        };

        reference.AddTransform( trans );

        return reference;
    }


    /// <summary />
    private static XmlElement ComputeSignature(
        SignedXml signedXml,
        ICryptoProvider provider,
        KeyReference key,
        HashAlgorithmName hashAlgorithm,
        XmlDigSigOptions? options )
    {
        var canon = options?.Canonicalization ?? XmlCanonicalization.XmlDsigC14NTransform;

        using var proxy = CreateSigningProxy( provider, key, hashAlgorithm );

        signedXml.SigningKey = proxy;
        signedXml.SignedInfo!.CanonicalizationMethod = canon.ToAlgorithmUrl();
        signedXml.SignedInfo.SignatureMethod = ToSignatureMethod( key.KeyType.Family(), hashAlgorithm );

        // Set digest method on all references
        var digestMethod = ToDigestMethod( hashAlgorithm );

        foreach ( Reference reference in signedXml.SignedInfo.References )
            reference.DigestMethod = digestMethod;

        AddKeyInfo( signedXml, options );

        signedXml.ComputeSignature();

        return signedXml.GetXml();
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
    private static void AddKeyInfo( SignedXml signedXml, XmlDigSigOptions? options )
    {
        if ( options == null || options.AddKeyInfo == KeyInfoPart.None )
            return;

        if ( options.Certificate is null )
            throw new InvalidOperationException( "Certificate is required when adding key info." );

        var x509Data = new KeyInfoX509Data();

        if ( options.AddKeyInfo.HasFlag( KeyInfoPart.Certificate ) )
            x509Data.AddCertificate( options.Certificate );

        if ( options.AddKeyInfo.HasFlag( KeyInfoPart.Issuer ) )
            x509Data.AddIssuerSerial( options.Certificate.Issuer, options.Certificate.SerialNumber );

        if ( options.AddKeyInfo.HasFlag( KeyInfoPart.SubjectName ) )
            x509Data.AddSubjectName( options.Certificate.Subject );

        var keyInfo = new KeyInfo();
        keyInfo.AddClause( x509Data );

        signedXml.KeyInfo = keyInfo;
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