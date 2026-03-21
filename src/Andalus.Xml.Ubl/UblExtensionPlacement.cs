using Andalus.Cryptography.Xml;
using System.Xml;

namespace Andalus.Xml.Ubl;

/// <summary />
public class UblExtensionPlacement : IEnvelopedSignaturePlacement
{
    private readonly string _role;
    private readonly string _partyIdentification;



    /// <summary />
    public UblExtensionPlacement( string role, string partyIdentification )
    {
        _role = role;
        _partyIdentification = partyIdentification;
    }


    /// <inheritdoc />
    public void PreSignature( XmlDocument document )
    {
        /*
         * 
         */
        var root = document.DocumentElement!;
        var extensions = root.Single( " cec:UBLExtensions" );

        if ( extensions == null )
        {
            extensions = document.CreateElement( "cec:UBLExtensions", UblNs.ExtensionUrn );
            root.PrependChild( extensions );
        }


        /*
         * How many digital signatures?
         */
        var count = 1 + extensions.Elements( " cec:UBLExtension[ cec:ExtensionURI = 'urn:oasis:names:specification:ubl:dsig:enveloped:xades' ] " ).Count();

        var sigId = "urn:oasis:names:specification:ubl:signature:" + _role;
        var sigInfoId = "urn:oasis:names:specification:ubl:signature:" + count;


        /*
         * Insert cac:Signature before cac:AccountingSupplierParty
         */
        var bodySig = (XmlElement) document.ImportNode( _bodySignature.Value, true );
        bodySig.Single( " cbc:ID " )!.InnerText = sigId;
        bodySig.Single( " cac:SignatoryParty/cac:PartyIdentification/cbc:ID " )!.InnerText = _partyIdentification;

        var supplier = root.Single( " cac:AccountingSupplierParty " )!;
        root.InsertBefore( bodySig, supplier );


        /*
         * Append cec:UBLExtension
         */
        var extension = (XmlElement) document.ImportNode( _extension.Value, true );

        var sigInfo = extension.Single( " .//sac:SignatureInformation " )!;
        sigInfo.Single( " cbc:ID " )!.InnerText = sigInfoId;
        sigInfo.Single( " sbc:ReferencedSignatureID " )!.InnerText = sigId;

        extensions.AppendChild( extension );
    }


    /// <inheritdoc />
    public void PlaceSignature( XmlDocument document, XmlElement signature )
    {
        if ( signature.OwnerDocument != document )
            throw new ArgumentException( "Signature must have same owner document." );


        /*
         * 
         */
        var root = document.DocumentElement!;
        var sigId = "urn:oasis:names:specification:ubl:signature:" + _role;
        var xpath = $" .//sac:SignatureInformation[ sbc:ReferencedSignatureID = '{sigId}' ] ";

        var sigInfo = root.Single( xpath )!;
        sigInfo.AppendChild( signature );
    }


    /// <summary />
    private static Lazy<XmlElement> _extension = new Lazy<XmlElement>( () =>
    {
        using var resx = typeof( UblExtensionPlacement ).Assembly.GetManifestResourceStream( "Andalus.Xml.Ubl.Resources.UblExtension.xml" );

        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.Load( resx! );

        return doc.DocumentElement!;
    } );


    /// <summary />
    private static Lazy<XmlElement> _bodySignature = new Lazy<XmlElement>( () =>
    {
        using var resx = typeof( UblExtensionPlacement ).Assembly.GetManifestResourceStream( "Andalus.Xml.Ubl.Resources.BodySignature.xml" );

        var doc = new XmlDocument() { PreserveWhitespace = true };
        doc.Load( resx! );

        return doc.DocumentElement!;
    } );
}