using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class Xades141
{
    /// <summary />
    public static XmlElement BuildXadesObject(
        XmlDocument document,
        X509Certificate2 certificate )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        var digestBytes = SHA256.HashData( certificate.RawData );
        var issuerSerialV2 = BuildIssuerSerialV2( certificate );


        /*
         *
         */
        var elem = (XmlElement) document.ImportNode( _fragment.Value, true );

        elem.SelectSingleNode( " //x132:SignedProperties/@Id ", XmlNs.Manager )!.Value = "xades-" + Guid.NewGuid().ToString();
        elem.SelectSingleNode( " //x132:SigningTime ", XmlNs.Manager )!.InnerText = XmlConvert.ToString( DateTime.UtcNow, XmlDateTimeSerializationMode.Utc );
        elem.SelectSingleNode( " //ds:DigestValue ", XmlNs.Manager )!.InnerText = Convert.ToBase64String( digestBytes );
        elem.SelectSingleNode( " //x141:IssuerSerialV2 ", XmlNs.Manager )!.InnerText = issuerSerialV2;

        return elem;
    }


    /// <summary />
    private static string BuildIssuerSerialV2( X509Certificate2 certificate )
    {
        var serial = new BigInteger( certificate.SerialNumberBytes.Span, isUnsigned: true, isBigEndian: true );

        var writer = new AsnWriter( AsnEncodingRules.DER );

        using ( writer.PushSequence() )                                                    // IssuerSerial
        {
            using ( writer.PushSequence() )                                                // GeneralNames
            {
                var directoryName = new Asn1Tag( TagClass.ContextSpecific, 4, isConstructed: true );
                using ( writer.PushSequence( directoryName ) )                             // [4] EXPLICIT Name
                {
                    writer.WriteEncodedValue( certificate.IssuerName.RawData );            // raw DER Name bytes
                }
            }

            writer.WriteInteger( serial );                                                 // serialNumber
        }

        return Convert.ToBase64String( writer.Encode() );
    }


    /// <summary />
    private static Lazy<XmlElement> _fragment = new Lazy<XmlElement>( () =>
    {
        using var resx = typeof( Xades141 ).Assembly.GetManifestResourceStream( "Andalus.Cryptography.Xml.Resources.Xades141.xml" );

        var doc = new XmlDocument();
        doc.Load( resx! );

        return doc.DocumentElement!;
    } );
}
