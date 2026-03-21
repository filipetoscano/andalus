using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class Xades132
{
    /// <summary />
    public static XmlElement BuildXadesObject(
        XmlDocument document,
        X509Certificate2 certificate )
    {
        if ( document.PreserveWhitespace == false )
            throw new InvalidOperationException( "Expected XML document to be initialized with PreserveWhitespace = true" );

        var bytes = SHA256.HashData( certificate.RawData );


        /*
         * 
         */
        var elem = (XmlElement) document.ImportNode( _fragment.Value, true );

        elem.SelectSingleNode( " //x132:SignedProperties/@Id ", Ns.Manager )!.Value = "xades-" + Guid.NewGuid().ToString();
        elem.SelectSingleNode( " //x132:SigningTime ", Ns.Manager )!.InnerText = XmlConvert.ToString( DateTime.UtcNow, XmlDateTimeSerializationMode.Utc );
        elem.SelectSingleNode( " //ds:DigestValue ", Ns.Manager )!.InnerText = Convert.ToBase64String( bytes );
        elem.SelectSingleNode( " //ds:X509IssuerName ", Ns.Manager )!.InnerText = certificate.Issuer;
        elem.SelectSingleNode( " //ds:X509SerialNumber ", Ns.Manager )!.InnerText = HexToDecimal( certificate.SerialNumber );

        return elem;
    }


    /// <summary />
    private static string HexToDecimal( string hex )
    {
        // Ensure positive by prefixing 0 if leading nibble >= 8
        if ( "89ABCDEFabcdef".Contains( hex[ 0 ] ) )
            hex = "0" + hex;

        var value = BigInteger.Parse( hex, NumberStyles.HexNumber );
        return value.ToString();
    }


    /// <summary />
    private static Lazy<XmlElement> _fragment = new Lazy<XmlElement>( () =>
    {
        using var resx = typeof( Xades132 ).Assembly.GetManifestResourceStream( "Andalus.Cryptography.Xml.Resources.Xades132.xml" );

        var doc = new XmlDocument();
        doc.Load( resx! );

        return doc.DocumentElement!;
    } );
}