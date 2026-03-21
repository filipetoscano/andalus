using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class XmlNs
{
    /// <summary />
    public const string DigSig = SignedXml.XmlDsigNamespaceUrl;

    /// <summary />
    public const string Xades132 = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary />
    public const string Xades141 = "http://uri.etsi.org/01903/v1.4.1#";


    /// <summary />
    public static XmlNamespaceManager Manager { get => _mgr.Value; }


    private static Lazy<XmlNamespaceManager> _mgr = new Lazy<XmlNamespaceManager>( () =>
    {
        var mgr = new XmlNamespaceManager( new NameTable() );
        mgr.AddNamespace( "ds", DigSig );
        mgr.AddNamespace( "x132", Xades132 );
        mgr.AddNamespace( "x141", Xades141 );

        return mgr;
    } );
}