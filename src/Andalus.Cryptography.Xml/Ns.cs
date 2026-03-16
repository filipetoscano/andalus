using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class Ns
{
    /// <summary />
    public const string Xades123 = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary />
    public const string DigSig = SignedXml.XmlDsigNamespaceUrl;


    /// <summary />
    public static XmlNamespaceManager Manager { get => _mgr.Value; }


    private static Lazy<XmlNamespaceManager> _mgr = new Lazy<XmlNamespaceManager>( () =>
    {
        var mgr = new XmlNamespaceManager( new NameTable() );
        mgr.AddNamespace( "ds", DigSig );
        mgr.AddNamespace( "xa", Xades123 );

        return mgr;
    } );
}