using Andalus.Cryptography.Xml;
using System.Xml;

namespace Andalus.Xml.Ubl;

/// <summary />
public class UblNs
{
    /// <summary />
    public const string CreditNote = "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2";

    /// <summary />
    public const string Invoice = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";


    /// <summary />
    public const string AggregateUrn = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";

    /// <summary />
    public const string BasicUrn = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";

    /// <summary />
    public const string ExtensionUrn = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";

    /// <summary />
    public const string SignatureUrn = "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2";

    /// <summary />
    public const string SignatureAggregateUrn = "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2";

    /// <summary />
    public const string SignatureBasicUrn = "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2";


    /// <summary />
    public static XmlNamespaceManager NamespaceManager { get => _mgr.Value; }


    private static readonly Lazy<XmlNamespaceManager> _mgr = new Lazy<XmlNamespaceManager>( () =>
    {
        var mgr = new XmlNamespaceManager( new NameTable() );
        mgr.AddNamespace( "cn", CreditNote );
        mgr.AddNamespace( "iv", Invoice );

        mgr.AddNamespace( "cac", AggregateUrn );
        mgr.AddNamespace( "cbc", BasicUrn );
        mgr.AddNamespace( "cec", ExtensionUrn );
        mgr.AddNamespace( "csc", SignatureUrn );

        mgr.AddNamespace( "sac", SignatureAggregateUrn );
        mgr.AddNamespace( "sbc", SignatureBasicUrn );

        mgr.AddNamespace( "ds", XmlNs.DigSig );
        mgr.AddNamespace( "x132", XmlNs.Xades132 );
        mgr.AddNamespace( "x141", XmlNs.Xades141 );

        return mgr;
    } );
}