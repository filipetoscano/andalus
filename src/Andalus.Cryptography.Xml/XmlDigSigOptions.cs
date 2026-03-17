using System.Security.Cryptography.X509Certificates;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class XmlDigSigOptions
{
    /// <summary />
    public X509Certificate2? Certificate { get; set; }

    /// <summary />
    public KeyInfoPart AddKeyInfo { get; set; }

    /// <summary />
    public IEnvelopedSignaturePlacement? EnvelopedSignaturePlacement { get; set; }
}