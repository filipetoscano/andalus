using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class XmlDigSigOptions
{
    /// <summary />
    public SignatureProfile Profile { get; set; } = SignatureProfile.XmlDigSig;

    /// <summary />
    public XmlCanonicalization Canonicalization { get; set; } = XmlCanonicalization.XmlDsigC14NTransform;

    /// <summary />
    public X509Certificate2? Certificate { get; set; }

    /// <summary />
    public KeyInfoPart AddKeyInfo { get; set; }

    /// <summary />
    public IEnvelopedSignaturePlacement? EnvelopedSignaturePlacement { get; set; }

    /// <summary>
    /// Additional transforms to apply to the document reference.
    /// </summary>
    /// <remarks>
    /// Transforms will be added after the signature transformation and
    /// before document canonicalization.
    /// </remarks>
    public List<Transform>? ReferenceTransforms { get; set; }
}