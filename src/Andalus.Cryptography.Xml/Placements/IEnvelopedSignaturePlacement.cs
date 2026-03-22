using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary>
/// Interface for placement strategy of enveloped signatures.
/// </summary>
public interface IEnvelopedSignaturePlacement
{
    /// <summary />
    List<Transform>? GetTransforms();

    /// <summary />
    void PreSignature( XmlDocument document );

    /// <summary>
    /// Places the enveloped signature into the document.
    /// </summary>
    /// <param name="document">Document.</param>
    /// <param name="signature">Signature.</param>
    /// <remarks>
    /// This method is called after signing.
    /// </remarks>
    void PlaceSignature( XmlDocument document, XmlElement signature );
}