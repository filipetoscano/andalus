using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml.Placements;

/// <summary>
/// Places the signature as the first child of the document element.
/// </summary>
public class FirstChildPlacement : IEnvelopedSignaturePlacement
{
    /// <inheritdoc />
    public List<Transform>? GetTransforms()
    {
        return null;
    }


    /// <inheritdoc />
    public void PlaceSignature( XmlDocument document, XmlElement signature )
    {
        if ( signature.OwnerDocument != document )
            throw new ArgumentException( "Signature must have same owner document." );

        document.DocumentElement!.PrependChild( signature );
    }


    /// <inheritdoc />
    public void PreSignature( XmlDocument document )
    {
    }
}