using System.Xml;

namespace Andalus.Cryptography.Xml.Placements;

/// <summary>
/// Places the signature as the last child of the document element.
/// </summary>
public class LastChildPlacement : IEnvelopedSignaturePlacement
{
    /// <inheritdoc />
    public void PlaceSignature( XmlDocument document, XmlElement signature )
    {
        if ( signature.OwnerDocument != document )
            throw new ArgumentException( "Signature must have same owner document." );

        document.DocumentElement!.AppendChild( signature );
    }


    /// <inheritdoc />
    public void EnsureLocation( XmlDocument document )
    {
    }


    /// <inheritdoc />
    public bool HasLocation( XmlDocument document )
    {
        return true;
    }
}