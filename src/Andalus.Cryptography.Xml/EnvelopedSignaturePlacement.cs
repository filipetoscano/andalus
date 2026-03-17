using System.Xml;

namespace Andalus.Cryptography.Xml;


/// <summary>
/// Interface for placement strategy of enveloped signatures.
/// </summary>
public interface IEnvelopedSignaturePlacement
{
    /// <summary>
    /// Checks if the document has the insert location.
    /// </summary>
    /// <param name="document">Document.</param>
    /// <returns>True if the embed location already exists, false otherwise.</returns>
    /// <remarks>
    /// This method can be used by calling code to determine if <see cref="EnsureLocation" />
    /// may change the nodes impacted by the signature. Calling code may choose to
    /// set different exclusions.
    /// </remarks>
    bool HasLocation( XmlDocument document );

    /// <summary>
    /// Ensures that the insert location exists.
    /// </summary>
    /// <param name="document">Document.</param>
    /// <returns>Insert location.</returns>
    /// <remarks>
    /// This method is called before signing. Any elements created by this method will
    /// be part of the digital signature, unless otherwise conditionally ignored by
    /// exclusions.
    /// </remarks>
    void EnsureLocation( XmlDocument document );


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


/// <summary>
/// Places the signature as the first child of the document element.
/// </summary>
public class FirstChildPlacement : IEnvelopedSignaturePlacement
{
    /// <inheritdoc />
    public void PlaceSignature( XmlDocument document, XmlElement signature )
    {
        if ( signature.OwnerDocument != document )
            throw new ArgumentException( "Signature must have same owner document." );

        document.DocumentElement!.PrependChild( signature );
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