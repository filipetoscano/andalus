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