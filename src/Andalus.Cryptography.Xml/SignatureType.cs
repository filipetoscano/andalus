namespace Andalus.Cryptography.Xml;

/// <summary />
public enum SignatureType
{
    /// <summary>
    /// Signature is placed within the document being signed,
    /// at a location which does not break the document schema.
    /// </summary>
    Enveloped,

    /// <summary>
    /// Signature contains the document being signed.
    /// </summary>
    Enveloping,

    /// <summary>
    /// Signature exists as distinct separate document.
    /// </summary>
    Detached,
}