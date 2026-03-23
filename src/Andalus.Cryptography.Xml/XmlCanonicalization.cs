namespace Andalus.Cryptography.Xml;

/// <summary>
/// Specifies the canonicalization algorithm applied to XML content
/// before signing or digest computation.
/// </summary>
public enum XmlCanonicalization
{
    /// <summary>
    /// Canonical XML 1.0 (omits comments).
    /// </summary>
    /// <remarks>
    /// Algorithm URI: <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</c>
    /// </remarks>
    XmlDsigC14NTransform,

    /// <summary>
    /// Canonical XML 1.1 (omits comments).
    /// </summary>
    /// <remarks>
    /// Algorithm URI: <c>http://www.w3.org/2006/12/xml-c14n11</c>
    /// </remarks>
    XmlDsigC14N11Transform,

    /// <summary>
    /// Canonical XML 1.0 (preserves comments).
    /// </summary>
    /// <remarks>
    /// Algorithm URI: <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments</c>
    /// </remarks>
    XmlDsigC14NWithCommentsTransform,

    /// <summary>
    /// Canonical XML 1.1 (preserves comments).
    /// </summary>
    /// <remarks>
    /// Algorithm URI: <c>http://www.w3.org/2006/12/xml-c14n11#WithComments</c>
    /// </remarks>
    XmlDsigC14N11WithCommentsTransform,

    /// <summary>
    /// Exclusive Canonical XML 1.0 (omits comments). Only namespaces
    /// visibly utilized by the target node set are included.
    /// </summary>
    /// <remarks>
    /// Algorithm URI: <c>http://www.w3.org/2001/10/xml-exc-c14n#</c>
    /// </remarks>
    XmlDsigExcC14NTransform,

    /// <summary>
    /// Exclusive Canonical XML 1.0 (preserves comments). Only namespaces
    /// visibly utilized by the target node set are included.
    /// </summary>
    /// <remarks>
    /// Algorithm URI: <c>http://www.w3.org/2001/10/xml-exc-c14n#WithComments</c>
    /// </remarks>
    XmlDsigExcC14NWithCommentsTransform,
}