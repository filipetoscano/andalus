using System.Security.Cryptography.Xml;

namespace Andalus.Cryptography.Xml.Algorithms;

/// <summary />
public class XmlDsigC14N11Transform : XmlDsigC14NTransform
{
    public const string AlgorithmUri = "http://www.w3.org/2006/12/xml-c14n11";


    /// <summary />
    public XmlDsigC14N11Transform()
    {
        Algorithm = AlgorithmUri;
    }
}