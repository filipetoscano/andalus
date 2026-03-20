using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml;

/// <summary />
public class XPathExclusion
{
    /// <summary />
    public required string XPath { get; set; }

    /// <summary />
    public Dictionary<string, string>? Namespaces { get; set; }


    /// <summary />
    public XmlDsigXPathTransform ToTransform()
    {
        var frag = new XmlDocument() { PreserveWhitespace = true };
        frag.LoadXml( "<XPath />" );

        var elem = frag.DocumentElement!;
        elem.InnerText = this.XPath;

        if ( this.Namespaces != null )
        {
            foreach ( var kv in this.Namespaces )
            {
                var attr = frag.CreateAttribute( "xmlns", kv.Key, "http://www.w3.org/2000/xmlns/" );
                attr.Value = kv.Value;

                elem.Attributes.Append( attr );
            }
        }

        var transform = new XmlDsigXPathTransform();
        transform.LoadInnerXml( frag.SelectNodes( " //* " )! );

        return transform;
    }
}