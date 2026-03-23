using System.Xml;

namespace Andalus.Xml.Ubl;

internal static class InternalExtensions
{
    /// <summary />
    internal static XmlElement? Single( this XmlNode node, string xpath )
    {
        return (XmlElement?) node.SelectSingleNode( xpath, UblNs.NamespaceManager );
    }


    /// <summary />
    internal static void Remove( this XmlNode node, string xpath )
    {
        var elem = node.SelectSingleNode( xpath, UblNs.NamespaceManager )!;
        elem.ParentNode!.RemoveChild( elem );
    }


    /// <summary />
    internal static IEnumerable<XmlElement> Elements( this XmlNode node, string xpath )
    {
        return node.SelectNodes( xpath, UblNs.NamespaceManager )!.OfType<XmlElement>();
    }
}