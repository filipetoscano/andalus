using System.Security.Cryptography.Xml;
using System.Xml;

namespace Andalus.Cryptography.Xml.Internals;

/// <summary>
/// Extends <see cref="SignedXml"/> so that <c>GetIdElement</c> searches
/// recursively inside <c>ds:Object</c> content. This is required for XAdES,
/// where the reference URI points to <c>xades:SignedProperties/@Id</c> which
/// is nested inside the <c>xades:QualifyingProperties</c> child of a
/// <c>ds:Object</c> — a depth that the base implementation does not reach.
/// </summary>
internal class AndalusSignedXml : SignedXml
{
    /// <summary />
    internal AndalusSignedXml() : base() { }

    /// <summary />
    internal AndalusSignedXml( XmlDocument document ) : base( document ) { }


    /// <inheritdoc />
    public override XmlElement? GetIdElement( XmlDocument? document, string idValue )
    {
        var result = base.GetIdElement( document, idValue );

        if ( result != null )
            return result;

        foreach ( DataObject obj in Signature.ObjectList )
        {
            foreach ( XmlNode node in obj.Data )
            {
                if ( node is XmlElement elem )
                {
                    var found = FindById( elem, idValue );

                    if ( found != null )
                        return found;
                }
            }
        }

        return null;
    }


    /// <summary />
    private static XmlElement? FindById( XmlElement element, string idValue )
    {
        if ( element.GetAttribute( "Id" ) == idValue ||
             element.GetAttribute( "id" ) == idValue ||
             element.GetAttribute( "ID" ) == idValue )
        {
            return element;
        }

        foreach ( XmlNode child in element.ChildNodes )
        {
            if ( child is XmlElement childElem )
            {
                var found = FindById( childElem, idValue );

                if ( found != null )
                    return found;
            }
        }

        return null;
    }
}