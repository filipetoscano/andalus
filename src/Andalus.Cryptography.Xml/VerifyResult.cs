using System.Text.Json.Serialization;
using System.Xml;

namespace Andalus.Cryptography.Xml;


/// <summary />
public class VerifyResult
{
    /// <summary />
    public required bool HasSignatures { get; init; }

    /// <summary />
    public required bool IsValid { get; init; }

    /// <summary />
    public required List<VerifySignatureResult> Signatures { get; init; }
}


/// <summary />
public class VerifySignatureResult
{
    /// <summary />
    public required string? Id { get; init; }

    /// <summary />
    public required bool IsValid { get; init; }

    /// <summary />
    [JsonIgnore]
    public XmlElement SignatureElement { get; init; } = default!;

    /// <summary />
    public string RefUri
    {
        get
        {
            return this.SignatureElement
                .SelectSingleNode( " ds:SignedInfo/ds:Reference/@URI ", XmlNs.Manager )!.Value ?? "";
        }
    }

    /// <summary />
    public string DigestValue
    {
        get
        {
            return this.SignatureElement
                .SelectSingleNode( " ds:SignedInfo/ds:Reference/ds:DigestValue ", XmlNs.Manager )!.InnerText;
        }
    }
}