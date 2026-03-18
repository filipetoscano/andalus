using Org.BouncyCastle.Asn1;

namespace Andalus.Cryptography;

/// <summary />
public class CsrData
{
    /// <summary>
    /// (CN) Common Name
    /// </summary>
    public required string CommonName { get; set; }

    /// <summary>
    /// (Device) Serial Number
    /// </summary>
    public string? SerialNumber { get; set; }

    /// <summary>
    /// (O) Organization
    /// </summary>
    public string? Organization { get; set; }

    /// <summary>
    /// (OI) Organization Identifier
    /// </summary>
    public string? OrganizationIdentifier { get; set; }

    /// <summary>
    /// (OU) Organizational Unit
    /// </summary>
    public string? OrganizationalUnit { get; set; }

    /// <summary>
    /// Business category
    /// </summary>
    public string? BusinessCategory { get; set; }

    /// <summary>
    /// (L) Locality
    /// </summary>
    public string? Locality { get; internal set; }

    /// <summary>
    /// (C) Country
    /// </summary>
    public string? Country { get; set; }

    /// <summary>
    /// Additional custom subject key info key/values, where the
    /// key is an OID.
    /// </summary>
    public Dictionary<string, string>? Additional { get; set; }


    /// <summary />
    public DerSet? Attributes { get; set; }
}