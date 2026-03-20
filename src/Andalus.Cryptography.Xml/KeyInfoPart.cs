namespace Andalus.Cryptography.Xml;

/// <summary />
[Flags]
public enum KeyInfoPart
{
    /// <summary />
    None = 0,

    /// <summary>
    /// Signing certificate.
    /// </summary>
    Certificate = 1,

    /// <summary>
    /// Subject name of signing certificate.
    /// </summary>
    SubjectName = 2,

    /// <summary>
    /// Subject name and serial number of issuer.
    /// </summary>
    Issuer = 4,
}