namespace Andalus.Cryptography.Xml;

/// <summary />
[Flags]
public enum KeyInfoPart
{
    /// <summary />
    None = 0,

    /// <summary />
    Certificate = 1,

    /// <summary />
    SubjectName = 2,

    /// <summary />
    IssuerSerial = 4,
}