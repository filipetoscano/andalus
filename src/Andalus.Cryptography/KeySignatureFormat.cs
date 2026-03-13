namespace Andalus.Cryptography;

/// <summary />
public enum KeySignatureFormat
{
    /// <summary>PKCS#1 v1.5 or PSS for RSA.</summary>
    Pkcs1,

    /// <summary>IEEE P1363 fixed-length r||s for ECDSA.</summary>
    IeeeP1363,

    /// <summary>DER-encoded SEQUENCE { INTEGER r, INTEGER s } for ECDSA.</summary>
    Der,
}