using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Andalus.Cryptography;

/// <summary />
public class SignatureFormat
{
    /// <summary>
    /// IEEE P1363 (r||s) → DER SEQUENCE { INTEGER r, INTEGER s }
    /// </summary>
    public static byte[] ConvertIeeeP1363ToDer( byte[] ieee, BigInteger order )
    {
        var rs = PlainDsaEncoding.Instance.Decode( order, ieee );

        return StandardDsaEncoding.Instance.Encode( order, rs[ 0 ], rs[ 1 ] );
    }

    /// <summary>
    /// DER SEQUENCE { INTEGER r, INTEGER s } → IEEE P1363 (r||s)
    /// </summary>
    public static byte[] ConvertDerToIeeeP1363( byte[] der, BigInteger order )
    {
        var rs = StandardDsaEncoding.Instance.Decode( order, der );

        return PlainDsaEncoding.Instance.Encode( order, rs[ 0 ], rs[ 1 ] );
    }
}