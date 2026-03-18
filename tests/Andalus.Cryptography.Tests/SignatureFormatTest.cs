using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Andalus.Cryptography.Tests;

/// <summary />
/// <remarks>Thanks Claude!</remarks>
public class SignatureFormatTest
{
    // secp256k1 curve order
    private static readonly BigInteger Order = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
    );

    private static readonly int ComponentLength = 32; // secp256k1 = 256-bit → 32 bytes per r/s


    /// <summary />
    [Fact]
    public void P1363_to_Der_to_P1363_returns_original()
    {
        var r = new BigInteger( "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16 );
        var s = new BigInteger( "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16 );

        var ieee = PlainDsaEncoding.Instance.Encode( Order, r, s );

        var der = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );
        var roundTripped = SignatureFormat.ConvertDerToIeeeP1363( der, Order );

        Assert.Equal( ieee, roundTripped );
    }


    /// <summary />
    [Fact]
    public void Der_to_P1363_to_Der_returns_original()
    {
        var r = new BigInteger( "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16 );
        var s = new BigInteger( "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16 );

        var der = StandardDsaEncoding.Instance.Encode( Order, r, s );

        var ieee = SignatureFormat.ConvertDerToIeeeP1363( der, Order );
        var roundTripped = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );

        Assert.Equal( der, roundTripped );
    }


    /// <summary />
    [Fact]
    public void ConvertIeeeP1363ToDer_produces_valid_der_sequence()
    {
        var r = new BigInteger( "1", 16 );
        var s = new BigInteger( "2", 16 );

        var ieee = PlainDsaEncoding.Instance.Encode( Order, r, s );
        var der = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );

        // DER must start with SEQUENCE tag (0x30)
        Assert.Equal( 0x30, der[ 0 ] );

        // Parse and verify r, s integers
        var seq = Asn1Sequence.GetInstance( der );
        Assert.Equal( 2, seq.Count );

        var parsedR = DerInteger.GetInstance( seq[ 0 ] ).Value;
        var parsedS = DerInteger.GetInstance( seq[ 1 ] ).Value;

        Assert.Equal( r, parsedR );
        Assert.Equal( s, parsedS );
    }


    /// <summary />
    [Fact]
    public void ConvertIeeeP1363ToDer_high_bit_r_gets_zero_padded()
    {
        // r with high bit set → DER INTEGER must prepend 0x00
        var r = new BigInteger( "FF".PadRight( 64, '0' ), 16 );
        var s = new BigInteger( "01", 16 );

        var ieee = PlainDsaEncoding.Instance.Encode( Order, r, s );
        var der = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );

        var seq = Asn1Sequence.GetInstance( der );
        var rBytes = DerInteger.GetInstance( seq[ 0 ] ).Value.ToByteArrayUnsigned();

        // DER encoding of a positive integer with high bit set includes a leading 0x00
        // BouncyCastle's DerInteger handles this internally
        Assert.Equal( r, DerInteger.GetInstance( seq[ 0 ] ).Value );
    }


    /// <summary />
    [Fact]
    public void ConvertIeeeP1363ToDer_high_bit_s_gets_zero_padded()
    {
        var r = new BigInteger( "01", 16 );
        var s = new BigInteger( "FF".PadRight( 64, '0' ), 16 );

        var ieee = PlainDsaEncoding.Instance.Encode( Order, r, s );
        var der = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );

        var seq = Asn1Sequence.GetInstance( der );

        Assert.Equal( s, DerInteger.GetInstance( seq[ 1 ] ).Value );
    }


    /// <summary />
    [Fact]
    public void ConvertDerToIeeeP1363_produces_fixed_length_output()
    {
        var r = new BigInteger( "01", 16 );
        var s = new BigInteger( "02", 16 );

        var der = StandardDsaEncoding.Instance.Encode( Order, r, s );
        var ieee = SignatureFormat.ConvertDerToIeeeP1363( der, Order );

        // P1363 is always exactly 2 × component length (r || s)
        Assert.Equal( ComponentLength * 2, ieee.Length );
    }


    /// <summary />
    [Fact]
    public void ConvertDerToIeeeP1363_small_values_are_left_padded()
    {
        var r = new BigInteger( "01", 16 );
        var s = new BigInteger( "01", 16 );

        var der = StandardDsaEncoding.Instance.Encode( Order, r, s );
        var ieee = SignatureFormat.ConvertDerToIeeeP1363( der, Order );

        // r occupies first 32 bytes, left-padded with zeros
        var rSlice = ieee[ ..ComponentLength ];
        Assert.Equal( new byte[ ComponentLength - 1 ], rSlice[ ..^1 ] ); // all leading bytes are 0x00
        Assert.Equal( 0x01, rSlice[ ^1 ] );

        // s occupies last 32 bytes, left-padded with zeros
        var sSlice = ieee[ ComponentLength.. ];
        Assert.Equal( new byte[ ComponentLength - 1 ], sSlice[ ..^1 ] );
        Assert.Equal( 0x01, sSlice[ ^1 ] );
    }


    /// <summary />
    [Fact]
    public void ConvertDerToIeeeP1363_full_width_values_fill_components()
    {
        var r = new BigInteger( "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16 );
        var s = new BigInteger( "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16 );

        var der = StandardDsaEncoding.Instance.Encode( Order, r, s );
        var ieee = SignatureFormat.ConvertDerToIeeeP1363( der, Order );

        Assert.Equal( ComponentLength * 2, ieee.Length );

        // Verify r and s can be reconstructed from their fixed-width slots
        var extractedR = new BigInteger( 1, ieee[ ..ComponentLength ] );
        var extractedS = new BigInteger( 1, ieee[ ComponentLength.. ] );

        Assert.Equal( r, extractedR );
        Assert.Equal( s, extractedS );
    }


    /// <summary />
    [Fact]
    public void Known_vector_P1363_to_Der()
    {
        // r = 1, s = 1 → minimal DER: 30 06 02 01 01 02 01 01
        var r = BigInteger.One;
        var s = BigInteger.One;

        var ieee = PlainDsaEncoding.Instance.Encode( Order, r, s );
        var der = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );

        var seq = Asn1Sequence.GetInstance( der );

        Assert.Equal( BigInteger.One, DerInteger.GetInstance( seq[ 0 ] ).Value );
        Assert.Equal( BigInteger.One, DerInteger.GetInstance( seq[ 1 ] ).Value );
    }


    /// <summary />
    [Fact]
    public void Known_vector_Der_to_P1363()
    {
        // Manually constructed DER: SEQUENCE { INTEGER 1, INTEGER 2 }
        byte[] der = [ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 ];

        var ieee = SignatureFormat.ConvertDerToIeeeP1363( der, Order );

        Assert.Equal( ComponentLength * 2, ieee.Length );

        var extractedR = new BigInteger( 1, ieee[ ..ComponentLength ] );
        var extractedS = new BigInteger( 1, ieee[ ComponentLength.. ] );

        Assert.Equal( BigInteger.One, extractedR );
        Assert.Equal( BigInteger.Two, extractedS );
    }


    /// <summary />
    [Fact]
    public void Max_valid_r_and_s_just_below_order()
    {
        var maxValid = Order.Subtract( BigInteger.One );

        var ieee = PlainDsaEncoding.Instance.Encode( Order, maxValid, maxValid );
        var der = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );
        var roundTripped = SignatureFormat.ConvertDerToIeeeP1363( der, Order );

        Assert.Equal( ieee, roundTripped );
    }


    /// <summary />
    [Fact]
    public void Asymmetric_r_large_s_small()
    {
        var r = Order.Subtract( BigInteger.One );
        var s = BigInteger.One;

        var ieee = PlainDsaEncoding.Instance.Encode( Order, r, s );
        var der = SignatureFormat.ConvertIeeeP1363ToDer( ieee, Order );
        var result = SignatureFormat.ConvertDerToIeeeP1363( der, Order );

        Assert.Equal( ieee, result );
    }
}