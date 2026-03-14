namespace Andalus.Cryptography;

/// <summary />
public class SignatureFormat
{
    /// <summary>
    /// Converts a fixed-length r||s signature to DER-encoded
    /// SEQUENCE { INTEGER r, INTEGER s }.
    /// </summary>
    public static byte[] ConvertIeeeP1363ToDer( byte[] ieee )
    {
        var half = ieee.Length / 2;

        var r = TrimLeadingZeros( ieee.AsSpan( 0, half ) );
        var s = TrimLeadingZeros( ieee.AsSpan( half, half ) );

        // DER INTEGERs are signed; pad with 0x00 if the high bit is set.
        var rNeedsPad = ( r[ 0 ] & 0x80 ) != 0;
        var sNeedsPad = ( s[ 0 ] & 0x80 ) != 0;

        var rLen = r.Length + ( rNeedsPad ? 1 : 0 );
        var sLen = s.Length + ( sNeedsPad ? 1 : 0 );

        // SEQUENCE tag (1) + length (1-2) + INTEGER tag (1) + length (1) + r + INTEGER tag (1) + length (1) + s
        var sequencePayload = 2 + rLen + 2 + sLen;
        var totalLen = 1 + ( sequencePayload > 127 ? 2 : 1 ) + sequencePayload;

        var der = new byte[ totalLen ];
        var offset = 0;

        // SEQUENCE
        der[ offset++ ] = 0x30;
        offset += WriteDerLength( der.AsSpan( offset ), sequencePayload );

        // INTEGER r
        der[ offset++ ] = 0x02;
        der[ offset++ ] = (byte) rLen;

        if ( rNeedsPad )
            der[ offset++ ] = 0x00;

        r.CopyTo( der.AsSpan( offset ) );
        offset += r.Length;

        // INTEGER s
        der[ offset++ ] = 0x02;
        der[ offset++ ] = (byte) sLen;

        if ( sNeedsPad )
            der[ offset++ ] = 0x00;

        s.CopyTo( der.AsSpan( offset ) );

        return der;
    }


    /// <summary>
    /// Converts a DER-encoded ECDSA signature back to fixed-length r||s (IEEE P1363).
    /// </summary>
    public static byte[] ConvertDerToIeeeP1363( byte[] der )
    {
        var offset = 0;

        if ( der[ offset++ ] != 0x30 )
            throw new InvalidOperationException( "Invalid DER signature: expected SEQUENCE tag." );

        _ = ReadDerLength( der, ref offset );

        // Read r
        if ( der[ offset++ ] != 0x02 )
            throw new InvalidOperationException( "Invalid DER signature: expected INTEGER tag for r." );

        var rLen = ReadDerLength( der, ref offset );
        var r = der.AsSpan( offset, rLen );
        offset += rLen;

        // Read s
        if ( der[ offset++ ] != 0x02 )
            throw new InvalidOperationException( "Invalid DER signature: expected INTEGER tag for s." );

        var sLen = ReadDerLength( der, ref offset );
        var s = der.AsSpan( offset, sLen );

        // Strip leading zero padding from signed DER integers.
        if ( r.Length > 1 && r[ 0 ] == 0x00 )
            r = r[ 1.. ];

        if ( s.Length > 1 && s[ 0 ] == 0x00 )
            s = s[ 1.. ];

        // Component size: take the larger of the two, rounded to a standard size.
        var componentSize = Math.Max( r.Length, s.Length );
        componentSize = componentSize switch
        {
            <= 32 => 32,  // P-256 / secp256k1
            <= 48 => 48,  // P-384
            <= 66 => 66,  // P-521
            _ => componentSize
        };

        var ieee = new byte[ componentSize * 2 ];

        // Right-align r and s within their fixed-length slots.
        r.CopyTo( ieee.AsSpan( componentSize - r.Length, r.Length ) );
        s.CopyTo( ieee.AsSpan( componentSize * 2 - s.Length, s.Length ) );

        return ieee;
    }


    /// <summary />
    private static ReadOnlySpan<byte> TrimLeadingZeros( ReadOnlySpan<byte> value )
    {
        var i = 0;

        while ( i < value.Length - 1 && value[ i ] == 0 )
            i++;

        return value[ i.. ];
    }


    /// <summary />
    private static int WriteDerLength( Span<byte> dest, int length )
    {
        if ( length < 0x80 )
        {
            dest[ 0 ] = (byte) length;
            return 1;
        }

        dest[ 0 ] = 0x81;
        dest[ 1 ] = (byte) length;
        return 2;
    }


    /// <summary />
    private static int ReadDerLength( byte[] data, ref int offset )
    {
        var b = data[ offset++ ];

        if ( b < 0x80 )
            return b;

        if ( b == 0x81 )
            return data[ offset++ ];

        if ( b == 0x82 )
        {
            var len = ( data[ offset ] << 8 ) | data[ offset + 1 ];
            offset += 2;
            return len;
        }

        throw new InvalidOperationException( $"Unsupported DER length encoding: 0x{b:X2}" );
    }
}