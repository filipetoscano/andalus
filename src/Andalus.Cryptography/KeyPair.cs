using System.Security.Cryptography;
using System.Text;

namespace Andalus.Cryptography;

/// <summary>
/// Compact representation of a keypair.
/// </summary>
public class KeyPair
{
    /// <summary>
    /// Type of key.
    /// </summary>
    public required KeyType KeyType { get; set; }

    /// <summary>
    /// Public material, in PEM format.
    /// </summary>
    public required string PublicPem { get; init; }

    /// <summary>
    /// Private material, in PEM format.
    /// </summary>
    public required string PrivatePem { get; init; }


    /// <summary>
    /// Get the raw bytes of the public key.
    /// </summary>
    public byte[] GetPublicKeyBytes()
    {
        return Convert.FromBase64String( PublicPem[ PemEncoding.Find( PublicPem ).Base64Data ] );
    }


    /// <summary>
    /// Get the raw bytes of the private key.
    /// </summary>
    public byte[] GetPrivateKeyBytes()
    {
        return Convert.FromBase64String( PrivatePem[ PemEncoding.Find( PrivatePem ).Base64Data ] );
    }



    /// <summary />
    public static KeyPair CreateKey( KeyType keyType )
    {
        var pem = keyType switch
        {
            KeyType.EcdsaSecp256k1 => CreateEcKey( ECCurve.CreateFromValue( "1.3.132.0.10" ) ),
            KeyType.EcdsaP256 => CreateEcKey( ECCurve.NamedCurves.nistP256 ),
            KeyType.EcdsaP384 => CreateEcKey( ECCurve.NamedCurves.nistP384 ),
            KeyType.EcdsaP521 => CreateEcKey( ECCurve.NamedCurves.nistP521 ),

            KeyType.Rsa2048 => CreateRsaKey( 2048 ),
            KeyType.Rsa3072 => CreateRsaKey( 3072 ),
            KeyType.Rsa4096 => CreateRsaKey( 4096 ),
            _ => throw new NotSupportedException()
        };

        return new KeyPair()
        {
            KeyType = keyType,
            PrivatePem = pem.Private,
            PublicPem = pem.Public,
        };
    }


    /// <summary />
    public static KeyPair FromDerBytes( KeyType keyType, byte[] publicKey, byte[] privateKey )
    {
        var family = keyType.Family();
        var type = family switch
        {
            KeyFamily.Ecdsa => "EC",
            KeyFamily.Rsa => "RSA",
            _ => throw new NotSupportedException(),
        };

        var p = ToPem( publicKey, "PUBLIC KEY" );
        var q = ToPem( privateKey, $"{type} PRIVATE KEY" );

        return new KeyPair()
        {
            KeyType = keyType,
            PublicPem = p,
            PrivatePem = q,
        };
    }


    /// <summary />
    private static string ToPem( byte[] value, string label )
    {
        var base64 = Convert.ToBase64String( value );

        var sb = new StringBuilder();
        sb.Append( $"-----BEGIN {label}-----\n" );

        for ( int i = 0; i < base64.Length; i += 64 )
        {
            sb.Append( base64.Substring( i, Math.Min( 64, base64.Length - i ) ) );
            sb.Append( "\n" );
        }

        sb.Append( $"-----END {label}-----" );

        return sb.ToString();
    }


    /// <summary />
    private static (string Public, string Private) CreateEcKey( ECCurve curve )
    {
        using var ecdsa = ECDsa.Create( curve );

        var privatePem = ecdsa.ExportECPrivateKeyPem();
        var publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();

        return (publicPem, privatePem);
    }


    /// <summary />
    private static (string Public, string Private) CreateRsaKey( int keySizeBits )
    {
        using var rsa = RSA.Create( keySizeBits );

        var privatePem = rsa.ExportRSAPrivateKeyPem();
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();

        return (publicPem, privatePem);
    }
}