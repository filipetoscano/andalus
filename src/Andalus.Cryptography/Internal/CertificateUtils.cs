using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using System.Security.Cryptography;

namespace Andalus.Cryptography.Internal;


/// <summary />
internal class CertificateUtils
{
    /// <summary />
    internal static AlgorithmIdentifier MapSignatureAlgorithm( KeyType keyType, HashAlgorithmName hashAlgorithmName )
    {
        var family = keyType.Family();

        if ( family == KeyFamily.Ecdsa )
        {
            return hashAlgorithmName.Name switch
            {
                "SHA256" => new AlgorithmIdentifier( X9ObjectIdentifiers.ECDsaWithSha256 ),
                "SHA384" => new AlgorithmIdentifier( X9ObjectIdentifiers.ECDsaWithSha384 ),
                "SHA512" => new AlgorithmIdentifier( X9ObjectIdentifiers.ECDsaWithSha512 ),
                _ => throw new NotSupportedException( $"Hash algotihm '{hashAlgorithmName.Name}' is not supported." )
            };
        }
        else
        {
            return hashAlgorithmName.Name switch
            {
                "SHA256" => new AlgorithmIdentifier( PkcsObjectIdentifiers.Sha256WithRsaEncryption, DerNull.Instance ),
                "SHA384" => new AlgorithmIdentifier( PkcsObjectIdentifiers.Sha384WithRsaEncryption, DerNull.Instance ),
                "SHA512" => new AlgorithmIdentifier( PkcsObjectIdentifiers.Sha512WithRsaEncryption, DerNull.Instance ),
                _ => throw new NotSupportedException( $"Hash algotihm '{hashAlgorithmName.Name}' is not supported." )
            };
        }
    }


    /// <summary />
    internal static HashAlgorithmName MapHashAlgorithm( KeyType keyType )
    {
        return keyType switch
        {
            KeyType.EcdsaP256 or KeyType.EcdsaSecp256k1 => HashAlgorithmName.SHA256,
            KeyType.EcdsaP384 => HashAlgorithmName.SHA384,
            KeyType.EcdsaP521 => HashAlgorithmName.SHA512,

            KeyType.Rsa2048 => HashAlgorithmName.SHA256,
            KeyType.Rsa3072 => HashAlgorithmName.SHA384,
            KeyType.Rsa4096 => HashAlgorithmName.SHA512,

            _ => throw new NotSupportedException( $"Key type '{keyType}' is not supported." )
        };
    }
}