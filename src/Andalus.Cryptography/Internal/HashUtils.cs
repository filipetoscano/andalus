using System.Security.Cryptography;

namespace Andalus.Cryptography.Internal;

/// <summary />
internal class HashUtils
{
    /// <summary />
    internal static byte[] HashData( HashAlgorithmName algorithm, byte[] data )
    {
        return algorithm.Name switch
        {
            "SHA256" => SHA256.HashData( data ),
            "SHA384" => SHA384.HashData( data ),
            "SHA512" => SHA512.HashData( data ),
            _ => throw new NotSupportedException( $"Hash '{algorithm.Name}' not supported." )
        };
    }
}