namespace Andalus.Cryptography;

/// <summary>
/// Represents a key.
/// </summary>
/// <remarks>
/// For (remote) HSM, the private material never leaves the HSM boundary:
/// only the identifier and public key are available locally.
/// </remarks>
public sealed class KeyReference
{
    /// <summary>
    /// HSM-specific key identifier (e.g. Key Vault key URI, PKCS#11 handle, ARN).
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// The algorithm family this key belongs to.
    /// </summary>
    public required KeyType KeyType { get; init; }


    /// <summary />
    public override string ToString()
    {
        return $"{this.KeyId}#{this.KeyType}";
    }


    /// <summary />
    public static implicit operator string( KeyReference key )
    {
        return $"{key.KeyId}#{key.KeyType}";
    }


    /// <summary />
    public static implicit operator KeyReference( string value )
    {
        var ix = value.LastIndexOf( '#' );

        if ( ix < 0 )
            throw new FormatException( $"Invalid key reference '{value}', expected 'KeyId#KeyType'." );

        return new KeyReference
        {
            KeyId = value[ ..ix ],
            KeyType = Enum.Parse<KeyType>( value[ ( ix + 1 ).. ] ),
        };
    }
}