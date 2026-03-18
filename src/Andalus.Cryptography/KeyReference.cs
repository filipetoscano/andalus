namespace Andalus.Cryptography;

/// <summary>
/// Represents a key.
/// </summary>
/// <remarks>
/// For (remote) HSM, the private material never leaves the HSM boundary:
/// only the identifier and public key are available locally.
/// </remarks>
public sealed class KeyReference : IEquatable<KeyReference>
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
        return KeyReference.Parse( value );
    }


    /// <summary />
    public static KeyReference Parse( string value )
    {
        var ix = value.LastIndexOf( '#' );

        if ( ix <= 0 )
            throw new FormatException( $"Invalid key reference '{value}', expected 'KeyId#KeyType'." );

        return new KeyReference
        {
            KeyId = value[ ..ix ],
            KeyType = Enum.Parse<KeyType>( value[ ( ix + 1 ).. ] ),
        };
    }


    /// <summary />
    public static bool TryParse( string value, out KeyReference? result )
    {
        var ix = value.LastIndexOf( '#' );

        if ( ix <= 0 )
        {
            result = null;
            return false;
        }

        if ( Enum.TryParse<KeyType>( value[ ( ix + 1 ).. ], out var keyType ) == false )
        {
            result = null;
            return false;
        }

        result = new KeyReference()
        {
            KeyId = value[ ..ix ],
            KeyType = keyType
        };

        return true;
    }


    /// <inheritdoc />
    public bool Equals( KeyReference? other )
    {
        if ( other is null )
            return false;

        return KeyId == other.KeyId && KeyType == other.KeyType;
    }

    /// <inheritdoc />
    public override bool Equals( object? obj ) => Equals( obj as KeyReference );

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine( KeyId, KeyType );

    /// <summary />
    public static bool operator ==( KeyReference? left, KeyReference? right )
        => ReferenceEquals( left, right ) || ( left is not null && left.Equals( right ) );

    /// <summary />
    public static bool operator !=( KeyReference? left, KeyReference? right )
        => !( left == right );
}