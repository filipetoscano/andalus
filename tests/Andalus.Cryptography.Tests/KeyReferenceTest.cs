namespace Andalus.Cryptography.Tests;

/// <summary />
public class KeyReferenceTest
{
    /// <summary />
    [Theory]
    [InlineData( "test", KeyType.Rsa3072, "test#Rsa3072" )]
    [InlineData( "one#two", KeyType.EcdsaSecp256k1, "one#two#EcdsaSecp256k1" )]
    [InlineData( "https://vault/key", KeyType.EcdsaP256, "https://vault/key#EcdsaP256" )]
    public void OpImplicitString_Ok( string id, KeyType type, string expected )
    {
        var kr = new KeyReference( )
        {
            KeyId = id,
            KeyType = type,
        };

        string actual = kr;

        Assert.Equal( expected, actual );
    }


    /// <summary />
    [Theory]
    [InlineData( "test#Rsa3072", "test", KeyType.Rsa3072 )]
    [InlineData( "one#two#EcdsaSecp256k1", "one#two", KeyType.EcdsaSecp256k1 )]
    [InlineData( "https://vault/key#EcdsaP256", "https://vault/key", KeyType.EcdsaP256 )]
    public void OpImplicitKeyRef_Ok( string value, string expectedId, KeyType expectedType )
    {
        KeyReference actual = value;

        Assert.Equal( expectedId, actual.KeyId );
        Assert.Equal( expectedType, actual.KeyType );
    }


    /// <summary />
    [Theory]
    [InlineData( "test#Rsa3072", "test", KeyType.Rsa3072 )]
    [InlineData( "one#two#EcdsaSecp256k1", "one#two", KeyType.EcdsaSecp256k1 )]
    [InlineData( "https://vault/key#EcdsaP256", "https://vault/key", KeyType.EcdsaP256 )]
    public void Parse( string value, string expectedId, KeyType expectedType )
    {
        KeyReference actual = KeyReference.Parse( value );

        Assert.Equal( expectedId, actual.KeyId );
        Assert.Equal( expectedType, actual.KeyType );
    }


    /// <summary />
    [Theory]
    [InlineData( "string" )]
    [InlineData( "#Rsa2048" )]
    public void Parse_MissingHash( string value )
    {
        var ex = Assert.Throws<FormatException>( () =>
        {
            KeyReference actual = KeyReference.Parse( value );

            Assert.Fail();
        } );
    }


    /// <summary />
    [Theory]
    [InlineData( "string#InvalidEnum" )]
    [InlineData( "string#RSA2048" )]
    public void Parse_InvalidKeyType( string value )
    {
        var ex = Assert.Throws<ArgumentException>( () =>
        {
            KeyReference actual = KeyReference.Parse( value );

            Assert.Fail();
        } );
    }


    /// <summary />
    [Theory]
    [InlineData( "test#Rsa3072", "test", KeyType.Rsa3072 )]
    [InlineData( "one#two#EcdsaSecp256k1", "one#two", KeyType.EcdsaSecp256k1 )]
    [InlineData( "https://vault/key#EcdsaP256", "https://vault/key", KeyType.EcdsaP256 )]
    public void TryParse_Ok( string value, string expectedId, KeyType expectedType )
    {
        var b = KeyReference.TryParse( value, out var actual );

        Assert.True( b );
        Assert.NotNull( actual );
        Assert.Equal( expectedId, actual.KeyId );
        Assert.Equal( expectedType, actual.KeyType );
    }


    /// <summary />
    [Theory]
    [InlineData( "string" )]
    [InlineData( "#Rsa2048" )]
    [InlineData( "string#InvalidEnum" )]
    [InlineData( "string#RSA2048" )]
    public void TryParse_NotOk( string value )
    {
        var b = KeyReference.TryParse( value, out var actual );

        Assert.False( b );
        Assert.Null( actual );
    }


    /// <summary />
    [Theory]
    [InlineData( "test", KeyType.Rsa3072, "test#Rsa3072" )]
    [InlineData( "one#two", KeyType.EcdsaSecp256k1, "one#two#EcdsaSecp256k1" )]
    [InlineData( "https://vault/key", KeyType.EcdsaP256, "https://vault/key#EcdsaP256" )]
    public void OpToString( string id, KeyType type, string expected )
    {
        var kr = new KeyReference()
        {
            KeyId = id,
            KeyType = type,
        };

        string actual = kr.ToString();

        Assert.Equal( expected, actual );
    }


    /// <summary />
    [Theory]
    [InlineData( "test#Rsa3072" )]
    [InlineData( "one#two#EcdsaSecp256k1" )]
    [InlineData( "https://vault/key#EcdsaP256" )]
    public void Equals_Ok( string value )
    {
        var k1 = KeyReference.Parse( value );
        var k2 = KeyReference.Parse( value );

        Assert.True( k1.Equals( k2 ) );
    }


    /// <summary />
    [Theory]
    [InlineData( "test#Rsa3072" )]
    [InlineData( "one#two#EcdsaSecp256k1" )]
    [InlineData( "https://vault/key#EcdsaP256" )]
    public void OpEquals_Ok( string value )
    {
        var k1 = KeyReference.Parse( value );
        var k2 = KeyReference.Parse( value );

        Assert.True( k1 == k2 );
        Assert.False( k1 != k2 );
    }


    /// <summary />
    [Theory]
    [InlineData( "test#Rsa3072" )]
    [InlineData( "one#two#EcdsaSecp256k1" )]
    [InlineData( "https://vault/key#EcdsaP256" )]
    public void GetHashCode_Ok( string value )
    {
        var k1 = KeyReference.Parse( value );
        var k2 = KeyReference.Parse( value );

        Assert.Equal( k1.GetHashCode(), k2.GetHashCode() );
    }
}