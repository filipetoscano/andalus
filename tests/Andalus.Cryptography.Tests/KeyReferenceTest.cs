namespace Andalus.Cryptography.Tests;

/// <summary />
public class KeyReferenceTest
{
    /// <summary />
    [Theory]
    [InlineData( "test", KeyType.Rsa3072, "test#Rsa3072" )]
    [InlineData( "one#two", KeyType.EcdsaSecp256k1, "one#two#EcdsaSecp256k1" )]
    [InlineData( "https://vault/key", KeyType.EcdsaP256, "https://vault/key#EcdsaP256" )]
    public void OpImplicitString( string id, KeyType type, string expected )
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
    public void OpImplicitKeyRef( string value, string expectedId, KeyType expectedType )
    {
        KeyReference actual = value;

        Assert.Equal( expectedId, actual.KeyId );
        Assert.Equal( expectedType, actual.KeyType );
    }


    /// <summary />
    [Theory]
    [InlineData( "string" )]
    public void OpImplicitKeyRef_MissingHash( string value )
    {
        var ex = Assert.Throws<FormatException>( () =>
        {
            KeyReference actual = value;

            Assert.Fail();
        } );
    }


    /// <summary />
    [Theory]
    [InlineData( "string#InvalidEnum" )]
    public void OpImplicitKeyRef_InvalidKeyType( string value )
    {
        var ex = Assert.Throws<ArgumentException>( () =>
        {
            KeyReference actual = value;

            Assert.Fail();
        } );
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
}