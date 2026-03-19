namespace Andalus.Cryptography.Tests;

/// <summary />
public class KeyPairTest
{
    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1 )]
    [InlineData( KeyType.EcdsaP256 )]
    [InlineData( KeyType.EcdsaP384 )]
    [InlineData( KeyType.EcdsaP521 )]
    [InlineData( KeyType.Rsa2048 )]
    [InlineData( KeyType.Rsa3072 )]
    [InlineData( KeyType.Rsa4096 )]
    public void Create( KeyType keyType )
    {
        var kp = KeyPair.CreateKey( keyType );

        var pub = kp.GetPublicKeyBytes();
        var prv = kp.GetPublicKeyBytes();

        Assert.NotNull( kp );
        Assert.NotEmpty( kp.PublicPem );
        Assert.NotEmpty( kp.PrivatePem );
        Assert.NotNull( pub );
        Assert.NotNull( prv );
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1 )]
    [InlineData( KeyType.EcdsaP256 )]
    [InlineData( KeyType.EcdsaP384 )]
    [InlineData( KeyType.EcdsaP521 )]
    [InlineData( KeyType.Rsa2048 )]
    [InlineData( KeyType.Rsa3072 )]
    [InlineData( KeyType.Rsa4096 )]
    public void CreateFromBytes( KeyType keyType )
    {
        var expected = KeyPair.CreateKey( keyType );
        var actual = KeyPair.FromDerBytes( keyType, expected.GetPublicKeyBytes(), expected.GetPrivateKeyBytes() );

        Assert.Equal( expected.PublicPem, actual.PublicPem );
        Assert.Equal( expected.PrivatePem, actual.PrivatePem );

        var pub = actual.GetPublicKeyBytes();
        var prv = actual.GetPublicKeyBytes();
    }
}