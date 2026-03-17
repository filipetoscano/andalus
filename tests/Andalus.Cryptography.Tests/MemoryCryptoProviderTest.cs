using System.Security.Cryptography;

namespace Andalus.Cryptography.Tests;

/// <summary />
public class MemoryCryptoProviderTest
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
    public async Task Roundtrip( KeyType keyType )
    {
        var ks = new MemoryKeyStore();
        var p = new KeyStoreCryptoProvider( ks );

        var keyRef = await p.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = nameof( Roundtrip ) + "-" + keyType.ToString(),
            KeyType = keyType,
            Exportable = false,
            MomentExpiry = DateTime.MaxValue,
        } );


        /*
         * 
         */
        var digest = new byte[ 32 ];
        Random.Shared.NextBytes( digest );

        var sr = await p.SignHashAsync( keyRef, digest, HashAlgorithmName.SHA256 );
        var sig = sr.Signature;


        /*
         * 
         */
        var ok = await p.VerifyHashAsync( keyRef, digest, sig, HashAlgorithmName.SHA256 );
        Assert.True( ok );


        /*
         * 
         */
        await p.RemoveKeyPairAsync( keyRef );
    }
}
