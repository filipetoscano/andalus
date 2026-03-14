using System.Security.Cryptography;

namespace Andalus.Cryptography.Tests;

/// <summary />
public class FileCryptoProviderTest
{
    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1 )]
    [InlineData( KeyType.EcdsaP256 )]
    [InlineData( KeyType.EcdsaP384 )]
    [InlineData( KeyType.EcdsaP521 )]
    [InlineData( KeyType.RsaSha256 )]
    [InlineData( KeyType.RsaSha384 )]
    [InlineData( KeyType.RsaSha512 )]
    public async Task Roundtrip( KeyType keyType )
    {
        var p = new FileCryptoProvider( new FileCryptoProviderOptions()
        {
            RootDirectory = Path.Combine( Environment.CurrentDirectory, "tests" ),
        } );

        var keyRef = await p.CreateKeyPairAsync( new

            KeyCreationOptions()
        {
            KeyName = nameof( Roundtrip) + "-" + keyType.ToString(),
            KeyType = keyType,
            Exportable = false,
            MomentExpiry = DateTime.MaxValue,
        } );


        /*
         * 
         */
        var digest = new byte[ 32 ];
        Random.Shared.NextBytes( digest );

        var sr = await p.SignHashAsync( keyRef, digest );
        var sig = sr.Signature;


        /*
         * 
         */
        var ok = await p.VerifyHashAsync( keyRef, digest, sig );
        Assert.True( ok );


        /*
         * 
         */
        await p.RemoveKeyPairAsync( keyRef );
    }
}