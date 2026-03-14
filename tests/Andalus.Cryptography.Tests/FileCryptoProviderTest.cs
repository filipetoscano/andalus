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

        var key = await p.CreateKeyPairAsync( new

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

        var sr = await p.SignHashAsync( key.KeyId, digest, HashAlgorithmName.SHA256 );

        var sig = sr.ConvertSignature( KeySignatureFormat.Der );


        /*
         * 
         */
        var ok = await p.VerifyHashAsync( key.KeyId, digest, sig, HashAlgorithmName.SHA256 );

        Assert.True( ok );


        /*
         * 
         */
        await p.RemoveKeyPairAsync( key.KeyId );
    }
}