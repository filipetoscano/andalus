using System.Security.Cryptography;

namespace Andalus.Cryptography.Tests;

/// <summary />
public class FileCryptoProviderTest
{
    /// <summary />
    [Fact]
    public async Task Roundtrip()
    {
        var p = new FileCryptoProvider( new FileCryptoProviderOptions()
        {
            RootDirectory = Path.Combine( Environment.CurrentDirectory, "tests" ),
        } );

        var key = await p.CreateKeyPairAsync( new 
            
            KeyCreationOptions()
        {
            KeyName = Guid.NewGuid().ToString(),
            KeyType = KeyType.EcdsaP256,
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
    }
}