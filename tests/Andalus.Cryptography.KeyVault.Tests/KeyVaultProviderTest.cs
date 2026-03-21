using System.Security.Cryptography;

namespace Andalus.Cryptography.KeyVault.Tests;

/// <summary />
public class KeyVaultProviderTest : IClassFixture<Fixture>
{
    private readonly Fixture _f;


    /// <summary />
    public KeyVaultProviderTest( Fixture fixture )
    {
        _f = fixture;
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1, "SHA256" )]
    [InlineData( KeyType.EcdsaP256, "SHA256" )]
    [InlineData( KeyType.EcdsaP384, "SHA384" )]
    [InlineData( KeyType.EcdsaP521, "SHA512" )]
    [InlineData( KeyType.Rsa2048, "SHA256" )]
    [InlineData( KeyType.Rsa3072, "SHA256" )]
    [InlineData( KeyType.Rsa4096, "SHA256" )]
    public async Task Roundtrip( KeyType keyType, string hash )
    {
        Assert.SkipWhen( !TestConfig.Enabled, "Key Vault tests are disabled." );


        /*
         * 
         */
        var han = new HashAlgorithmName( hash );

        var p = new KeyVaultCryptoProvider( new KeyVaultCryptoProviderOptions()
        {
            VaultId = TestConfig.VaultId,
        } );

        var keyRef = await p.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = nameof( Roundtrip ) + "-" + keyType.ToString(),
            KeyType = keyType,
            Exportable = false,
            MomentExpiry = DateTime.MaxValue,
        }, TestContext.Current.CancellationToken );


        /*
         * 
         */
        var size = hash switch
        {
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => throw new InvalidOperationException(),
        };

        var digest = new byte[ size ];
        Random.Shared.NextBytes( digest );

        var sr = await p.SignHashAsync( keyRef, digest, han, TestContext.Current.CancellationToken );
        var sig = sr.Signature;


        /*
         * 
         */
        var publicKey = await p.GetPublicKeyAsync( keyRef, TestContext.Current.CancellationToken );
        Assert.NotNull( publicKey );


        /*
         * 
         */
        var ok = await p.VerifyHashAsync( keyRef, digest, sig, han, TestContext.Current.CancellationToken );
        Assert.True( ok );


        /*
         * 
         */
        var r = await p.RemoveKeyPairAsync( keyRef, TestContext.Current.CancellationToken );

        if ( r.CompleteAsync != null )
            await r.CompleteAsync;
    }
}