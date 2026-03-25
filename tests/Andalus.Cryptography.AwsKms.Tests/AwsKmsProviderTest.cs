using Amazon;
using Amazon.KeyManagementService;
using System.Security.Cryptography;

namespace Andalus.Cryptography.AwsKms.Tests;

/// <summary />
public class AwsKmsProviderTest : IClassFixture<Fixture>
{
    private readonly Fixture _f;


    /// <summary />
    public AwsKmsProviderTest( Fixture fixture )
    {
        _f = fixture;
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaSecp256k1, "SHA256" )]
    public async Task Roundtrip( KeyType keyType, string hash )
    {
        Assert.SkipWhen( !TestConfig.Enabled, "AWS tests are disabled." );


        /*
         * 
         */
        var chain = new Amazon.Runtime.CredentialManagement.CredentialProfileStoreChain();
        chain.TryGetAWSCredentials( TestConfig.ProfileName, out var credentials );

        var client = new AmazonKeyManagementServiceClient( credentials, RegionEndpoint.EUWest1 );

        var p = new AwsKmsCryptoProvider( new AwsKmsCryptoProviderOptions()
        {
            KmsClient = client,
        } );

        var keyRef = await p.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = nameof( Roundtrip ) + "-" + keyType.ToString() + "-" + Guid.NewGuid().ToString(),
            KeyType = keyType,
            Exportable = false,
            MomentExpiry = DateTime.MaxValue,
        }, TestContext.Current.CancellationToken );


        /*
         * 
         */
        var han = new HashAlgorithmName( hash );
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