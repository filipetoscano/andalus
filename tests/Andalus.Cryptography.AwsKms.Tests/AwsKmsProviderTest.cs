using Amazon;
using Amazon.KeyManagementService;
using System.Reflection;
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


    /// <summary />
    [Theory]
    [InlineData( (KeyType) 0 )]
    [InlineData( (KeyType) 900 )]
    public void MapKeyTypeThrowsOnInvalid( KeyType keyType )
    {
        KeySpec Invoke( KeyType keyType )
        {
            var method = typeof( AwsKmsCryptoProvider ).GetMethod(
                "MapKeyType",
                BindingFlags.NonPublic | BindingFlags.Static );

            try
            {
                return (KeySpec) method!.Invoke( null, new object[] { keyType } )!;
            }
            catch ( TargetInvocationException ex )
            {
                throw ex.InnerException!;
            }
        }

        Assert.Throws<NotSupportedException>( () => Invoke( keyType ) );
    }


    /// <summary />
    [Theory]
    [InlineData( KeyType.EcdsaP256, "SHA3_256" )]
    [InlineData( KeyType.EcdsaP256, "SHA3_384" )]
    [InlineData( KeyType.EcdsaP256, "SHA3_512" )]
    [InlineData( KeyType.EcdsaP256, "MD5" )]
    [InlineData( KeyType.Rsa2048, "SHA3_256" )]
    [InlineData( KeyType.Rsa2048, "SHA3_384" )]
    [InlineData( KeyType.Rsa2048, "SHA3_512" )]
    [InlineData( KeyType.Rsa2048, "MD5" )]
    public void MapSigningAlgorithmThrowsOnInvalid( KeyType keyType, string name )
    {
        SigningAlgorithmSpec Invoke( KeyType keyType, HashAlgorithmName hashAlgorithm )
        {
            var method = typeof( AwsKmsCryptoProvider ).GetMethod(
                "MapSigningAlgorithm",
                BindingFlags.NonPublic | BindingFlags.Static );

            try
            {
                return (SigningAlgorithmSpec) method!.Invoke( null, new object[] { keyType, hashAlgorithm } )!;
            }
            catch ( TargetInvocationException ex )
            {
                throw ex.InnerException!;
            }
        }

        var han = new HashAlgorithmName( name );
        Assert.Throws<NotSupportedException>( () => Invoke( keyType, han ) );
    }
}