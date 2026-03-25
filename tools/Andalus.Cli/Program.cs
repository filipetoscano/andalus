using Amazon;
using Amazon.KeyManagementService;
using Andalus.Cryptography;
using Andalus.Cryptography.AwsKms;
using Andalus.Cryptography.BouncyHsm;
using Andalus.Cryptography.KeyVault;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;

namespace Andalus.Cli;

/// <summary />
[Command( "andalus", Description = "" )]
[Subcommand( typeof( CertificateCommand ) )]
[Subcommand( typeof( CsrCommand ) )]
[Subcommand( typeof( HashCommand ) )]
[Subcommand( typeof( KeyCommand ) )]
[Subcommand( typeof( UblCommand ) )]
[Subcommand( typeof( XmlCommand ) )]
[VersionOptionFromMember( MemberName = nameof( GetVersion ) )]
public class Program
{
    /// <summary />
    public static int Main( string[] args )
    {
        /*
         * 
         */
        var app = new CommandLineApplication<Program>();

        var svc = new ServiceCollection();
        svc.AddOptions();

        svc.AddSingleton<ICryptoProvider>( x =>
        {
            var prov = Environment.GetEnvironmentVariable( "ANDALUS_CRYPTO_PROVIDER" )?.ToLowerInvariant() ?? "file";

            if ( prov == "file" )
            {
                var ks = new FilesystemKeyStore( new FilesystemKeyStoreOptions()
                {
                    RootDirectory = Path.Combine( Environment.CurrentDirectory, "keyvault" ),
                } );

                return new KeyStoreCryptoProvider( ks );
            }
            else if ( prov == "bouncy" )
            {
                var slotId = int.Parse( Environment.GetEnvironmentVariable( "ANDALUS_BOUNCY_SLOTID" ) ?? "1" );
                var userPin = Environment.GetEnvironmentVariable( "ANDALUS_BOUNCY_USERPIN" ) ?? "";

                return new BouncyHsmCryptoProvider( new BouncyHsmCryptoProviderOptions()
                {
                    SlotId = slotId,
                    UserPin = userPin,
                } );
            }
            else if ( prov == "keyvault" )
            {
                var kvid = Environment.GetEnvironmentVariable( "ANDALUS_KEYVAULT" ) ?? throw new ApplicationException( "Missing ANDALUS_KEYVAULT" );

                return new KeyVaultCryptoProvider( new KeyVaultCryptoProviderOptions()
                {
                    VaultId = new Uri( kvid ),
                } );
            }
            else if ( prov == "awskms" )
            {
                var profileName = Environment.GetEnvironmentVariable( "ANDALUS_AWS_PROFILE" ) ?? throw new ApplicationException( "Missing ANDALUS_AWS_PROFILE" );

                var chain = new Amazon.Runtime.CredentialManagement.CredentialProfileStoreChain();
                chain.TryGetAWSCredentials( profileName, out var credentials );

                var client = new AmazonKeyManagementServiceClient( credentials );

                return new AwsKmsCryptoProvider( new AwsKmsCryptoProviderOptions()
                {
                    KmsClient = client,
                } );
            }
            else
            {
                throw new NotSupportedException();
            }
        } );


        using var sp = svc.BuildServiceProvider();


        /*
         * 
         */
        try
        {
            app.Conventions
                .UseDefaultConventions()
                .UseConstructorInjection( sp );
        }
        catch ( Exception ex )
        {
            Console.WriteLine( "ftl: unhandled exception during setup" );
            Console.WriteLine( ex.ToString() );

            return 2;
        }


        /*
         * 
         */
        try
        {
            return app.Execute( args );
        }
        catch ( UnrecognizedCommandParsingException ex )
        {
            Console.WriteLine( "err: " + ex.Message );

            return 2;
        }
        catch ( CommandParsingException ex )
        {
            Console.WriteLine( "err: " + ex.Message );

            return 2;
        }
        catch ( Exception ex )
        {
            Console.WriteLine( "ftl: unhandled exception during execution" );
            Console.WriteLine( ex.ToString() );

            return 2;
        }
    }


    /// <summary />
    private static string GetVersion()
    {
        return typeof( Program ).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
    }


    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}