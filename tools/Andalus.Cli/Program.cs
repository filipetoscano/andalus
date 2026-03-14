using Andalus.Cryptography;
using Andalus.Cryptography.KeyVault;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;

namespace Andalus.Cli;

/// <summary />
[Command( "andalus", Description = "" )]
[Subcommand( typeof( KeyCommand ))]
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

        svc.AddTransient<ICryptoProvider>( x =>
        {
            var prov = Environment.GetEnvironmentVariable( "ANDALUS_HSM_PROVIDER" )?.ToLowerInvariant() ?? "keyvault";

            if ( prov == "keyvault" )
            {
                var kvid = Environment.GetEnvironmentVariable( "ANDALUS_HSM_KEYVAULT" ) ?? throw new ApplicationException( "Missing ANDALUS_HSM_KEYVAULT" );

                return new KeyVaultCryptoProvider( new KeyVaultCryptoProviderOptions()
                {
                    VaultId = new Uri( kvid ),
                } );
            }
            else
            {
                throw new NotSupportedException();
            }
        } );


        var sp = svc.BuildServiceProvider();


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