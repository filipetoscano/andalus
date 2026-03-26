using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "import", Description = "Import a key pair" )]
public class KeyImportCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeyImportCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Name of key" )]
    [Required]
    public string? KeyName { get; set; }

    /// <summary />
    [Option( "-t|--type", CommandOptionType.SingleValue, Description = "Type of key" )]
    public KeyType KeyType { get; set; } = KeyType.EcdsaSecp256k1;

    /// <summary />
    [Option( "-p|--public", CommandOptionType.SingleValue, Description = "Path to public key, in PEM format" )]
    [FileExists]
    public string? PublicKeyPath { get; set; }

    /// <summary />
    [Option( "-q|--private", CommandOptionType.SingleValue, Description = "Path to private key, in PEM format" )]
    [FileExists]
    public string? PrivateKeyPath { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        string p;
        string q;

        if ( this.PublicKeyPath != null )
            p = File.ReadAllText( this.PublicKeyPath );
        else
            p = File.ReadAllText( this.KeyName + ".pub" );

        if ( this.PrivateKeyPath != null )
            q = File.ReadAllText( this.PrivateKeyPath );
        else
            q = File.ReadAllText( this.KeyName + ".key" );


        /*
         * 
         */
        var kp = await _crypto.ImportKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = this.KeyName!,
            KeyType = this.KeyType,
            Exportable = false,
            HardwareProtected = true,
        }, new KeyPair()
        {
            KeyType = this.KeyType,
            PublicPem = p,
            PrivatePem = q,
        } );

        Console.WriteLine( kp );

        return 0;
    }
}