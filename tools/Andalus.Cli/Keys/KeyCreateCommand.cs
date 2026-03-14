using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "create", Description = "Create a key pair" )]
public class KeyCreateCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeyCreateCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Name" )]
    [Required]
    public string? KeyName { get; set; }


    /// <summary />
    [Option( "-t|--type", CommandOptionType.SingleValue, Description = "" )]
    public KeyType KeyType { get; set; } = KeyType.EcdsaSecp256k1;


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var kp = await _crypto.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = this.KeyName!,
            KeyType = this.KeyType,
            Exportable = false,
        } );

        Console.WriteLine( kp );

        return 0;
    }
}