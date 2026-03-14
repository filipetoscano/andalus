using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "create", Description = "" )]
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
    public async Task<int> OnExecuteAsync()
    {
        var kp = await _crypto.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = this.KeyName!,
            KeyType = KeyType.EcdsaSecp256k1,
            Exportable = false,
        } );

        Console.WriteLine( kp );

        return 0;
    }
}