using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "get", Description = "Retrieve the public key" )]
public class KeyGetCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeyGetCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Key reference" )]
    [Required]
    public string? KeyReference { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var kp = await _crypto.GetPublicKeyAsync( this.KeyReference! );
        Console.WriteLine( Convert.ToBase64String( kp ) );

        return 0;
    }
}