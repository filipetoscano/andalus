using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "remove", Description = "" )]
public class KeyRemoveCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeyRemoveCommand( ICryptoProvider cp )
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
        await _crypto.RemoveKeyPairAsync( this.KeyReference! );

        return 0;
    }
}
