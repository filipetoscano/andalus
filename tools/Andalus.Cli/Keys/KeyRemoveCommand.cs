using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "remove" )]
public class KeyRemoveCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeyRemoveCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Key identifier" )]
    [Required]
    public string? KeyId { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        await _crypto.RemoveKeyPairAsync( this.KeyId! );

        return 0;
    }
}
