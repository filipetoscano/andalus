using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "verify", Description = "" )]
public class KeyVerifyCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeyVerifyCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Key reference" )]
    [Required]
    public string? KeyReference { get; set; }

    /// <summary />
    [Argument( 1, Description = "Hash" )]
    [Required]
    public string? Hash { get; set; }

    /// <summary />
    [Argument( 2, Description = "Signature" )]
    [Required]
    public string? Signature { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var hash = Convert.FromBase64String( this.Hash! );
        var sign = Convert.FromBase64String( this.Signature! );

        var isValid = await _crypto.VerifyHashAsync( this.KeyReference!, hash, sign, HashAlgorithmName.SHA256 );

        if ( isValid == false )
        {
            Console.WriteLine( "not ok" );
            return 1;
        }

        Console.WriteLine( "ok" );
        return 0;
    }
}