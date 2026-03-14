using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "sign", Description = "" )]
public class KeySignCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeySignCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Key identifier" )]
    [Required]
    public string? KeyId { get; set; }

    /// <summary />
    [Argument( 1, Description = "Hash" )]
    [Required]
    public string? Hash { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var hash = Convert.FromBase64String( this.Hash! );
        var sr = await _crypto.SignHashAsync( this.KeyId!, hash, HashAlgorithmName.SHA256 );

        Console.WriteLine( Convert.ToBase64String( sr.ConvertSignature( KeySignatureFormat.Der ) ) );

        return 0;
    }
}