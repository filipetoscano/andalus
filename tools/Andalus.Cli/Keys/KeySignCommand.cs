using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace Andalus.Cli.Keys;

/// <summary />
[Command( "sign", Description = "Signs a hash" )]
public class KeySignCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public KeySignCommand( ICryptoProvider cp )
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
    [Option( "-n|--hash-algo", CommandOptionType.SingleValue, Description = "Hash algorithm name" )]
    public string HashAlgorithmName { get; set; } = "SHA256";


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var han = new HashAlgorithmName( this.HashAlgorithmName! );

        var hash = Convert.FromBase64String( this.Hash! );
        var sr = await _crypto.SignHashAsync( this.KeyReference!, hash, han );

        Console.WriteLine( Convert.ToBase64String( sr.Signature ) );

        return 0;
    }
}