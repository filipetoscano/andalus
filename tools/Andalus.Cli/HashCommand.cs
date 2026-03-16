using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace Andalus.Cli;

/// <summary />
[Command( "hash", Description = "Hash a file" )]
public class HashCommand
{
    /// <summary />
    public HashCommand()
    {
    }


    /// <summary />
    [Argument( 0, Description = "" )]
    [Required]
    [FileExists]
    public string? Filepath { get; set; }


    /// <summary />
    [Option( "-n|--hash-name", CommandOptionType.SingleValue, Description = "" )]
    public string HashAlgorithmName { get; set; } = "SHA256";


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var bytes = await File.ReadAllBytesAsync( this.Filepath! );

        var hash = this.HashAlgorithmName.ToUpperInvariant() switch
        {
            "SHA256" => SHA256.HashData( bytes ),
            "SHA384" => SHA384.HashData( bytes ),
            "SHA512" => SHA512.HashData( bytes ),
            "SHA1" => SHA1.HashData( bytes ),
            "MD5" => MD5.HashData( bytes ),

            _ => throw new ArgumentException( $"Unknown hash algorithm '{this.HashAlgorithmName}'." ),
        };

        Console.WriteLine( Convert.ToBase64String( hash ) );

        return 0;
    }
}