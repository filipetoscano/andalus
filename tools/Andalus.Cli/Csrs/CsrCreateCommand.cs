using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace Andalus.Cli.Csrs;

/// <summary />
[Command( "create", Description = "Create a (CSR) certificate signing request" )]
public class CsrCreateCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public CsrCreateCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Key reference" )]
    [Required]
    public string? KeyReference { get; set; }


    /// <summary />
    [Argument( 1, Description = "Data JSON" )]
    [Required]
    [FileExists]
    public string? CsrData { get; set; }

    /// <summary />
    [Option( "-o|--output", CommandOptionType.SingleValue, Description = "Output filename" )]
    public string? OutputPath { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var json = File.ReadAllText( this.CsrData! );
        var data = JsonSerializer.Deserialize<CsrData>( json )!;

        var csr = await CsrSigner.CreateAsync( _crypto, this.KeyReference!, data );


        /*
         * 
         */
        var b64 = Convert.ToBase64String( csr.GetDerEncoded() );

        if ( this.OutputPath != null )
            await File.WriteAllTextAsync( this.OutputPath, b64 );
        else
            Console.WriteLine( b64 );

        return 0;
    }
}