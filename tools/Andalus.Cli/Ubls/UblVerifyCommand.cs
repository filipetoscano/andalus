using Andalus.Cryptography;
using Andalus.Cryptography.Xml;
using McMaster.Extensions.CommandLineUtils;
using Spectre.Console;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Xml;

namespace Andalus.Cli.Ubls;

/// <summary />
[Command( "verify", Description = "" )]
public class UblVerifyCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public UblVerifyCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "" )]
    [Required]
    [FileExists]
    public string? InputPath { get; set; }

    /// <summary />
    [Option( "-d|--detailed", CommandOptionType.NoValue, Description = "" )]
    public bool Detailed { get; set; }

    /// <summary />
    [Option( "--json", CommandOptionType.NoValue, Description = "" )]
    public bool InJson { get; set; }


    /// <summary />
    public int OnExecute()
    {
        var doc = new XmlDocument();
        doc.PreserveWhitespace = true;
        doc.Load( this.InputPath! );

        if ( XmlDigSig.IsSigned( doc ) == false )
        {
            AnsiConsole.MarkupLine( "[red]nok[/]: document is not signed" );
            return 1;
        }


        /*
         * 
         */
        var result = XmlDigSig.Verify( doc );

        if ( this.InJson == true )
        {
            var json = JsonSerializer.Serialize( result, new JsonSerializerOptions()
            {
                WriteIndented = true,
            } );

            Console.WriteLine( json );
            return ( result.All( x => x.IsValid == true ) == true ) ? 1 : 0;
        }


        /*
         * 
         */
        if ( this.Detailed == true )
        {
            var table = new Table();
            table.Border = TableBorder.SimpleHeavy;
            table.AddColumn( "V?" );
            table.AddColumn( "Id" );
            table.AddColumn( "Ref" );
            table.AddColumn( "Digest" );

            foreach ( var row in result )
            {
                table.AddRow(
                    new Markup( row.IsValid ? "[green]ok[/]" : "[red]nok[/]" ),
                    new Markup( row.Id ?? "" ),
                    new Markup( row.RefUri ),
                    new Markup( row.DigestValue )
                );
            }

            AnsiConsole.Write( table );
        }


        /*
         * 
         */
        var isOk = result.All( x => x.IsValid == true );

        if ( isOk == false )
        {
            AnsiConsole.MarkupLine( "[red]nok[/]: signature is invalid" );
            return 1;
        }

        AnsiConsole.MarkupLine( "[green]ok[/]: signature is valid" );
        return 0;
    }
}