using Andalus.Cryptography;
using Andalus.Cryptography.Xml;
using McMaster.Extensions.CommandLineUtils;
using Spectre.Console;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Xml;

namespace Andalus.Cli.Xmls;

/// <summary />
[Command( "verify", Description = "" )]
public class XmlVerifyCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public XmlVerifyCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "" )]
    [Required]
    [FileExists]
    public string? InputPath { get; set; }

    /// <summary />
    [Option( "-c|--certificate", CommandOptionType.SingleValue, Description = "" )]
    [FileExists]
    public string? CertificatePath { get; set; }

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
        X509Certificate2? x509 = null;

        if ( this.CertificatePath != null )
            x509 = X509CertificateLoader.LoadCertificateFromFile( this.CertificatePath! );


        /*
         * 
         */
        var result = XmlDigSig.Verify( doc, x509 );

        if ( this.InJson == true )
        {
            var json = JsonSerializer.Serialize( result, new JsonSerializerOptions()
            {
                WriteIndented = true,
            } );

            Console.WriteLine( json );
            return result.IsValid == true ? 0 : 1;
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

            foreach ( var row in result.Signatures )
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
        var isOk = result.IsValid;

        if ( isOk == false )
        {
            AnsiConsole.MarkupLine( "[red]nok[/]: signature is invalid" );
            return 1;
        }

        AnsiConsole.MarkupLine( "[green]ok[/]: signature is valid" );
        return 0;
    }
}