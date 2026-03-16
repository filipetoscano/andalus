using Andalus.Cryptography;
using Andalus.Cryptography.Xml;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
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
    public int OnExecute()
    {
        var doc = new XmlDocument();
        doc.PreserveWhitespace = true;
        doc.Load( this.InputPath! );


        /*
         * 
         */
        bool isOk;

        if ( this.CertificatePath != null )
        {
            var x509 = X509CertificateLoader.LoadCertificateFromFile( this.CertificatePath! );

            isOk = XmlDigSig.VerifyAll( doc, x509 );
        }
        else
        {
            isOk = XmlDigSig.VerifyAll( doc );
        }


        /*
         * 
         */
        if ( isOk == false )
        {
            Console.WriteLine( "not ok" );
            return 1;
        }

        Console.WriteLine( "ok" );
        return 0;
    }
}