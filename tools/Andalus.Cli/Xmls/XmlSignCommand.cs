using Andalus.Cryptography;
using Andalus.Cryptography.Xml;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Andalus.Cli.Xmls;

/// <summary />
[Command( "sign", Description = "Sign an XML file" )]
public class XmlSignCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public XmlSignCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    [Argument( 0, Description = "Key reference" )]
    [Required]
    public string? KeyReference { get; set; }

    /// <summary />
    [Argument( 1, Description = "" )]
    [Required]
    [FileExists]
    public string? CertificatePath { get; set; }

    /// <summary />
    [Argument( 2, Description = "" )]
    [Required]
    [FileExists]
    public string? InputPath { get; set; }

    /// <summary />
    [Option( "-t|--type", CommandOptionType.SingleValue, Description = "Output filename" )]
    public SignatureType SignatureType { get; set; } = SignatureType.Enveloping;

    /// <summary />
    [Option( "-o|--output", CommandOptionType.SingleValue, Description = "Output filename" )]
    public string? OutputPath { get; set; }


    /// <summary />
    public int OnExecute()
    {
        var doc = new XmlDocument();
        doc.PreserveWhitespace = true;
        doc.Load( this.InputPath! );

        var x509 = X509CertificateLoader.LoadCertificateFromFile( this.CertificatePath! );


        /*
         * 
         */
        var signed = XmlDigSig.Sign( this.SignatureType, doc, _crypto, this.KeyReference!, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            AddKeyInfo = KeyInfoPart.Certificate | KeyInfoPart.IssuerSerial,
            Certificate = x509,
        } );


        /*
         * 
         */
        if ( this.OutputPath != null )
        {
            using var writer = XmlWriter.Create( this.OutputPath, new XmlWriterSettings
            {
                Indent = false,
                OmitXmlDeclaration = false,
            } );

            signed.WriteTo( writer );
        }
        else
        {
            Console.WriteLine( signed.OuterXml );
        }

        return 0;
    }
}