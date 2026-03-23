using Andalus.Cryptography;
using Andalus.Cryptography.Xml;
using Andalus.Xml.Ubl;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Andalus.Cli.Ubls;

/// <summary />
[Command( "sign", Description = "Sign a UBL XML file" )]
public class UblSignCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public UblSignCommand( ICryptoProvider cp )
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
    [Option( "-r|--role", CommandOptionType.SingleValue, Description = "" )]
    public string? Role { get; set; }

    /// <summary />
    [Option( "-i|--id", CommandOptionType.SingleValue, Description = "" )]
    public string? PartyId { get; set; }

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
        var placement = new UblExtensionPlacement(
            this.Role ?? "Issuer",
            this.PartyId
        );


        /*
         * 
         */
        var signed = XmlDigSig.Sign( SignatureType.Enveloped, doc, _crypto, this.KeyReference!, HashAlgorithmName.SHA256, new XmlDigSigOptions()
        {
            Profile = SignatureProfile.Xades132,
            Canonicalization = XmlCanonicalization.XmlDsigC14N11Transform,
            XadesCanonicalization = null,
            AddKeyInfo = KeyInfoPart.Certificate,
            Certificate = x509,
            EnvelopedSignaturePlacement = placement,
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