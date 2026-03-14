using McMaster.Extensions.CommandLineUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using System.ComponentModel.DataAnnotations;

namespace Andalus.Cli.Csrs;

/// <summary />
[Command( "view", Description = "Views a (CSR) certificate signing request" )]
public class CsrViewCommand
{
    /// <summary />
    public CsrViewCommand()
    {
    }


    /// <summary />
    [Argument( 0, Description = "Data JSON" )]
    [Required]
    [FileExists]
    public string? CsrPath { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var b64 = await File.ReadAllTextAsync( this.CsrPath! );
        var bytes = Convert.FromBase64String( b64 );

        var csr = new Pkcs10CertificationRequest( bytes );

        if ( csr.Verify() == false )
        {
            Console.WriteLine( "fail: verify failed" );
            return 1;
        }

        var req = csr.GetCertificationRequestInfo();


        /*
         * 
         */
        var publicKey = Convert.ToBase64String( req.SubjectPublicKeyInfo.GetDerEncoded() );
        Console.WriteLine( publicKey );


        /*
         * 
         */
        var sub = req.Subject;

        foreach ( var oid in sub.GetOidList() )
        {
            var key = ToKey( oid );
            var val = sub.GetValueList( oid ).First();

            Console.WriteLine( "{0}={1}", key, val );
        }

        return 0;
    }


    /// <summary />
    private static string ToKey( DerObjectIdentifier oid )
    {
        return oid.Id switch
        {
            "2.5.4.3" => "CN",
            "2.5.4.5" => "SN",
            "2.5.4.6" => "C",
            "2.5.4.7" => "L",
            "2.5.4.10" => "O",
            "2.5.4.11" => "OU",
            "2.5.4.15" => "BC",
            "2.5.4.97" => "OI",

            _ => oid.Id,
        };
    }
}