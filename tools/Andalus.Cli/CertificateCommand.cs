using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "cert", Description = "X509 certificate operations" )]
[Subcommand( typeof( Certificates.CertificateViewCommand ) )]
public class CertificateCommand
{
    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}