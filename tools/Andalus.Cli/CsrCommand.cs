using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "csr", Description = "(CSR) Certificate signing requests operations" )]
[Subcommand( typeof( Csrs.CsrCreateCommand ) )]
[Subcommand( typeof( Csrs.CsrViewCommand ) )]
public class CsrCommand
{
    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}