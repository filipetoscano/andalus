using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "csr" )]
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