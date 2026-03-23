using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "ubl", Description = "UBL XML operations" )]
[Subcommand( typeof( Ubls.UblSignCommand ) )]
public class UblCommand
{
    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}