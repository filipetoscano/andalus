using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "key" )]
[Subcommand( typeof( Keys.KeyCreateCommand ) )]
[Subcommand( typeof( Keys.KeyRemoveCommand ) )]
public class KeyCommand
{
    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}