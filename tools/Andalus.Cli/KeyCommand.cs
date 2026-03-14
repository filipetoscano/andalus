using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "key" )]
[Subcommand( typeof( Keys.KeyCreateCommand ) )]
[Subcommand( typeof( Keys.KeyRemoveCommand ) )]
[Subcommand( typeof( Keys.KeySignCommand ) )]
[Subcommand( typeof( Keys.KeyVerifyCommand ) )]
public class KeyCommand
{
    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}