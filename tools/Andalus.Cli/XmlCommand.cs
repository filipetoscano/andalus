using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "xml" )]
[Subcommand( typeof( Xmls.XmlSignCommand ) )]
[Subcommand( typeof( Xmls.XmlVerifyCommand ) )]
public class XmlCommand
{
    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}