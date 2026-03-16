using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli.Xmls;

/// <summary />
[Command( "verify", Description = "" )]
public class XmlVerifyCommand
{
    private readonly ICryptoProvider _crypto;


    /// <summary />
    public XmlVerifyCommand( ICryptoProvider cp )
    {
        _crypto = cp;
    }


    /// <summary />
    public int OnExecute()
    {
        return 0;
    }
}