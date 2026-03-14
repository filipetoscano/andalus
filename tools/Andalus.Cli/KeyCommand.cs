using Andalus.Cryptography;
using McMaster.Extensions.CommandLineUtils;

namespace Andalus.Cli;

/// <summary />
[Command( "key" )]
public class KeyCommand
{
    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        ICryptoProvider cp = new FileCryptoProvider( new FileCryptoProviderOptions()
        {
            RootDirectory = Path.Combine( Environment.CurrentDirectory, "key-vault" ),
        } );

        var kp = await cp.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = Guid.NewGuid().ToString(),
            KeyType = KeyType.EcdsaSecp256k1,
            Exportable = true,
        } );

        Console.WriteLine( kp.KeyId );
        Console.WriteLine( kp.KeyType );

        return 0;
    }
}