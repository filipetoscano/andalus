using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace Andalus.Cryptography.Xml.Tests;

/// <summary />
public class Fixture : IAsyncLifetime
{
    /// <summary />
    public ServiceProvider Services { get; private set; } = null!;

    /// <summary />
    public KeyReference EcdsaKey { get; set; } = null!;

    /// <summary />
    public KeyReference RsaKey { get; set; } = null!;


    /// <summary />
    public async Task InitializeAsync()
    {
        this.Services = SetupDependencyInjection();

        var cp = Services.GetRequiredService<ICryptoProvider>();

        this.EcdsaKey = await cp.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = "ECDSA",
            KeyType = KeyType.EcdsaSecp256k1,
        } );

        this.RsaKey = await cp.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = "RSA",
            KeyType = KeyType.Rsa2048,
        } );
    }


    /// <summary />
    public async Task DisposeAsync()
    {
        if ( Services is IAsyncDisposable ad )
            await ad.DisposeAsync();
        else
            Services?.Dispose();
    }


    /// <summary />
    protected ServiceProvider SetupDependencyInjection()
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .MinimumLevel.Override( "Microsoft", LogEventLevel.Warning )
            .Enrich.FromLogContext()
            .WriteTo.Console()
            .CreateLogger();

        var svc = new ServiceCollection();

        svc.AddLogging( b =>
        {
            b.ClearProviders();
            b.AddSerilog( Log.Logger, dispose: true );
        } );

        svc.AddOptions();
        svc.AddSingleton<ICryptoProvider, MemoryCryptoProvider>();

        return svc.BuildServiceProvider();
    }
}