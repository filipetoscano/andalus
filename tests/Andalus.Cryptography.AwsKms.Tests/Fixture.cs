using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace Andalus.Cryptography.AwsKms.Tests;

/// <summary />
public class Fixture : IAsyncLifetime
{
    /// <summary />
    public ServiceProvider Services { get; private set; } = null!;


    /// <summary />
    public async ValueTask InitializeAsync()
    {
        this.Services = SetupDependencyInjection();
    }


    /// <summary />
    public async ValueTask DisposeAsync()
    {
        await TearDownAsync();

        if ( Services is IAsyncDisposable ad )
            await ad.DisposeAsync();
        else
            Services?.Dispose();
    }


    /// <summary />
    private async Task TearDownAsync()
    {
        if ( TestConfig.Enabled == false )
            return;

        
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

        return svc.BuildServiceProvider();
    }
}