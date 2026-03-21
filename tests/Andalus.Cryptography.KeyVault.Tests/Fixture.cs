using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace Andalus.Cryptography.KeyVault.Tests;

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

        var client = new KeyClient( TestConfig.VaultId, new DefaultAzureCredential() );

        // Delete all keys
        var deleteTasks = new List<Task>();

        await foreach ( var prop in client.GetPropertiesOfKeysAsync() )
        {
            var op = await client.StartDeleteKeyAsync( prop.Name );
            deleteTasks.Add( op.WaitForCompletionAsync().AsTask() );
        }

        await Task.WhenAll( deleteTasks );

        // Purge all deleted keys
        await foreach ( var deleted in client.GetDeletedKeysAsync() )
        {
            await client.PurgeDeletedKeyAsync( deleted.Name );
        }
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