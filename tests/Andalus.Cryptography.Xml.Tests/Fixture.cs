using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using System.Security.Cryptography.X509Certificates;

namespace Andalus.Cryptography.Xml.Tests;

/// <summary />
public class Fixture : IAsyncLifetime
{
    /// <summary />
    public ServiceProvider Services { get; private set; } = null!;

    /// <summary />
    private readonly Dictionary<KeyType, Bundle> _bundles = new Dictionary<KeyType, Bundle>();


    /// <summary />
    public Bundle Get( KeyType keyType )
    {
        return _bundles[ keyType ];
    }


    /// <summary />
    public async ValueTask InitializeAsync()
    {
        this.Services = SetupDependencyInjection();

        var cp = Services.GetRequiredService<ICryptoProvider>();

        foreach ( var v in Enum.GetValues<KeyType>() )
        {
            var b = await CreateBundleAsync( cp, v );
            _bundles.Add( v, b );
        }
    }


    /// <summary />
    private async Task<Bundle> CreateBundleAsync( ICryptoProvider provider, KeyType keyType )
    {
        var keyRef = await provider.CreateKeyPairAsync( new KeyCreationOptions()
        {
            KeyName = keyType.ToString(),
            KeyType = keyType,
        } );

        var csr = await CsrSigner.CreateAsync( provider, keyRef, new CsrData()
        {
            CommonName = "Fixture " + keyType.ToString(),
            Country = "PT",
        } );

        var cert = await X509.SelfSignAsync( provider, keyRef, csr );
        var x509 = cert.ToX509Certificate2();

        return new Bundle()
        {
            KeyReference = keyRef,
            Certificate = x509,
        };
    }


    /// <summary />
    public class Bundle
    {
        /// <summary />
        public required KeyReference KeyReference { get; set; }

        /// <summary />
        public required X509Certificate2 Certificate { get; set; }
    }


    /// <summary />
    public async ValueTask DisposeAsync()
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