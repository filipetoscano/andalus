using Google.Api.Gax.Grpc;

namespace Andalus.Cryptography.GoogleKms;

/// <summary />
internal static class CancellationTokenExtensions
{
    /// <summary />
    internal static CallSettings? ToCallSettings( this CancellationToken cancellationToken )
    {
        return cancellationToken == default
            ? null
            : CallSettings.FromCancellationToken( cancellationToken );
    }
}