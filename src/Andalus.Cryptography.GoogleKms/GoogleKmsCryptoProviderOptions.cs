using Google.Cloud.Kms.V1;

namespace Andalus.Cryptography.GoogleKms;

/// <summary />
public sealed class GoogleKmsCryptoProviderOptions
{
    /// <summary>
    /// GCP project ID.
    /// </summary>
    public required string ProjectId { get; init; }

    /// <summary>
    /// GCP location (e.g. "europe-west1", "global").
    /// </summary>
    public required string LocationId { get; init; }

    /// <summary>
    /// Key ring name within the project/location.
    /// </summary>
    public required string KeyRingId { get; init; }

    /// <summary>
    /// Optional pre-configured KMS client. If null, a default client
    /// is created using Application Default Credentials (ADC).
    /// </summary>
    public KeyManagementServiceClient? KmsClient { get; init; }
}