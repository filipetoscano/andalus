using Amazon.KeyManagementService;

namespace Andalus.Cryptography.AwsKms;

/// <summary />
public sealed class AwsKmsCryptoProviderOptions
{
    /// <summary>
    /// Optional pre-configured KMS client. If null, a default client
    /// is created using the ambient AWS credentials chain.
    /// </summary>
    public AmazonKeyManagementServiceClient? KmsClient { get; init; }
}