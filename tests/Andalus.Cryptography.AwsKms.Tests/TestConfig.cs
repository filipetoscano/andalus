namespace Andalus.Cryptography.AwsKms.Tests;

/// <summary />
internal class TestConfig
{
    /// <summary />
    internal static bool Enabled
    {
        get
        {
            return Environment.GetEnvironmentVariable( "AWS_KMS" ) != null;
        }
    }


    /// <summary />
    internal static Uri VaultId
    {
        get
        {
            var url = Environment.GetEnvironmentVariable( "AWS_KMS" ) ?? throw new InvalidOperationException();

            return new Uri( url );
        }
    }
}