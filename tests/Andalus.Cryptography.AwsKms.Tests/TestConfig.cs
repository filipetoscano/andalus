namespace Andalus.Cryptography.AwsKms.Tests;

/// <summary />
internal class TestConfig
{
    /// <summary />
    internal static bool Enabled
    {
        get
        {
            return Environment.GetEnvironmentVariable( "AWS_PROFILE" ) != null;
        }
    }


    /// <summary />
    internal static string ProfileName
    {
        get
        {
            return Environment.GetEnvironmentVariable( "AWS_PROFILE" ) ?? throw new InvalidOperationException();
        }
    }
}