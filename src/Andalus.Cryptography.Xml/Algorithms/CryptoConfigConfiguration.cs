using System.Security.Cryptography;

namespace Andalus.Cryptography.Xml.Algorithms;

/// <summary />
public static class CryptoConfigConfiguration
{
    private static Lazy<bool> _registration = new Lazy<bool>( AddAlgorithms );


    /// <summary />
    public static void Register()
    {
        _ = _registration.Value;
    }


    /// <summary />
    private static bool AddAlgorithms()
    {
        CryptoConfig.AddAlgorithm( typeof( XmlDsigC14N11Transform ), XmlDsigC14N11Transform.AlgorithmUri );
        CryptoConfig.AddAlgorithm( typeof( XmlDsigC14N11WithCommentsTransform ), XmlDsigC14N11WithCommentsTransform.AlgorithmUri );

        CryptoConfig.AddAlgorithm( typeof( EcdsaSha256SignatureDescription ), EcdsaSha256SignatureDescription.AlgorithmUrl );
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha384SignatureDescription ), EcdsaSha384SignatureDescription.AlgorithmUrl );
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha512SignatureDescription ), EcdsaSha512SignatureDescription.AlgorithmUrl );

        return true;
    }
}