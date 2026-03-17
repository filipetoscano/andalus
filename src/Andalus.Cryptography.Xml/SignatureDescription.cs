using System.Security.Cryptography;

namespace Andalus.Cryptography.Xml;


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
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha256SignatureDescription ), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" );
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha384SignatureDescription ), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" );
        CryptoConfig.AddAlgorithm( typeof( EcdsaSha512SignatureDescription ), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" );

        return true;
    }
}


/// <summary />
public sealed class EcdsaSha256SignatureDescription : SignatureDescription
{
    /// <summary />
    public EcdsaSha256SignatureDescription()
    {
        KeyAlgorithm = typeof( ECDsa ).AssemblyQualifiedName!;
        DigestAlgorithm = typeof( SHA256 ).AssemblyQualifiedName!;
    }

    /// <summary />
    public override HashAlgorithm CreateDigest() => SHA256.Create();

    /// <summary />
    public override AsymmetricSignatureFormatter CreateFormatter( AsymmetricAlgorithm key )
        => new EcdsaSignatureFormatter( key, HashAlgorithmName.SHA256 );

    /// <summary />
    public override AsymmetricSignatureDeformatter CreateDeformatter( AsymmetricAlgorithm key )
        => new EcdsaSignatureDeformatter( key, HashAlgorithmName.SHA256 );
}


/// <summary />
public sealed class EcdsaSha384SignatureDescription : SignatureDescription
{
    /// <summary />
    public EcdsaSha384SignatureDescription()
    {
        KeyAlgorithm = typeof( ECDsa ).AssemblyQualifiedName!;
        DigestAlgorithm = typeof( SHA384 ).AssemblyQualifiedName!;
    }

    /// <summary />
    public override HashAlgorithm CreateDigest() => SHA384.Create();

    /// <summary />
    public override AsymmetricSignatureFormatter CreateFormatter( AsymmetricAlgorithm key )
        => new EcdsaSignatureFormatter( key, HashAlgorithmName.SHA384 );

    /// <summary />
    public override AsymmetricSignatureDeformatter CreateDeformatter( AsymmetricAlgorithm key )
        => new EcdsaSignatureDeformatter( key, HashAlgorithmName.SHA384 );
}


/// <summary />
public sealed class EcdsaSha512SignatureDescription : SignatureDescription
{
    /// <summary />
    public EcdsaSha512SignatureDescription()
    {
        KeyAlgorithm = typeof( ECDsa ).AssemblyQualifiedName!;
        DigestAlgorithm = typeof( SHA512 ).AssemblyQualifiedName!;
    }

    /// <summary />
    public override HashAlgorithm CreateDigest() => SHA512.Create();

    /// <summary />
    public override AsymmetricSignatureFormatter CreateFormatter( AsymmetricAlgorithm key )
        => new EcdsaSignatureFormatter( key, HashAlgorithmName.SHA512 );

    /// <summary />
    public override AsymmetricSignatureDeformatter CreateDeformatter( AsymmetricAlgorithm key )
        => new EcdsaSignatureDeformatter( key, HashAlgorithmName.SHA512 );
}


/// <summary />
public sealed class EcdsaSignatureFormatter : AsymmetricSignatureFormatter
{
    private ECDsa? _key;
    private readonly HashAlgorithmName _hashAlgorithm;

    /// <summary />
    public EcdsaSignatureFormatter( AsymmetricAlgorithm key, HashAlgorithmName hashAlgorithm )
    {
        _key = key as ECDsa ?? throw new ArgumentException( "Key must be ECDsa." );
        _hashAlgorithm = hashAlgorithm;
    }

    /// <summary />
    public override void SetKey( AsymmetricAlgorithm key )
        => _key = key as ECDsa ?? throw new ArgumentException( "Key must be ECDsa." );

    /// <summary />
    public override void SetHashAlgorithm( string strName )
    {
        if ( strName != _hashAlgorithm.Name )
            throw new InvalidOperationException( $"Hash algorithm mismatch: expected '{_hashAlgorithm.Name}', called with '{strName}'" );
    }

    /// <summary />
    public override byte[] CreateSignature( byte[] rgbHash )
        => _key!.SignHash( rgbHash );
}


/// <summary />
public sealed class EcdsaSignatureDeformatter : AsymmetricSignatureDeformatter
{
    private ECDsa? _key;
    private readonly HashAlgorithmName _hashAlgorithm;

    /// <summary />
    public EcdsaSignatureDeformatter( AsymmetricAlgorithm key, HashAlgorithmName hashAlgorithm )
    {
        _key = key as ECDsa ?? throw new ArgumentException( "Key must be ECDsa." );
        _hashAlgorithm = hashAlgorithm;
    }

    /// <summary />
    public override void SetKey( AsymmetricAlgorithm key )
        => _key = key as ECDsa ?? throw new ArgumentException( "Key must be ECDsa." );

    /// <summary />
    public override void SetHashAlgorithm( string strName )
    {
        if ( strName != _hashAlgorithm.Name )
            throw new InvalidOperationException( $"Hash algorithm mismatch: expected '{_hashAlgorithm.Name}', called with '{strName}'" );
    }

    /// <summary />
    public override bool VerifySignature( byte[] rgbHash, byte[] rgbSignature )
        => _key!.VerifyHash( rgbHash, rgbSignature );
}