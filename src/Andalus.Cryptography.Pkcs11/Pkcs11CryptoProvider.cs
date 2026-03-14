using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Security.Cryptography;

namespace Andalus.Cryptography.Pkcs11;

/// <summary />
public class Pkcs11CryptoProvider : ICryptoProvider, IDisposable
{
    private readonly Pkcs11CryptoProviderOptions _options;
    private readonly Pkcs11InteropFactories _factories;
    private readonly IPkcs11Library _pkcs11;
    private readonly ISlot _slot;


    /// <summary />
    public Pkcs11CryptoProvider( Pkcs11CryptoProviderOptions options )
    {
        _options = options;
        _factories = new Pkcs11InteropFactories();

        _pkcs11 = _factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            _factories,
            options.LibraryPath,
            AppType.MultiThreaded );

        _slot = _pkcs11
            .GetSlotList( SlotsType.WithTokenPresent )
            .FirstOrDefault( s => s.GetSlotInfo().SlotId == (ulong) options.SlotId )
            ?? throw new CryptographicException( $"Slot {options.SlotId} not found." );
    }


    /// <inheritdoc />
    public Task<KeyReference> CreateKeyPairAsync(
        KeyCreationOptions options,
        CancellationToken cancellationToken = default )
    {
        using var session = OpenUserSession( SessionType.ReadWrite );

        var (publicHandle, privateHandle) = options.KeyType.Family() == KeyFamily.Ecdsa
            ? GenerateEcKeyPair( session, options )
            : GenerateRsaKeyPair( session, options );

        var keyId = ReadCkaId( session, privateHandle );

        return Task.FromResult( new KeyReference
        {
            KeyId = keyId,
            KeyType = options.KeyType,
        } );
    }


    /// <inheritdoc />
    public Task<byte[]> GetPublicKeyAsync(
        KeyReference key,
        CancellationToken cancellationToken = default )
    {
        using var session = OpenUserSession( SessionType.ReadOnly );

        var handle = FindKey( session, CKO.CKO_PUBLIC_KEY, key.KeyId );

        var attrs = session.GetAttributeValue( handle,
            new List<CKA> { CKA.CKA_PUBLIC_KEY_INFO } );

        return Task.FromResult( attrs[ 0 ].GetValueAsByteArray() );
    }


    /// <inheritdoc />
    public Task<KeyReference> ImportKeyPairAsync(
        KeyCreationOptions options,
        KeyPair keyPair,
        CancellationToken cancellationToken = default )
    {
        throw new NotImplementedException();
    }


    /// <inheritdoc />
    public Task<RemoveResult> RemoveKeyPairAsync(
        KeyReference key,
        CancellationToken cancellationToken = default )
    {
        using var session = OpenUserSession( SessionType.ReadWrite );

        var privateHandle = FindKey( session, CKO.CKO_PRIVATE_KEY, key.KeyId );
        session.DestroyObject( privateHandle );

        var publicHandle = FindKey( session, CKO.CKO_PUBLIC_KEY, key.KeyId );
        session.DestroyObject( publicHandle );

        return Task.FromResult( new RemoveResult
        {
            CompleteAsync = Task.CompletedTask,
        } );
    }


    /// <inheritdoc />
    public Task<SignResult> SignHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        using var session = OpenUserSession( SessionType.ReadOnly );

        var handle = FindKey( session, CKO.CKO_PRIVATE_KEY, key.KeyId );
        var ckm = MapSignMechanism( key.KeyType );

        using var mechanism = _factories.MechanismFactory.Create( ckm );
        var raw = session.Sign( mechanism, handle, hash.ToArray() );

        // CKM_ECDSA returns IEEE P1363; normalize to DER
        byte[] signature = key.KeyType.Family() == KeyFamily.Ecdsa
            ? SignatureFormat.ConvertIeeeP1363ToDer( raw )
            : raw;

        return Task.FromResult( new SignResult
        {
            KeyVersion = key.KeyId,
            Signature = signature,
        } );
    }


    /// <inheritdoc />
    public Task<bool> VerifyHashAsync(
        KeyReference key,
        ReadOnlyMemory<byte> hash,
        ReadOnlyMemory<byte> signature,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken = default )
    {
        using var session = OpenUserSession( SessionType.ReadOnly );

        var handle = FindKey( session, CKO.CKO_PUBLIC_KEY, key.KeyId );
        var ckm = MapSignMechanism( key.KeyType );

        // CKM_ECDSA expects IEEE P1363; input is DER
        byte[] signBytes = key.KeyType.Family() == KeyFamily.Ecdsa
            ? SignatureFormat.ConvertDerToIeeeP1363( signature.ToArray() )
            : signature.ToArray();

        using var mechanism = _factories.MechanismFactory.Create( ckm );
        session.Verify( mechanism, handle, hash.ToArray(), signBytes, out bool isValid );

        return Task.FromResult( isValid );
    }


    /// <summary />
    public void Dispose()
    {
        _pkcs11?.Dispose();
    }


    /*
     * Session management
     */

    private ISession OpenUserSession( SessionType type )
    {
        var session = _slot.OpenSession( type );
        session.Login( CKU.CKU_USER, _options.UserPin );
        return session;
    }


    /*
     * Key generation
     */

    private (IObjectHandle pub, IObjectHandle prv) GenerateEcKeyPair(
        ISession session,
        KeyCreationOptions options )
    {
        var ecParams = MapEcParams( options.KeyType );
        var ckaId = Guid.NewGuid().ToByteArray();

        var pubTemplate = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create( CKA.CKA_TOKEN, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_VERIFY, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_LABEL, options.KeyName ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_EC_PARAMS, ecParams ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_ID, ckaId ),
        };

        var prvTemplate = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create( CKA.CKA_TOKEN, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_PRIVATE, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_SENSITIVE, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_EXTRACTABLE, options.Exportable ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_SIGN, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_LABEL, options.KeyName ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_ID, ckaId ),
        };

        using var mech = _factories.MechanismFactory.Create( CKM.CKM_EC_KEY_PAIR_GEN );
        session.GenerateKeyPair( mech, pubTemplate, prvTemplate,
            out var pubHandle, out var prvHandle );

        return (pubHandle, prvHandle);
    }


    private (IObjectHandle pub, IObjectHandle prv) GenerateRsaKeyPair(
        ISession session,
        KeyCreationOptions options )
    {
        var keySize = options.KeyType switch
        {
            KeyType.Rsa2048 => 2048,
            KeyType.Rsa3072 => 3072,
            KeyType.Rsa4096 => 4096,
            _ => 2048,
        };

        var ckaId = Guid.NewGuid().ToByteArray();

        var pubTemplate = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create( CKA.CKA_TOKEN, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_VERIFY, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_LABEL, options.KeyName ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_MODULUS_BITS, (ulong)keySize ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_PUBLIC_EXPONENT,
                new byte[] { 0x01, 0x00, 0x01 } ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_ID, ckaId ),
        };

        var prvTemplate = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create( CKA.CKA_TOKEN, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_PRIVATE, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_SENSITIVE, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_EXTRACTABLE, options.Exportable ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_SIGN, true ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_LABEL, options.KeyName ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_ID, ckaId ),
        };

        using var mech = _factories.MechanismFactory.Create( CKM.CKM_RSA_PKCS_KEY_PAIR_GEN );
        session.GenerateKeyPair( mech, pubTemplate, prvTemplate,
            out var pubHandle, out var prvHandle );

        return (pubHandle, prvHandle);
    }


    /*
     * Object lookup
     */

    private IObjectHandle FindKey( ISession session, CKO objectClass, string keyId )
    {
        var ckaId = Convert.FromHexString( keyId );

        var template = new List<IObjectAttribute>
        {
            _factories.ObjectAttributeFactory.Create( CKA.CKA_CLASS, objectClass ),
            _factories.ObjectAttributeFactory.Create( CKA.CKA_ID, ckaId ),
        };

        return session.FindAllObjects( template ).SingleOrDefault()
            ?? throw new CryptographicException(
                $"{objectClass} with CKA_ID '{keyId}' not found." );
    }


    private string ReadCkaId( ISession session, IObjectHandle handle )
    {
        var attrs = session.GetAttributeValue( handle, new List<CKA> { CKA.CKA_ID } );
        return Convert.ToHexString( attrs[ 0 ].GetValueAsByteArray() );
    }


    /*
     * PKCS#11 mapping
     */

    /// <summary>
    /// DER-encoded OID for the EC curve, set as CKA_EC_PARAMS.
    /// </summary>
    private static byte[] MapEcParams( KeyType keyType ) => keyType switch
    {
        KeyType.EcdsaP256 => [ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 ],
        KeyType.EcdsaP384 => [ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 ],
        KeyType.EcdsaP521 => [ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 ],
        KeyType.EcdsaSecp256k1 => [ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A ],
        _ => throw new NotSupportedException( $"'{keyType}' is not an EC key." )
    };


    /// <summary>
    /// CKM_ECDSA: signs a raw hash, no internal hashing.
    /// CKM_RSA_PKCS: PKCS#1 v1.5 sign with DigestInfo wrapping.
    /// </summary>
    private static CKM MapSignMechanism( KeyType keyType ) => keyType.Family() switch
    {
        KeyFamily.Ecdsa => CKM.CKM_ECDSA,
        KeyFamily.Rsa => CKM.CKM_RSA_PKCS,
        _ => throw new NotSupportedException( $"'{keyType}' is not supported." )
    };

}