using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Andalus.Cryptography.Pkcs11;

/// <summary />
public class Pkcs11CryptoProvider : ICryptoProvider, IDisposable
{
    private static readonly Pkcs11InteropFactories _factories = new();
    private static readonly ConcurrentDictionary<string, SharedPkcs11Library> _libraries = new();

    private readonly Pkcs11CryptoProviderOptions _options;
    private readonly IPkcs11Library _pkcs11;
    private readonly ISlot _slot;


    /// <summary />
    public Pkcs11CryptoProvider( Pkcs11CryptoProviderOptions options )
    {
        _options = options;

        var fullPath = Path.GetFullPath( options.LibraryPath );

        var shared = _libraries.GetOrAdd( fullPath,
            path => new SharedPkcs11Library( path, _factories ) );

        shared.AddRef();
        _pkcs11 = shared.Library;

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

        // Try CKA_PUBLIC_KEY_INFO first (PKCS#11 v2.40+)
        try
        {
            var attrs = session.GetAttributeValue( handle,
                new List<CKA> { CKA.CKA_PUBLIC_KEY_INFO } );

            var value = attrs[ 0 ].GetValueAsByteArray();

            if ( value is { Length: > 0 } )
                return Task.FromResult( value );
        }
        catch
        {
            // Not supported by this token, fall through
        }

        // Reconstruct SubjectPublicKeyInfo from raw attributes
        var spki = key.KeyType.Family() == KeyFamily.Ecdsa
            ? BuildEcSubjectPublicKeyInfo( session, handle )
            : BuildRsaSubjectPublicKeyInfo( session, handle );

        return Task.FromResult( spki );
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
            ? SignatureFormat.ConvertIeeeP1363ToDer( raw, key.KeyType.CurveOrder() )
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
            ? SignatureFormat.ConvertDerToIeeeP1363( signature.ToArray(), key.KeyType.CurveOrder() )
            : signature.ToArray();

        using var mechanism = _factories.MechanismFactory.Create( ckm );
        session.Verify( mechanism, handle, hash.ToArray(), signBytes, out bool isValid );

        return Task.FromResult( isValid );
    }


    /*
     * Session management
     */


    /// <summary />
    private ISession OpenUserSession( SessionType type )
    {
        var session = _slot.OpenSession( type );
        session.Login( CKU.CKU_USER, _options.UserPin );
        return session;
    }


    /// <summary />
    public void Dispose()
    {
        var fullPath = Path.GetFullPath( _options.LibraryPath );

        if ( _libraries.TryGetValue( fullPath, out var shared ) )
        {
            if ( shared.Release() == 0 )
            {
                _libraries.TryRemove( fullPath, out _ );
                shared.Library.Dispose(); // calls C_Finalize
            }
        }
    }


    /*
     * Key generation
     */


    /// <summary />
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


    /// <summary />
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

    /// <summary />
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


    /// <summary />
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



    /// <summary />
    private static byte[] BuildRsaSubjectPublicKeyInfo( ISession session, IObjectHandle handle )
    {
        var attrs = session.GetAttributeValue( handle,
            new List<CKA> { CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT } );

        var modulus = attrs[ 0 ].GetValueAsByteArray();
        var exponent = attrs[ 1 ].GetValueAsByteArray();

        using var rsa = RSA.Create();

        rsa.ImportParameters( new RSAParameters
        {
            Modulus = modulus,
            Exponent = exponent,
        } );

        return rsa.ExportSubjectPublicKeyInfo();
    }


    /// <summary />
    private static byte[] BuildEcSubjectPublicKeyInfo( ISession session, IObjectHandle handle )
    {
        var attrs = session.GetAttributeValue( handle,
            new List<CKA> { CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT } );

        var ecParamsOid = attrs[ 0 ].GetValueAsByteArray();
        var ecPointRaw = attrs[ 1 ].GetValueAsByteArray();

        // CKA_EC_POINT: DER OCTET STRING wrapping the uncompressed point.
        // Strip the outer OCTET STRING tag+length to get raw 04||x||y.
        var ecPoint = UnwrapOctetString( ecPointRaw );

        // Determine the curve from the DER-encoded OID
        var curve = MapOidToCurve( ecParamsOid );

        // Split 04||x||y into coordinates
        var coordLen = ( ecPoint.Length - 1 ) / 2;

        var ecParameters = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = ecPoint[ 1..( coordLen + 1 ) ],
                Y = ecPoint[ ( coordLen + 1 ).. ],
            },
        };

        using var ecdsa = ECDsa.Create( ecParameters );
        return ecdsa.ExportSubjectPublicKeyInfo();
    }


    /// <summary />
    private static byte[] UnwrapOctetString( byte[] data )
    {
        // If it starts with 0x04 (OCTET STRING tag) and the length matches,
        // it's DER-wrapped. Otherwise it's already the raw point.
        if ( data.Length > 2 && data[ 0 ] == 0x04 )
        {
            var contentLen = data[ 1 ] switch
            {
                < 0x80 => (int) data[ 1 ],
                0x81 => data[ 2 ],
                _ => -1,
            };

            var headerLen = data[ 1 ] < 0x80 ? 2 : 3;

            if ( contentLen == data.Length - headerLen )
                return data[ headerLen.. ];
        }

        return data;
    }


    /// <summary />
    private static ECCurve MapOidToCurve( byte[] derEncodedOid )
    {
        ReadOnlySpan<byte> oid = derEncodedOid;

        if ( oid.SequenceEqual( (ReadOnlySpan<byte>) [ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 ] ) )
            return ECCurve.NamedCurves.nistP256;

        if ( oid.SequenceEqual( (ReadOnlySpan<byte>) [ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 ] ) )
            return ECCurve.NamedCurves.nistP384;

        if ( oid.SequenceEqual( (ReadOnlySpan<byte>) [ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 ] ) )
            return ECCurve.NamedCurves.nistP521;

        if ( oid.SequenceEqual( (ReadOnlySpan<byte>) [ 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A ] ) )
            return ECCurve.CreateFromValue( "1.3.132.0.10" );

        throw new NotSupportedException(
            $"Unknown EC curve OID: {Convert.ToHexString( derEncodedOid )}" );
    }
}