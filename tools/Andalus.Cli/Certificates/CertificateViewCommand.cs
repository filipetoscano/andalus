using McMaster.Extensions.CommandLineUtils;
using Spectre.Console;
using System.ComponentModel.DataAnnotations;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Andalus.Cli.Certificates;

/// <summary />
[Command( "view", Description = "Views a certificate" )]
public class CertificateViewCommand
{
    /// <summary />
    public CertificateViewCommand()
    {
    }


    /// <summary />
    [Argument( 0, Description = "Certificate" )]
    [Required]
    [FileExists]
    public string? CertificatePath { get; set; }


    /// <summary />
    public async Task<int> OnExecuteAsync()
    {
        var crt = X509CertificateLoader.LoadCertificateFromFile( this.CertificatePath! );

        /*
         * 
         */
        AnsiConsole.MarkupLine( "[bold]General[/]" );

        var general = new Table();
        general.Border = TableBorder.SimpleHeavy;
        general.HideHeaders();
        general.AddColumn( "Key" );
        general.AddColumn( "Value" );

        general.AddRow( "Version", $"V{crt.Version}" );
        general.AddRow( "Serial Number", crt.SerialNumber );
        general.AddRow( "Signature Algorithm", crt.SignatureAlgorithm.FriendlyName ?? crt.SignatureAlgorithm.Value ?? "" );
        general.AddRow( "Not Before", crt.NotBefore.ToString( "u" ) );
        general.AddRow( "Not After", crt.NotAfter.ToString( "u" ) );
        general.AddRow( "Thumbprint (SHA1)", crt.Thumbprint );
        general.AddRow( "Thumbprint (SHA256)", Convert.ToHexString( crt.GetCertHash( System.Security.Cryptography.HashAlgorithmName.SHA256 ) ) );
        general.AddRow( "Has Private Key", crt.HasPrivateKey.ToString() );

        AnsiConsole.Write( general );
        AnsiConsole.WriteLine();


        /*
         * 
         */
        AnsiConsole.MarkupLine( "[bold]Subject[/]" );

        var table = new Table();
        table.Border = TableBorder.SimpleHeavy;
        table.AddColumn( "Oid" );
        table.AddColumn( "Name" );
        table.AddColumn( "Value" );

        foreach ( var dn in crt.SubjectName.EnumerateRelativeDistinguishedNames() )
        {
            table.AddRow(
                new Markup( dn.GetSingleElementType().Value ?? "" ),
                new Markup( dn.GetSingleElementType().FriendlyName ?? "" ),
                new Markup( dn.GetSingleElementValue() ?? "" )
            );
        }

        AnsiConsole.Write( table );


        /*
         *
         */
        AnsiConsole.MarkupLine( "[bold]Issuer[/]" );

        var issuer = new Table();
        issuer.Border = TableBorder.SimpleHeavy;
        issuer.AddColumn( "OID" );
        issuer.AddColumn( "Name" );
        issuer.AddColumn( "Value" );

        foreach ( var dn in crt.IssuerName.EnumerateRelativeDistinguishedNames() )
        {
            issuer.AddRow(
                new Markup( dn.GetSingleElementType().Value ?? "" ),
                new Markup( dn.GetSingleElementType().FriendlyName ?? "" ),
                new Markup( dn.GetSingleElementValue() ?? "" )
            );
        }

        var isSelfSigned = crt.SubjectName.RawData.AsSpan().SequenceEqual( crt.IssuerName.RawData );
        if ( isSelfSigned )
            issuer.Caption( "[dim](self-signed)[/]" );

        AnsiConsole.Write( issuer );
        AnsiConsole.WriteLine();


        /*
         *
         */
        AnsiConsole.MarkupLine( "[bold]Public Key[/]" );

        var pubKey = new Table();
        pubKey.Border = TableBorder.SimpleHeavy;
        pubKey.HideHeaders();
        pubKey.AddColumn( "Key" );
        pubKey.AddColumn( "Value" );

        var oid = crt.PublicKey.Oid;
        pubKey.AddRow( "Algorithm", oid.FriendlyName ?? oid.Value ?? "" );

        if ( crt.GetECDsaPublicKey() is { } ecdsa )
        {
            var ecParams = ecdsa.ExportParameters( false );
            pubKey.AddRow( "Curve", ecParams.Curve.Oid?.FriendlyName ?? ecParams.Curve.Oid?.Value ?? "" );
            pubKey.AddRow( "Key Size", $"{ecdsa.KeySize} bits" );
        }
        else if ( crt.GetRSAPublicKey() is { } rsa )
        {
            pubKey.AddRow( "Key Size", $"{rsa.KeySize} bits" );
            var rsaParams = rsa.ExportParameters( false );
            pubKey.AddRow( "Exponent", Convert.ToHexString( rsaParams.Exponent! ) );
        }

        AnsiConsole.Write( pubKey );
        AnsiConsole.WriteLine();


        /*
         *
         */
        if ( crt.Extensions.Count > 0 )
        {
            AnsiConsole.MarkupLine( "[bold]Extensions[/]" );

            var ext = new Table();
            ext.Border = TableBorder.SimpleHeavy;
            ext.AddColumn( "OID" );
            ext.AddColumn( "Name" );
            ext.AddColumn( "Critical" );
            ext.AddColumn( "Value" );

            foreach ( var extension in crt.Extensions )
            {
                var value = FormatExtension( extension );

                ext.AddRow(
                    new Markup( extension.Oid?.Value ?? "" ),
                    new Markup( extension.Oid?.FriendlyName ?? "" ),
                    new Markup( extension.Critical ? "[red]Yes[/]" : "No" ),
                    new Markup( Markup.Escape( value ) )
                );
            }

            AnsiConsole.Write( ext );
            AnsiConsole.WriteLine();
        }


        /*
         * Validation
         */
        AnsiConsole.MarkupLine( "[bold]Validation[/]" );

        var isExpired = crt.NotAfter < DateTime.UtcNow;
        var isNotYetValid = crt.NotBefore > DateTime.UtcNow;
        var daysRemaining = ( crt.NotAfter - DateTime.UtcNow ).Days;

        if ( isExpired )
            AnsiConsole.MarkupLine( "[red]  EXPIRED[/]" );
        else if ( isNotYetValid )
            AnsiConsole.MarkupLine( "[yellow]  NOT YET VALID[/]" );
        else if ( daysRemaining < 30 )
            AnsiConsole.MarkupLine( $"[yellow]  Valid — expires in {daysRemaining} days[/]" );
        else
            AnsiConsole.MarkupLine( $"[green]  Valid — expires in {daysRemaining} days[/]" );

        return 0;
    }


    /// <summary />
    private static string FormatExtension( X509Extension extension )
    {
        return extension switch
        {
            X509BasicConstraintsExtension bc
                => $"CA={bc.CertificateAuthority}, PathLen={( bc.HasPathLengthConstraint ? bc.PathLengthConstraint : "unlimited" )}",

            X509KeyUsageExtension ku
                => ku.KeyUsages.ToString(),

            X509EnhancedKeyUsageExtension eku
                => string.Join( ", ", eku.EnhancedKeyUsages.Cast<Oid>().Select( o => o.FriendlyName ?? o.Value ) ),

            X509SubjectKeyIdentifierExtension ski
                => ski.SubjectKeyIdentifier ?? "",

            X509AuthorityKeyIdentifierExtension aki
                => aki.KeyIdentifier is { } kid ? Convert.ToHexString( kid.Span ) : "",

            X509SubjectAlternativeNameExtension san
                => string.Join( ", ", san.EnumerateDnsNames().Select( d => $"DNS:{d}" )
                    .Concat( san.EnumerateIPAddresses().Select( ip => $"IP:{ip}" ) ) ),

            _ when extension.Oid?.Value == "2.5.29.32"
                => FormatCertificatePolicies( extension.RawData ),

            _ => FormatRawOrText( extension ),
        };
    }


    /// <summary />
    private static string FormatCertificatePolicies( byte[] rawData )
    {
        var lines = new List<string>();

        try
        {
            var reader = new AsnReader( rawData, AsnEncodingRules.DER );
            var policies = reader.ReadSequence();
            var index = 1;

            while ( policies.HasData )
            {
                var policyInfo = policies.ReadSequence();
                var policyOid = policyInfo.ReadObjectIdentifier();

                lines.Add( $"[{index}] Policy: {policyOid}" );

                if ( policyInfo.HasData )
                {
                    var qualifiers = policyInfo.ReadSequence();
                    var qualIndex = 1;

                    while ( qualifiers.HasData )
                    {
                        var qualInfo = qualifiers.ReadSequence();
                        var qualOid = qualInfo.ReadObjectIdentifier();

                        if ( qualOid == "1.3.6.1.5.5.7.2.1" )
                        {
                            // CPS URI
                            var cpsUri = qualInfo.ReadCharacterString( UniversalTagNumber.IA5String );
                            lines.Add( $"    [{index},{qualIndex}] CPS: {cpsUri}" );
                        }
                        else if ( qualOid == "1.3.6.1.5.5.7.2.2" )
                        {
                            // User Notice
                            var userNotice = qualInfo.ReadSequence();
                            var noticeText = ReadUserNoticeText( userNotice );

                            lines.Add( $"    [{index},{qualIndex}] User Notice: {noticeText}" );
                        }
                        else
                        {
                            lines.Add( $"    [{index},{qualIndex}] Qualifier: {qualOid}" );
                        }

                        qualIndex++;
                    }
                }

                index++;
            }
        }
        catch
        {
            lines.Add( Convert.ToHexString( rawData ) );
        }

        return string.Join( "\n", lines );
    }


    /// <summary />
    private static string ReadUserNoticeText( AsnReader userNotice )
    {
        // UserNotice ::= SEQUENCE {
        //   noticeRef   [0] NoticeReference OPTIONAL,
        //   explicitText    DisplayText OPTIONAL }
        //
        // DisplayText ::= CHOICE {
        //   ia5String     IA5String,
        //   visibleString VisibleString,
        //   bmpString     BMPString,
        //   utf8String    UTF8String }

        while ( userNotice.HasData )
        {
            var tag = userNotice.PeekTag();

            if ( tag == Asn1Tag.Sequence )
            {
                // NoticeReference — skip
                userNotice.ReadSequence();
                continue;
            }

            if ( tag.TagClass == TagClass.ContextSpecific )
            {
                userNotice.ReadEncodedValue();
                continue;
            }

            return tag.TagValue switch
            {
                (int) UniversalTagNumber.UTF8String
                    => userNotice.ReadCharacterString( UniversalTagNumber.UTF8String ),

                (int) UniversalTagNumber.IA5String
                    => userNotice.ReadCharacterString( UniversalTagNumber.IA5String ),

                (int) UniversalTagNumber.VisibleString
                    => userNotice.ReadCharacterString( UniversalTagNumber.VisibleString ),

                (int) UniversalTagNumber.BMPString
                    => userNotice.ReadCharacterString( UniversalTagNumber.BMPString ),

                _ => Convert.ToBase64String( userNotice.ReadEncodedValue().Span ),
            };
        }

        return "";
    }


    /// <summary />
    private static string FormatRawOrText( X509Extension extension )
    {
        // Try to decode as a simple OCTET STRING wrapping printable text
        try
        {
            var reader = new AsnReader( extension.RawData, AsnEncodingRules.DER );
            var tag = reader.PeekTag();

            if ( tag.TagValue == (int) UniversalTagNumber.OctetString )
            {
                var bytes = reader.ReadOctetString();

                // If it looks like Base64 or ASCII text, show it
                if ( bytes.All( b => b >= 0x20 && b < 0x7F ) )
                    return System.Text.Encoding.ASCII.GetString( bytes );

                return Convert.ToBase64String( bytes );
            }

            if ( tag.TagValue == (int) UniversalTagNumber.UTF8String )
                return reader.ReadCharacterString( UniversalTagNumber.UTF8String );
        }
        catch
        {
        }

        // Fallback: hex dump
        return Convert.ToHexString( extension.RawData.AsSpan( 0, Math.Min( extension.RawData.Length, 32 ) ) )
            + ( extension.RawData.Length > 32 ? "..." : "" );
    }
}