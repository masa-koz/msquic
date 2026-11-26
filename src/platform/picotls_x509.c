/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    X.509 certificate parsing and chain validation for the picotls TLS provider
    on Windows. See picotls_cert.h.

    The chain is validated as RFC 5280 describes for a TLS server, short of
    what isn't supported:

    - Signatures: sha256/384/512WithRSAEncryption, RSASSA-PSS with SHA-256/
      384/512, and ecdsa-with-SHA256/384/512 on P-256, P-384 and P-521.
      SHA-1 isn't accepted.
    - Names are compared byte for byte, as they are when one CA issues both
      certificates.
    - Name constraints and policies aren't enforced: a certificate that marks
      them critical is rejected, except certificatePolicies.
    - Revocation isn't checked.

--*/

#include "platform_internal.h"
#include "picotls_cert.h"
#include "picotls_der.h"
#ifdef QUIC_CLOG
#include "picotls_x509.c.clog.h"
#endif

//
// The most certificates between the leaf and the trust anchor.
//
#define CXPLAT_PICOTLS_MAX_CHAIN_DEPTH 8

static const uint8_t OidSha256WithRsa[] =       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
static const uint8_t OidSha384WithRsa[] =       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
static const uint8_t OidSha512WithRsa[] =       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
static const uint8_t OidRsassaPss[] =           { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
static const uint8_t OidMgf1[] =                { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08 };
static const uint8_t OidEcdsaWithSha256[] =     { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const uint8_t OidEcdsaWithSha384[] =     { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
static const uint8_t OidEcdsaWithSha512[] =     { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04 };
static const uint8_t OidSha256[] =              { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const uint8_t OidSha384[] =              { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const uint8_t OidSha512[] =              { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
static const uint8_t OidRsaEncryption[] =       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const uint8_t OidEcPublicKey[] =         { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t OidPrime256v1[] =          { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OidSecp384r1[] =           { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OidSecp521r1[] =           { 0x2B, 0x81, 0x04, 0x00, 0x23 };
static const uint8_t OidCommonName[] =          { 0x55, 0x04, 0x03 };
static const uint8_t OidKeyUsage[] =            { 0x55, 0x1D, 0x0F };
static const uint8_t OidSubjectAltName[] =      { 0x55, 0x1D, 0x11 };
static const uint8_t OidBasicConstraints[] =    { 0x55, 0x1D, 0x13 };
static const uint8_t OidCertificatePolicies[] = { 0x55, 0x1D, 0x20 };
static const uint8_t OidExtendedKeyUsage[] =    { 0x55, 0x1D, 0x25 };
static const uint8_t OidAnyExtendedKeyUsage[] = { 0x55, 0x1D, 0x25, 0x00 };
static const uint8_t OidServerAuth[] =          { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };

#define GENERAL_NAME_DNS        0x82    // [2] IMPLICIT IA5String
#define GENERAL_NAME_IP         0x87    // [7] IMPLICIT OCTET STRING

static
QUIC_STATUS
Malformed(
    _In_z_ const char* What
    )
{
    QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        What);
    return QUIC_STATUS_INVALID_PARAMETER;
}

static
ptls_iovec_t
ToIovec(
    _In_ const CXPLAT_DER* Der
    )
{
    return ptls_iovec_init(Der->Data, Der->Length);
}

static
BOOLEAN
IovecEqual(
    _In_ ptls_iovec_t A,
    _In_ ptls_iovec_t B
    )
{
    return A.len == B.len && (A.len == 0 || memcmp(A.base, B.base, A.len) == 0);
}

//
// Time.
//

static
BOOLEAN
ReadDigits(
    _In_reads_(Count) const uint8_t* Text,
    _In_ size_t Count,
    _Out_ uint32_t* Value
    )
{
    *Value = 0;
    for (size_t i = 0; i < Count; ++i) {
        if (Text[i] < '0' || Text[i] > '9') {
            return FALSE;
        }
        *Value = *Value * 10 + (uint32_t)(Text[i] - '0');
    }
    return TRUE;
}

//
// Days from 1970-01-01 to the given date of the proleptic Gregorian calendar.
//
static
int64_t
DaysFromCivil(
    _In_ int64_t Year,
    _In_ uint32_t Month,
    _In_ uint32_t Day
    )
{
    Year -= Month <= 2;
    const int64_t Era = (Year >= 0 ? Year : Year - 399) / 400;
    const int64_t YearOfEra = Year - Era * 400;
    const int64_t DayOfYear = (153 * (Month > 2 ? Month - 3 : Month + 9) + 2) / 5 + Day - 1;
    const int64_t DayOfEra = YearOfEra * 365 + YearOfEra / 4 - YearOfEra / 100 + DayOfYear;
    return Era * 146097 + DayOfEra - 719468;
}

//
// Reads a Time: UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ),
// the only forms RFC 5280 allows.
//
static
BOOLEAN
ReadTime(
    _Inout_ CXPLAT_DER* In,
    _Out_ int64_t* Seconds
    )
{
    uint8_t Tag;
    CXPLAT_DER Value;
    uint32_t Year, Month, Day, Hour, Minute, Second;
    *Seconds = 0;

    if (!DerRead(In, &Tag, &Value, NULL)) {
        return FALSE;
    }
    if (Tag == DER_UTC_TIME && Value.Length == 13) {
        if (!ReadDigits(Value.Data, 2, &Year)) {
            return FALSE;
        }
        Year += Year >= 50 ? 1900 : 2000;
        Value.Data += 2;
    } else if (Tag == DER_GENERALIZED_TIME && Value.Length == 15) {
        if (!ReadDigits(Value.Data, 4, &Year)) {
            return FALSE;
        }
        Value.Data += 4;
    } else {
        return FALSE;
    }
    if (!ReadDigits(Value.Data, 2, &Month) ||
        !ReadDigits(Value.Data + 2, 2, &Day) ||
        !ReadDigits(Value.Data + 4, 2, &Hour) ||
        !ReadDigits(Value.Data + 6, 2, &Minute) ||
        !ReadDigits(Value.Data + 8, 2, &Second) ||
        Value.Data[10] != 'Z' ||
        Month < 1 || Month > 12 || Day < 1 || Day > 31 ||
        Hour > 23 || Minute > 59 || Second > 60) {
        return FALSE;
    }
    *Seconds =
        DaysFromCivil(Year, Month, Day) * 86400 +
        (int64_t)Hour * 3600 + (int64_t)Minute * 60 + Second;
    return TRUE;
}

//
// Algorithms and keys.
//

static
BOOLEAN
ReadHashOid(
    _In_ const CXPLAT_DER* Oid,
    _Out_ CXPLAT_PICOTLS_HASH* Hash
    )
{
    if (DER_IS_OID(Oid, OidSha256)) {
        *Hash = CXPLAT_PICOTLS_HASH_SHA256;
    } else if (DER_IS_OID(Oid, OidSha384)) {
        *Hash = CXPLAT_PICOTLS_HASH_SHA384;
    } else if (DER_IS_OID(Oid, OidSha512)) {
        *Hash = CXPLAT_PICOTLS_HASH_SHA512;
    } else {
        *Hash = CXPLAT_PICOTLS_HASH_SHA1;
        return FALSE;
    }
    return TRUE;
}

//
// Reads the RSASSA-PSS-params of a signature algorithm. The defaults (SHA-1)
// aren't supported, and the mask must use MGF1 with the signature's hash,
// which is what BCrypt does.
//
static
BOOLEAN
ReadPssParams(
    _In_ CXPLAT_DER Params,
    _Out_ CXPLAT_PICOTLS_SIGNATURE_ALGORITHM* Algorithm
    )
{
    CXPLAT_DER Field, AlgorithmId, Oid, MgfParams;
    CXPLAT_PICOTLS_HASH MgfHash;

    Algorithm->Padding = CXPLAT_PICOTLS_PADDING_RSA_PSS;
    if (!DerExpect(&Params, DER_CONTEXT_0, &Field) ||                   // hashAlgorithm
        !DerExpect(&Field, DER_SEQUENCE, &AlgorithmId) ||
        !DerExpect(&AlgorithmId, DER_OID, &Oid) ||
        !ReadHashOid(&Oid, &Algorithm->Hash)) {
        return FALSE;
    }
    if (!DerExpect(&Params, DER_CONTEXT_1, &Field) ||                   // maskGenAlgorithm
        !DerExpect(&Field, DER_SEQUENCE, &AlgorithmId) ||
        !DerExpect(&AlgorithmId, DER_OID, &Oid) ||
        !DER_IS_OID(&Oid, OidMgf1) ||
        !DerExpect(&AlgorithmId, DER_SEQUENCE, &MgfParams) ||
        !DerExpect(&MgfParams, DER_OID, &Oid) ||
        !ReadHashOid(&Oid, &MgfHash) ||
        MgfHash != Algorithm->Hash) {
        return FALSE;
    }
    Algorithm->SaltLength = 20;
    if (DerExpect(&Params, DER_CONTEXT_2, &Field) &&                    // saltLength
        !DerUint32(&Field, &Algorithm->SaltLength)) {
        return FALSE;
    }
    if (DerExpect(&Params, DER_CONTEXT_3, &Field)) {                    // trailerField
        uint32_t Trailer;
        if (!DerUint32(&Field, &Trailer) || Trailer != 1) {
            return FALSE;
        }
    }
    return Params.Length == 0;
}

//
// Reads the AlgorithmIdentifier of a signature. Returns FALSE if it's
// malformed; Supported tells whether the algorithm is one that can be checked.
//
static
BOOLEAN
ReadSignatureAlgorithm(
    _In_ CXPLAT_DER AlgorithmId,
    _Out_ CXPLAT_PICOTLS_SIGNATURE_ALGORITHM* Algorithm,
    _Out_ BOOLEAN* Supported
    )
{
    CXPLAT_DER Oid;
    CxPlatZeroMemory(Algorithm, sizeof(*Algorithm));
    *Supported = FALSE;

    if (!DerExpect(&AlgorithmId, DER_OID, &Oid)) {
        return FALSE;
    }

    *Supported = TRUE;
    if (DER_IS_OID(&Oid, OidSha256WithRsa)) {
        Algorithm->Hash = CXPLAT_PICOTLS_HASH_SHA256;
        Algorithm->Padding = CXPLAT_PICOTLS_PADDING_RSA_PKCS1;
    } else if (DER_IS_OID(&Oid, OidSha384WithRsa)) {
        Algorithm->Hash = CXPLAT_PICOTLS_HASH_SHA384;
        Algorithm->Padding = CXPLAT_PICOTLS_PADDING_RSA_PKCS1;
    } else if (DER_IS_OID(&Oid, OidSha512WithRsa)) {
        Algorithm->Hash = CXPLAT_PICOTLS_HASH_SHA512;
        Algorithm->Padding = CXPLAT_PICOTLS_PADDING_RSA_PKCS1;
    } else if (DER_IS_OID(&Oid, OidEcdsaWithSha256)) {
        Algorithm->Hash = CXPLAT_PICOTLS_HASH_SHA256;
        Algorithm->Padding = CXPLAT_PICOTLS_PADDING_ECDSA;
    } else if (DER_IS_OID(&Oid, OidEcdsaWithSha384)) {
        Algorithm->Hash = CXPLAT_PICOTLS_HASH_SHA384;
        Algorithm->Padding = CXPLAT_PICOTLS_PADDING_ECDSA;
    } else if (DER_IS_OID(&Oid, OidEcdsaWithSha512)) {
        Algorithm->Hash = CXPLAT_PICOTLS_HASH_SHA512;
        Algorithm->Padding = CXPLAT_PICOTLS_PADDING_ECDSA;
    } else if (DER_IS_OID(&Oid, OidRsassaPss)) {
        CXPLAT_DER Params;
        if (!DerExpect(&AlgorithmId, DER_SEQUENCE, &Params)) {
            return FALSE;
        }
        *Supported = ReadPssParams(Params, Algorithm);
        return TRUE;
    } else {
        *Supported = FALSE;
        return TRUE;
    }

    //
    // The RSA algorithms have NULL parameters (which some encoders omit), the
    // ECDSA ones none.
    //
    CXPLAT_DER Null;
    if (Algorithm->Padding == CXPLAT_PICOTLS_PADDING_RSA_PKCS1 &&
        DerExpect(&AlgorithmId, DER_NULL, &Null) && Null.Length != 0) {
        return FALSE;
    }
    return AlgorithmId.Length == 0;
}

//
// Reads a SubjectPublicKeyInfo. Returns FALSE if it's malformed; Supported
// tells whether the key is one that can be used.
//
static
BOOLEAN
ReadPublicKey(
    _In_ CXPLAT_DER Spki,
    _Out_ CXPLAT_PICOTLS_PUBLIC_KEY* Key,
    _Out_ BOOLEAN* Supported
    )
{
    CXPLAT_DER AlgorithmId, Oid, KeyBits;
    CxPlatZeroMemory(Key, sizeof(*Key));
    *Supported = FALSE;

    if (!DerExpect(&Spki, DER_SEQUENCE, &AlgorithmId) ||
        !DerExpect(&AlgorithmId, DER_OID, &Oid) ||
        !DerExpect(&Spki, DER_BIT_STRING, &KeyBits) ||
        Spki.Length != 0 ||
        KeyBits.Length < 1 ||
        KeyBits.Data[0] != 0) { // No unused bits.
        return FALSE;
    }
    KeyBits.Data++;
    KeyBits.Length--;

    if (DER_IS_OID(&Oid, OidRsaEncryption)) {
        CXPLAT_DER RsaKey;
        if (!DerExpect(&KeyBits, DER_SEQUENCE, &RsaKey) ||
            !DerBigInteger(&RsaKey, &Key->Modulus) ||
            !DerBigInteger(&RsaKey, &Key->PublicExponent) ||
            RsaKey.Length != 0) {
            return FALSE;
        }
        Key->Type = CXPLAT_PICOTLS_KEY_RSA;
        //
        // RSA keys from 2048 to 16384 bits, with exponents of at most 64 bits.
        //
        *Supported =
            (BOOLEAN)(Key->Modulus.len >= 256 && Key->Modulus.len <= 2048 &&
                      Key->PublicExponent.len <= 8);
        return TRUE;
    }

    if (DER_IS_OID(&Oid, OidEcPublicKey)) {
        CXPLAT_DER Curve;
        if (!DerExpect(&AlgorithmId, DER_OID, &Curve)) {
            return TRUE; // Explicit curve parameters: not supported.
        }
        Key->Type = CXPLAT_PICOTLS_KEY_EC;
        if (DER_IS_OID(&Curve, OidPrime256v1)) {
            Key->CurveBits = 256;
        } else if (DER_IS_OID(&Curve, OidSecp384r1)) {
            Key->CurveBits = 384;
        } else if (DER_IS_OID(&Curve, OidSecp521r1)) {
            Key->CurveBits = 521;
        } else {
            return TRUE;
        }
        Key->PublicPoint = ToIovec(&KeyBits);
        const size_t FieldLength = (Key->CurveBits + 7) / 8;
        *Supported =
            (BOOLEAN)(KeyBits.Length == 1 + 2 * FieldLength &&
                      KeyBits.Data[0] == 0x04); // Uncompressed.
        return TRUE;
    }

    return TRUE;
}

//
// Extensions.
//

static
BOOLEAN
ReadBasicConstraints(
    _In_ CXPLAT_DER Value,
    _Inout_ CXPLAT_PICOTLS_X509* Certificate
    )
{
    CXPLAT_DER Constraints, Field;
    if (!DerExpect(&Value, DER_SEQUENCE, &Constraints) || Value.Length != 0) {
        return FALSE;
    }
    Certificate->HasBasicConstraints = TRUE;
    if (DerExpect(&Constraints, DER_BOOLEAN, &Field)) {
        if (Field.Length != 1) {
            return FALSE;
        }
        Certificate->IsCa = (BOOLEAN)(Field.Data[0] != 0);
    }
    if (DerPeek(&Constraints, DER_INTEGER)) {
        uint32_t PathLength;
        if (!DerUint32(&Constraints, &PathLength)) {
            return FALSE;
        }
        Certificate->PathLength = PathLength > 0x7FFFFFFF ? 0x7FFFFFFF : (int32_t)PathLength;
    }
    return Constraints.Length == 0;
}

static
BOOLEAN
ReadKeyUsage(
    _In_ CXPLAT_DER Value,
    _Inout_ CXPLAT_PICOTLS_X509* Certificate
    )
{
    CXPLAT_DER Bits;
    if (!DerExpect(&Value, DER_BIT_STRING, &Bits) || Value.Length != 0 || Bits.Length < 1) {
        return FALSE;
    }
    Certificate->HasKeyUsage = TRUE;
    Certificate->KeyUsage = Bits.Length >= 2 ? Bits.Data[1] : (uint8_t)0;
    return TRUE;
}

static
BOOLEAN
ReadExtendedKeyUsage(
    _In_ CXPLAT_DER Value,
    _Inout_ CXPLAT_PICOTLS_X509* Certificate
    )
{
    CXPLAT_DER Usages, Oid;
    if (!DerExpect(&Value, DER_SEQUENCE, &Usages) || Value.Length != 0) {
        return FALSE;
    }
    Certificate->HasExtendedKeyUsage = TRUE;
    while (Usages.Length != 0) {
        if (!DerExpect(&Usages, DER_OID, &Oid)) {
            return FALSE;
        }
        if (DER_IS_OID(&Oid, OidServerAuth) || DER_IS_OID(&Oid, OidAnyExtendedKeyUsage)) {
            Certificate->ServerAuth = TRUE;
        }
    }
    return TRUE;
}

static
BOOLEAN
ReadExtensions(
    _In_ CXPLAT_DER Extensions,
    _Inout_ CXPLAT_PICOTLS_X509* Certificate
    )
{
    while (Extensions.Length != 0) {
        CXPLAT_DER Extension, Oid, Critical, Value;
        BOOLEAN IsCritical = FALSE;
        if (!DerExpect(&Extensions, DER_SEQUENCE, &Extension) ||
            !DerExpect(&Extension, DER_OID, &Oid)) {
            return FALSE;
        }
        if (DerExpect(&Extension, DER_BOOLEAN, &Critical)) {
            if (Critical.Length != 1) {
                return FALSE;
            }
            IsCritical = (BOOLEAN)(Critical.Data[0] != 0);
        }
        if (!DerExpect(&Extension, DER_OCTET_STRING, &Value) || Extension.Length != 0) {
            return FALSE;
        }

        BOOLEAN Ok = TRUE;
        if (DER_IS_OID(&Oid, OidBasicConstraints)) {
            Ok = (BOOLEAN)(!Certificate->HasBasicConstraints && ReadBasicConstraints(Value, Certificate));
        } else if (DER_IS_OID(&Oid, OidKeyUsage)) {
            Ok = (BOOLEAN)(!Certificate->HasKeyUsage && ReadKeyUsage(Value, Certificate));
        } else if (DER_IS_OID(&Oid, OidExtendedKeyUsage)) {
            Ok = (BOOLEAN)(!Certificate->HasExtendedKeyUsage && ReadExtendedKeyUsage(Value, Certificate));
        } else if (DER_IS_OID(&Oid, OidSubjectAltName)) {
            CXPLAT_DER Names = { NULL, 0 };
            Ok =
                (BOOLEAN)(!Certificate->HasSubjectAltName &&
                          DerExpect(&Value, DER_SEQUENCE, &Names) &&
                          Value.Length == 0);
            if (Ok) {
                Certificate->HasSubjectAltName = TRUE;
                Certificate->SubjectAltName = ToIovec(&Names);
            }
        } else if (IsCritical && !DER_IS_OID(&Oid, OidCertificatePolicies)) {
            Certificate->UnhandledCriticalExtension = TRUE;
        }
        if (!Ok) {
            return FALSE;
        }
    }
    return TRUE;
}

QUIC_STATUS
CxPlatPicotlsParseCertificate(
    _In_reads_bytes_(Length) const uint8_t* Der,
    _In_ size_t Length,
    _Out_ CXPLAT_PICOTLS_X509* Certificate
    )
{
    CXPLAT_DER In = { Der, Length };
    CXPLAT_DER Cert, Tbs, TbsWhole, Field, Whole, OuterAlgorithm, InnerAlgorithm;
    uint8_t Tag;

    CxPlatZeroMemory(Certificate, sizeof(*Certificate));
    Certificate->PathLength = -1;

    if (!DerRead(&In, &Tag, &Cert, &Whole) || Tag != DER_SEQUENCE || In.Length != 0) {
        return Malformed("Certificate isn't a DER SEQUENCE");
    }
    Certificate->Der = ToIovec(&Whole);

    if (!DerRead(&Cert, &Tag, &Tbs, &TbsWhole) || Tag != DER_SEQUENCE ||
        !DerRead(&Cert, &Tag, &OuterAlgorithm, &Whole) || Tag != DER_SEQUENCE ||
        !DerExpect(&Cert, DER_BIT_STRING, &Field) ||
        Cert.Length != 0 ||
        Field.Length < 1 || Field.Data[0] != 0) {
        return Malformed("Invalid Certificate");
    }
    Certificate->TbsCertificate = ToIovec(&TbsWhole);
    Certificate->Signature = ptls_iovec_init(Field.Data + 1, Field.Length - 1);
    const ptls_iovec_t OuterAlgorithmWhole = ToIovec(&Whole);
    if (!ReadSignatureAlgorithm(
            OuterAlgorithm,
            &Certificate->SignatureAlgorithm,
            &Certificate->SignatureSupported)) {
        return Malformed("Invalid certificate signature algorithm");
    }

    //
    // TBSCertificate.
    //
    uint32_t Version = 0; // v1
    if (DerExpect(&Tbs, DER_CONTEXT_0, &Field)) {
        if (!DerUint32(&Field, &Version) || Field.Length != 0 || Version > 2) {
            return Malformed("Invalid certificate version");
        }
    }
    if (!DerExpect(&Tbs, DER_INTEGER, &Field) ||                        // serialNumber
        !DerRead(&Tbs, &Tag, &InnerAlgorithm, &Whole) || Tag != DER_SEQUENCE ||
        !IovecEqual(ToIovec(&Whole), OuterAlgorithmWhole)) {
        return Malformed("Invalid certificate serial number or signature");
    }
    if (!DerRead(&Tbs, &Tag, &Field, &Whole) || Tag != DER_SEQUENCE) {
        return Malformed("Invalid certificate issuer");
    }
    Certificate->Issuer = ToIovec(&Whole);
    CXPLAT_DER Validity;
    if (!DerExpect(&Tbs, DER_SEQUENCE, &Validity) ||
        !ReadTime(&Validity, &Certificate->NotBefore) ||
        !ReadTime(&Validity, &Certificate->NotAfter) ||
        Validity.Length != 0) {
        return Malformed("Invalid certificate validity");
    }
    if (!DerRead(&Tbs, &Tag, &Field, &Whole) || Tag != DER_SEQUENCE) {
        return Malformed("Invalid certificate subject");
    }
    Certificate->Subject = ToIovec(&Whole);
    if (!DerExpect(&Tbs, DER_SEQUENCE, &Field) ||
        !ReadPublicKey(Field, &Certificate->PublicKey, &Certificate->PublicKeySupported)) {
        return Malformed("Invalid certificate public key");
    }

    //
    // issuerUniqueID [1] and subjectUniqueID [2] are IMPLICIT BIT STRINGs.
    //
    if (Version >= 1) {
        if (DerPeek(&Tbs, 0x81) && !DerExpect(&Tbs, 0x81, &Field)) {
            return Malformed("Invalid certificate issuer unique ID");
        }
        if (DerPeek(&Tbs, 0x82) && !DerExpect(&Tbs, 0x82, &Field)) {
            return Malformed("Invalid certificate subject unique ID");
        }
    }
    if (Version == 2 && DerExpect(&Tbs, DER_CONTEXT_3, &Field)) {
        CXPLAT_DER Extensions;
        if (!DerExpect(&Field, DER_SEQUENCE, &Extensions) ||
            Field.Length != 0 ||
            !ReadExtensions(Extensions, Certificate)) {
            return Malformed("Invalid certificate extensions");
        }
    }
    if (Tbs.Length != 0) {
        return Malformed("Trailing data in certificate");
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Names.
//

static
char
ToLowerAscii(
    _In_ char c
    )
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static
BOOLEAN
EqualsIgnoreCase(
    _In_reads_(Length) const char* A,
    _In_reads_(Length) const char* B,
    _In_ size_t Length
    )
{
    for (size_t i = 0; i < Length; ++i) {
        if (ToLowerAscii(A[i]) != ToLowerAscii(B[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

//
// Matches a DNS name from a certificate against the server name. A wildcard is
// only allowed as the whole left-most label ("*.example.com"), and stands for
// exactly one label.
//
static
BOOLEAN
DnsNameMatches(
    _In_reads_(PatternLength) const char* Pattern,
    _In_ size_t PatternLength,
    _In_reads_(NameLength) const char* Name,
    _In_ size_t NameLength,
    _In_ BOOLEAN AllowWildcard
    )
{
    if (PatternLength > 0 && Pattern[PatternLength - 1] == '.') {
        PatternLength--;
    }
    if (PatternLength == 0) {
        return FALSE;
    }
    for (size_t i = 0; i < PatternLength; ++i) {
        if (Pattern[i] == '\0') {
            return FALSE; // Embedded NUL.
        }
    }

    if (PatternLength == NameLength && EqualsIgnoreCase(Pattern, Name, NameLength)) {
        return TRUE;
    }

    if (!AllowWildcard ||
        PatternLength < 3 || Pattern[0] != '*' || Pattern[1] != '.') {
        return FALSE;
    }
    //
    // The rest of the pattern must hold at least two labels ("*.com" doesn't
    // count), and no other wildcard.
    //
    const char* Suffix = Pattern + 1; // ".example.com"
    const size_t SuffixLength = PatternLength - 1;
    BOOLEAN HasInnerDot = FALSE;
    for (size_t i = 1; i < SuffixLength; ++i) {
        if (Suffix[i] == '*') {
            return FALSE;
        }
        if (Suffix[i] == '.') {
            HasInnerDot = TRUE;
        }
    }
    if (!HasInnerDot || NameLength <= SuffixLength) {
        return FALSE;
    }
    const size_t LabelLength = NameLength - SuffixLength;
    for (size_t i = 0; i < LabelLength; ++i) {
        if (Name[i] == '.') {
            return FALSE;
        }
    }
    return EqualsIgnoreCase(Name + LabelLength, Suffix, SuffixLength);
}

static
int
HexDigit(
    _In_ char c
    )
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static
BOOLEAN
ParseIpv4(
    _In_reads_(Length) const char* Text,
    _In_ size_t Length,
    _Out_writes_(4) uint8_t* Address
    )
{
    size_t Part = 0, i = 0;
    CxPlatZeroMemory(Address, 4);
    while (Part < 4) {
        uint32_t Value = 0;
        size_t Digits = 0;
        while (i < Length && Text[i] >= '0' && Text[i] <= '9') {
            if (Digits == 3 || (Digits == 1 && Value == 0)) {
                return FALSE; // Too long, or a leading zero.
            }
            Value = Value * 10 + (uint32_t)(Text[i] - '0');
            Digits++;
            i++;
        }
        if (Digits == 0 || Value > 255) {
            return FALSE;
        }
        Address[Part++] = (uint8_t)Value;
        if (Part < 4) {
            if (i == Length || Text[i] != '.') {
                return FALSE;
            }
            i++;
        }
    }
    return i == Length;
}

static
BOOLEAN
ParseIpv6(
    _In_reads_(Length) const char* Text,
    _In_ size_t Length,
    _Out_writes_(16) uint8_t* Address
    )
{
    const size_t NO_GAP = (size_t)-1;
    uint16_t Groups[8] = { 0 };
    size_t GroupCount = 0;
    size_t GapAt = NO_GAP;
    size_t i = 0;

    CxPlatZeroMemory(Address, 16);
    if (Length >= 2 && Text[0] == ':' && Text[1] == ':') {
        GapAt = 0;
        i = 2;
    } else if (Length == 0 || Text[0] == ':') {
        return FALSE;
    }

    while (i < Length) {
        if (GroupCount == 8) {
            return FALSE;
        }
        uint32_t Value = 0;
        size_t Digits = 0;
        while (i < Length && HexDigit(Text[i]) >= 0) {
            if (Digits == 4) {
                return FALSE;
            }
            Value = (Value << 4) | (uint32_t)HexDigit(Text[i]);
            Digits++;
            i++;
        }
        if (Digits == 0) {
            return FALSE;
        }
        Groups[GroupCount++] = (uint16_t)Value;
        if (i >= Length) {
            break;
        }
        if (Text[i] != ':') {
            return FALSE;
        }
        i++;
        if (i < Length && Text[i] == ':') {
            if (GapAt != NO_GAP) {
                return FALSE; // Two "::".
            }
            GapAt = GroupCount;
            i++;
        } else if (i == Length) {
            return FALSE; // Trailing single ':'.
        }
    }

    if (GapAt == NO_GAP) {
        if (GroupCount != 8) {
            return FALSE;
        }
        GapAt = 8;
    } else if (GroupCount == 8) {
        return FALSE;
    }
    if (GapAt > GroupCount || GroupCount > 8) {
        return FALSE;
    }
    const size_t Tail = GroupCount - GapAt;
    for (size_t g = 0; g < GapAt && g < 8; ++g) {
        Address[2 * g] = (uint8_t)(Groups[g] >> 8);
        Address[2 * g + 1] = (uint8_t)Groups[g];
    }
    for (size_t g = 0; g < Tail && GapAt + g < 8; ++g) {
        const size_t To = 8 - Tail + g;
        Address[2 * To] = (uint8_t)(Groups[GapAt + g] >> 8);
        Address[2 * To + 1] = (uint8_t)Groups[GapAt + g];
    }
    return TRUE;
}

//
// The value of the last common name in a Name, which is the most specific one.
//
static
BOOLEAN
LastCommonName(
    _In_ ptls_iovec_t Name,
    _Out_ CXPLAT_DER* CommonName
    )
{
    CXPLAT_DER In = { Name.base, Name.len };
    CXPLAT_DER Rdns, Rdn, Attribute, Oid, Value;
    uint8_t Tag;
    BOOLEAN Found = FALSE;

    CommonName->Data = NULL;
    CommonName->Length = 0;
    if (!DerExpect(&In, DER_SEQUENCE, &Rdns)) {
        return FALSE;
    }
    while (Rdns.Length != 0) {
        if (!DerExpect(&Rdns, DER_SET, &Rdn)) {
            return FALSE;
        }
        while (Rdn.Length != 0) {
            if (!DerExpect(&Rdn, DER_SEQUENCE, &Attribute) ||
                !DerExpect(&Attribute, DER_OID, &Oid) ||
                !DerRead(&Attribute, &Tag, &Value, NULL)) {
                return FALSE;
            }
            if (DER_IS_OID(&Oid, OidCommonName) &&
                (Tag == DER_UTF8_STRING || Tag == DER_PRINTABLE_STRING ||
                 Tag == DER_IA5_STRING || Tag == DER_T61_STRING)) {
                *CommonName = Value;
                Found = TRUE;
            }
        }
    }
    return Found;
}

BOOLEAN
CxPlatPicotlsCertificateMatchesName(
    _In_ const CXPLAT_PICOTLS_X509* Certificate,
    _In_z_ const char* ServerName
    )
{
    size_t NameLength = strlen(ServerName);
    uint8_t Address[16];
    size_t AddressLength = 0;

    if (ParseIpv4(ServerName, NameLength, Address)) {
        AddressLength = 4;
    } else if (ParseIpv6(ServerName, NameLength, Address)) {
        AddressLength = 16;
    } else if (NameLength > 0 && ServerName[NameLength - 1] == '.') {
        NameLength--; // A fully qualified name.
    }
    if (NameLength == 0) {
        return FALSE;
    }

    if (Certificate->HasSubjectAltName) {
        CXPLAT_DER Names = { Certificate->SubjectAltName.base, Certificate->SubjectAltName.len };
        while (Names.Length != 0) {
            uint8_t Tag;
            CXPLAT_DER Value;
            if (!DerRead(&Names, &Tag, &Value, NULL)) {
                return FALSE;
            }
            if (Tag == GENERAL_NAME_IP) {
                if (AddressLength != 0 &&
                    Value.Length == AddressLength &&
                    memcmp(Value.Data, Address, AddressLength) == 0) {
                    return TRUE;
                }
            } else if (Tag == GENERAL_NAME_DNS) {
                //
                // An address is also accepted as a DNS name spelled the same,
                // as Windows does; never through a wildcard.
                //
                if (DnsNameMatches(
                        (const char*)Value.Data, Value.Length,
                        ServerName, NameLength,
                        AddressLength == 0)) {
                    return TRUE;
                }
            }
        }
        return FALSE;
    }

    CXPLAT_DER CommonName;
    return
        LastCommonName(Certificate->Subject, &CommonName) &&
        DnsNameMatches(
            (const char*)CommonName.Data, CommonName.Length,
            ServerName, NameLength,
            AddressLength == 0);
}

//
// Chain building.
//

static
BOOLEAN
IsDisallowed(
    _In_ const CXPLAT_PICOTLS_TRUST_STORE* TrustStore,
    _In_ const CXPLAT_PICOTLS_X509* Certificate
    )
{
    for (size_t i = 0; i < TrustStore->DisallowedCount; ++i) {
        if (IovecEqual(TrustStore->Disallowed[i], Certificate->Der)) {
            return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
IsTimeValid(
    _In_ const CXPLAT_PICOTLS_X509* Certificate,
    _In_ int64_t Now
    )
{
    return Certificate->NotBefore <= Now && Now <= Certificate->NotAfter;
}

//
// Whether Issuer may have issued Subject, with IntermediateCount certificates
// below Issuer, not counting the leaf, and signed it.
//
static
BOOLEAN
IsIssuer(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ const CXPLAT_PICOTLS_X509* Issuer,
    _In_ BOOLEAN IsAnchor,
    _In_ const CXPLAT_PICOTLS_X509* Subject,
    _In_ size_t IntermediateCount
    )
{
    if (!IovecEqual(Issuer->Subject, Subject->Issuer)) {
        return FALSE;
    }

    //
    // A CA must say it is one; only a trust anchor may be a v1 certificate,
    // which has no extensions to say so.
    //
    if (Issuer->HasBasicConstraints ? !Issuer->IsCa : !IsAnchor) {
        return FALSE;
    }
    if (Issuer->HasKeyUsage &&
        !(Issuer->KeyUsage & CXPLAT_PICOTLS_KEY_USAGE_KEY_CERT_SIGN)) {
        return FALSE;
    }
    if (Issuer->PathLength >= 0 && IntermediateCount > (size_t)Issuer->PathLength) {
        return FALSE;
    }

    if (!Issuer->PublicKeySupported || !Subject->SignatureSupported) {
        return FALSE;
    }
    return
        QUIC_SUCCEEDED(
            CxPlatPicotlsCryptoVerifySignature(
                Crypto,
                &Issuer->PublicKey,
                &Subject->SignatureAlgorithm,
                Subject->TbsCertificate.base,
                Subject->TbsCertificate.len,
                Subject->Signature.base,
                Subject->Signature.len));
}

int
CxPlatPicotlsVerifyChain(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ const CXPLAT_PICOTLS_TRUST_STORE* TrustStore,
    _In_reads_(CertificateCount) const ptls_iovec_t* Certificates,
    _In_ size_t CertificateCount,
    _In_opt_z_ const char* ServerName,
    _In_ int64_t Now
    )
{
    CXPLAT_PICOTLS_X509 Chain[2];
    CXPLAT_PICOTLS_X509* Current = &Chain[0];
    CXPLAT_PICOTLS_X509* Next = &Chain[1];
    uint32_t Used = 1; // Certificates already in the chain; the leaf.
    BOOLEAN HasExpired = FALSE;

    if (CertificateCount == 0) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    if (CertificateCount > 32) {
        CertificateCount = 32; // Used is a 32-bit mask; picotls takes at most 16.
    }

    if (QUIC_FAILED(
            CxPlatPicotlsParseCertificate(
                Certificates[0].base, Certificates[0].len, Current))) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    //
    // The leaf: the server's name, and usable for TLS server authentication.
    //
    if (ServerName != NULL && !CxPlatPicotlsCertificateMatchesName(Current, ServerName)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Server certificate doesn't match the server name");
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    if ((Current->HasExtendedKeyUsage && !Current->ServerAuth) ||
        (Current->HasKeyUsage &&
         !(Current->KeyUsage & CXPLAT_PICOTLS_KEY_USAGE_DIGITAL_SIGNATURE))) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Server certificate isn't for TLS server authentication");
        return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
    }

    for (size_t Depth = 0; Depth <= CXPLAT_PICOTLS_MAX_CHAIN_DEPTH; ++Depth) {
        if (IsDisallowed(TrustStore, Current)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Certificate in the chain is explicitly distrusted");
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        if (Current->UnhandledCriticalExtension) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Certificate in the chain has an unsupported critical extension");
            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
        }
        if (!IsTimeValid(Current, Now)) {
            HasExpired = TRUE; // Reported once the chain is known to be trusted.
        }

        //
        // Done if the certificate is itself trusted, or a trust anchor issued it.
        //
        for (size_t i = 0; i < TrustStore->AnchorCount; ++i) {
            const CXPLAT_PICOTLS_X509* Anchor = &TrustStore->Anchors[i];
            if (IovecEqual(Anchor->Der, Current->Der) ||
                IsIssuer(Crypto, Anchor, TRUE, Current, Depth)) {
                if (IsDisallowed(TrustStore, Anchor)) {
                    continue;
                }
                if (HasExpired || !IsTimeValid(Anchor, Now)) {
                    QuicTraceEvent(
                        LibraryError,
                        "[ lib] ERROR, %s.",
                        "Certificate in the chain is expired or not yet valid");
                    return PTLS_ALERT_CERTIFICATE_EXPIRED;
                }
                return 0;
            }
        }

        //
        // Otherwise, move up to the certificate the server sent that issued it.
        //
        size_t i;
        for (i = 1; i < CertificateCount; ++i) {
            if ((Used & (1u << i)) ||
                QUIC_FAILED(
                    CxPlatPicotlsParseCertificate(
                        Certificates[i].base, Certificates[i].len, Next))) {
                continue;
            }
            if (IsIssuer(Crypto, Next, FALSE, Current, Depth)) {
                break;
            }
        }
        if (i == CertificateCount) {
            break;
        }
        Used |= 1u << i;
        CXPLAT_PICOTLS_X509* Swap = Current;
        Current = Next;
        Next = Swap;
    }

    QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        "Server certificate chain doesn't lead to a trusted root");
    return PTLS_ALERT_UNKNOWN_CA;
}
