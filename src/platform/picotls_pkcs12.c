/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    PKCS#12, PKCS#8, PKCS#1, SEC1 and PEM decoding for the picotls TLS
    provider on Windows. See picotls_cert.h.

    Only DER is accepted (no BER indefinite lengths), which is what Windows
    (PFXExportCertStoreEx) and OpenSSL produce.

--*/

#include "platform_internal.h"
#include "picotls_cert.h"
#ifdef QUIC_CLOG
#include "picotls_pkcs12.c.clog.h"
#endif

//
// The most certificates a credential may hold.
//
#define CXPLAT_PICOTLS_MAX_CERTIFICATES 32

//
// Silences a code analysis warning the analyzer can't see is wrong.
//
#ifdef _MSC_VER
#define ANALYSIS_SUPPRESS(Warnings) __pragma(warning(suppress:Warnings))
#else
#define ANALYSIS_SUPPRESS(Warnings)
#endif

//
// DER reading.
//

#define DER_INTEGER             0x02
#define DER_BIT_STRING          0x03
#define DER_OCTET_STRING        0x04
#define DER_NULL                0x05
#define DER_OID                 0x06
#define DER_SEQUENCE            0x30
#define DER_SET                 0x31
#define DER_CONTEXT_0           0xA0    // [0], constructed
#define DER_CONTEXT_1           0xA1    // [1], constructed
#define DER_CONTEXT_0_PRIMITIVE 0x80    // [0] IMPLICIT, primitive

typedef struct CXPLAT_DER {
    const uint8_t* Data;
    size_t Length;
} CXPLAT_DER;

//
// Reads one TLV. Value receives the contents, and Whole (if given) the whole
// encoding including tag and length.
//
static
BOOLEAN
DerRead(
    _Inout_ CXPLAT_DER* In,
    _Out_ uint8_t* Tag,
    _Out_ CXPLAT_DER* Value,
    _Out_opt_ CXPLAT_DER* Whole
    )
{
    *Tag = 0;
    Value->Data = NULL;
    Value->Length = 0;
    if (Whole != NULL) {
        Whole->Data = NULL;
        Whole->Length = 0;
    }

    if (In->Length < 2 || (In->Data[0] & 0x1F) == 0x1F) {
        return FALSE; // Truncated, or a high tag number, which isn't used here.
    }

    size_t Offset = 2;
    size_t Length = In->Data[1];
    if (Length & 0x80) {
        size_t Count = Length & 0x7F;
        if (Count == 0 || Count > 4 || In->Length < 2 + Count) {
            return FALSE; // Indefinite (BER), too large, or truncated.
        }
        Length = 0;
        for (size_t i = 0; i < Count; ++i) {
            Length = (Length << 8) | In->Data[2 + i];
        }
        Offset += Count;
    }
    if (Length > In->Length - Offset) {
        return FALSE;
    }

    *Tag = In->Data[0];
    Value->Data = In->Data + Offset;
    Value->Length = Length;
    if (Whole != NULL) {
        Whole->Data = In->Data;
        Whole->Length = Offset + Length;
    }
    In->Data += Offset + Length;
    In->Length -= Offset + Length;
    return TRUE;
}

//
// Reads one TLV that must have tag Tag. In is left as it was on failure.
//
static
BOOLEAN
DerExpect(
    _Inout_ CXPLAT_DER* In,
    _In_ uint8_t Tag,
    _Out_ CXPLAT_DER* Value
    )
{
    CXPLAT_DER Copy = *In;
    uint8_t ActualTag;
    if (!DerRead(&Copy, &ActualTag, Value, NULL) || ActualTag != Tag) {
        Value->Data = NULL;
        Value->Length = 0;
        return FALSE;
    }
    *In = Copy;
    return TRUE;
}

static
BOOLEAN
DerPeek(
    _In_ const CXPLAT_DER* In,
    _In_ uint8_t Tag
    )
{
    return In->Length > 0 && In->Data[0] == Tag;
}

//
// Reads a non-negative INTEGER that fits in 32 bits.
//
static
BOOLEAN
DerUint32(
    _Inout_ CXPLAT_DER* In,
    _Out_ uint32_t* Value
    )
{
    CXPLAT_DER Integer;
    *Value = 0;
    if (!DerExpect(In, DER_INTEGER, &Integer) ||
        Integer.Length == 0 ||
        (Integer.Data[0] & 0x80)) {
        return FALSE;
    }
    while (Integer.Length > 1 && Integer.Data[0] == 0) {
        Integer.Data++;
        Integer.Length--;
    }
    if (Integer.Length > 4) {
        return FALSE;
    }
    uint32_t Result = 0;
    for (size_t i = 0; i < Integer.Length; ++i) {
        Result = (Result << 8) | Integer.Data[i];
    }
    *Value = Result;
    return TRUE;
}

//
// Reads a positive INTEGER of any size, without its leading zero bytes.
//
static
BOOLEAN
DerBigInteger(
    _Inout_ CXPLAT_DER* In,
    _Out_ ptls_iovec_t* Value
    )
{
    CXPLAT_DER Integer;
    *Value = ptls_iovec_init(NULL, 0);
    if (!DerExpect(In, DER_INTEGER, &Integer) ||
        Integer.Length == 0 ||
        (Integer.Data[0] & 0x80)) {
        return FALSE;
    }
    while (Integer.Length > 0 && Integer.Data[0] == 0) {
        Integer.Data++;
        Integer.Length--;
    }
    if (Integer.Length == 0) {
        return FALSE;
    }
    *Value = ptls_iovec_init(Integer.Data, Integer.Length);
    return TRUE;
}

static
BOOLEAN
DerIsOid(
    _In_ const CXPLAT_DER* Oid,
    _In_reads_bytes_(ExpectedLength) const uint8_t* Expected,
    _In_ size_t ExpectedLength
    )
{
    return
        Oid->Length == ExpectedLength &&
        memcmp(Oid->Data, Expected, ExpectedLength) == 0;
}

#define DER_IS_OID(Oid, Expected) DerIsOid(Oid, Expected, sizeof(Expected))

//
// Object identifiers, as the contents of their DER encoding.
//

static const uint8_t OidData[] =                { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
static const uint8_t OidEncryptedData[] =       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06 };
static const uint8_t OidKeyBag[] =              { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01 };
static const uint8_t OidShroudedKeyBag[] =      { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02 };
static const uint8_t OidCertBag[] =             { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x03 };
static const uint8_t OidSafeContentsBag[] =     { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x06 };
static const uint8_t OidX509Certificate[] =     { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x16, 0x01 };
static const uint8_t OidLocalKeyId[] =          { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x15 };
static const uint8_t OidPbeSha3Des[] =          { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03 };
static const uint8_t OidPbeSha40BitRc2[] =      { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x06 };
static const uint8_t OidPbes2[] =               { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };
static const uint8_t OidPbkdf2[] =              { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };
static const uint8_t OidPbmac1[] =              { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0E };
static const uint8_t OidHmacSha1[] =            { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07 };
static const uint8_t OidHmacSha256[] =          { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09 };
static const uint8_t OidHmacSha384[] =          { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A };
static const uint8_t OidHmacSha512[] =          { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B };
static const uint8_t OidAes128Cbc[] =           { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
static const uint8_t OidAes192Cbc[] =           { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16 };
static const uint8_t OidAes256Cbc[] =           { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A };
static const uint8_t OidDesEde3Cbc[] =          { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07 };
static const uint8_t OidSha1[] =                { 0x2B, 0x0E, 0x03, 0x02, 0x1A };
static const uint8_t OidSha256[] =              { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const uint8_t OidSha384[] =              { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const uint8_t OidSha512[] =              { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
static const uint8_t OidRsaEncryption[] =       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const uint8_t OidEcPublicKey[] =         { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t OidPrime256v1[] =          { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OidSecp384r1[] =           { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OidSecp521r1[] =           { 0x2B, 0x81, 0x04, 0x00, 0x23 };

//
// Helpers.
//

void
CxPlatPicotlsSecureZero(
    _Out_writes_bytes_all_(Length) void* Buffer,
    _In_ size_t Length
    )
{
    volatile uint8_t* Cursor = (volatile uint8_t*)Buffer;
    while (Length-- > 0) {
        *Cursor++ = 0;
    }
}

static
void
FreeSecret(
    _In_opt_ uint8_t* Buffer,
    _In_ size_t Length
    )
{
    if (Buffer != NULL) {
        CxPlatPicotlsSecureZero(Buffer, Length);
        CXPLAT_FREE(Buffer, QUIC_POOL_TLS_PFX);
    }
}

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
QUIC_STATUS
Unsupported(
    _In_z_ const char* What
    )
{
    QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        What);
    return QUIC_STATUS_NOT_SUPPORTED;
}

static
uint8_t*
AllocCopy(
    _In_reads_bytes_(Length) const uint8_t* Data,
    _In_ size_t Length,
    _In_ uint32_t Tag,
    _In_z_ const char* What
    )
{
    uint8_t* Copy = CXPLAT_ALLOC_NONPAGED(Length == 0 ? 1 : Length, Tag);
    if (Copy == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            What,
            (uint64_t)Length);
        return NULL;
    }
    if (Length != 0) {
        memcpy(Copy, Data, Length);
    }
    return Copy;
}

void
CxPlatPicotlsFreeCertificates(
    _In_reads_opt_(Count) ptls_iovec_t* Certificates,
    _In_ size_t Count
    )
{
    if (Certificates == NULL) {
        return;
    }
    for (size_t i = 0; i < Count; ++i) {
        if (Certificates[i].base != NULL) {
ANALYSIS_SUPPRESS(6001) // Every entry below Count is initialized.
            CXPLAT_FREE(Certificates[i].base, QUIC_POOL_TLS_CERT_DER);
        }
    }
    CXPLAT_FREE(Certificates, QUIC_POOL_TLS_CERT_DER);
}

void
CxPlatPicotlsCredentialClear(
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    )
{
    CxPlatPicotlsFreeCertificates(Credential->Certificates, Credential->CertificateCount);
    FreeSecret(Credential->KeyDer, Credential->KeyDerLength);
    CxPlatZeroMemory(Credential, sizeof(*Credential));
}

//
// Appends a copy of Der to Credential->Certificates.
//
static
QUIC_STATUS
AppendCertificate(
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential,
    _In_reads_bytes_(Length) const uint8_t* Der,
    _In_ size_t Length
    )
{
    size_t Count = Credential->CertificateCount;
    if (Count >= CXPLAT_PICOTLS_MAX_CERTIFICATES) {
        return Unsupported("More certificates than supported");
    }
    CXPLAT_ANALYSIS_ASSUME(Count < CXPLAT_PICOTLS_MAX_CERTIFICATES);
    ptls_iovec_t* List =
        CXPLAT_ALLOC_NONPAGED(sizeof(ptls_iovec_t) * (Count + 1), QUIC_POOL_TLS_CERT_DER);
    if (List == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "certificate list",
            (uint64_t)(sizeof(ptls_iovec_t) * (Count + 1)));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    uint8_t* Copy = AllocCopy(Der, Length, QUIC_POOL_TLS_CERT_DER, "DER certificate");
    if (Copy == NULL) {
        CXPLAT_FREE(List, QUIC_POOL_TLS_CERT_DER);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    if (Count != 0) {
ANALYSIS_SUPPRESS(6386) // List holds Count + 1 entries.
        memcpy(List, Credential->Certificates, sizeof(ptls_iovec_t) * Count);
        CXPLAT_FREE(Credential->Certificates, QUIC_POOL_TLS_CERT_DER);
    }
ANALYSIS_SUPPRESS(6386) // List holds Count + 1 entries.
    List[Count] = ptls_iovec_init(Copy, Length);
    Credential->Certificates = List;
    Credential->CertificateCount = Count + 1;
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatPicotlsCredentialAddCertificate(
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential,
    _In_reads_bytes_(Length) const uint8_t* Der,
    _In_ size_t Length
    )
{
    return AppendCertificate(Credential, Der, Length);
}

static
size_t
HashLength(
    _In_ CXPLAT_PICOTLS_HASH Hash
    )
{
    switch (Hash) {
    case CXPLAT_PICOTLS_HASH_SHA1: return 20;
    case CXPLAT_PICOTLS_HASH_SHA256: return 32;
    case CXPLAT_PICOTLS_HASH_SHA384: return 48;
    default: return 64;
    }
}

static
size_t
HashBlockLength(
    _In_ CXPLAT_PICOTLS_HASH Hash
    )
{
    return Hash == CXPLAT_PICOTLS_HASH_SHA1 || Hash == CXPLAT_PICOTLS_HASH_SHA256 ? 64 : 128;
}

//
// Reads an AlgorithmIdentifier whose algorithm is a digest (for the MAC) or an
// HMAC (for the PBKDF2 PRF).
//
static
BOOLEAN
ReadHashAlgorithm(
    _In_ const CXPLAT_DER* Oid,
    _In_ BOOLEAN Hmac,
    _Out_ CXPLAT_PICOTLS_HASH* Hash
    )
{
    *Hash = CXPLAT_PICOTLS_HASH_SHA1;
    if (Hmac ? DER_IS_OID(Oid, OidHmacSha1) : DER_IS_OID(Oid, OidSha1)) {
        *Hash = CXPLAT_PICOTLS_HASH_SHA1;
    } else if (Hmac ? DER_IS_OID(Oid, OidHmacSha256) : DER_IS_OID(Oid, OidSha256)) {
        *Hash = CXPLAT_PICOTLS_HASH_SHA256;
    } else if (Hmac ? DER_IS_OID(Oid, OidHmacSha384) : DER_IS_OID(Oid, OidSha384)) {
        *Hash = CXPLAT_PICOTLS_HASH_SHA384;
    } else if (Hmac ? DER_IS_OID(Oid, OidHmacSha512) : DER_IS_OID(Oid, OidSha512)) {
        *Hash = CXPLAT_PICOTLS_HASH_SHA512;
    } else {
        return FALSE;
    }
    return TRUE;
}

//
// Passwords.
//
// PKCS#12 key derivation (RFC 7292, Appendix B) takes the password as a
// BMPString with a two-byte terminator, PBKDF2 takes its bytes as they are.
// An absent password is empty in both forms, while an empty one is just the
// terminator for PKCS#12.
//

typedef struct CXPLAT_PICOTLS_PASSWORD {
    const uint8_t* Raw;
    size_t RawLength;
    uint8_t* Bmp;
    size_t BmpLength;
} CXPLAT_PICOTLS_PASSWORD;

static
QUIC_STATUS
PasswordInitialize(
    _In_opt_z_ const char* Password,
    _Out_ CXPLAT_PICOTLS_PASSWORD* Result
    )
{
    CxPlatZeroMemory(Result, sizeof(*Result));
    if (Password == NULL) {
        return QUIC_STATUS_SUCCESS;
    }

    const uint8_t* Utf8 = (const uint8_t*)Password;
    size_t Utf8Length = strlen(Password);
    Result->Raw = Utf8;
    Result->RawLength = Utf8Length;

    //
    // UTF-8 never takes fewer bytes than UTF-16 per character, so this is
    // enough room for the BMPString and its terminator.
    //
    Result->Bmp = CXPLAT_ALLOC_NONPAGED(2 * Utf8Length + 2, QUIC_POOL_TLS_PFX);
    if (Result->Bmp == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PKCS#12 password",
            (uint64_t)(2 * Utf8Length + 2));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    size_t Out = 0;
    for (size_t i = 0; i < Utf8Length;) {
        uint32_t CodePoint;
        uint8_t Lead = Utf8[i];
        if (Lead < 0x80) {
            CodePoint = Lead;
            i += 1;
        } else if ((Lead & 0xE0) == 0xC0 && i + 1 < Utf8Length &&
                   (Utf8[i + 1] & 0xC0) == 0x80) {
            CodePoint = ((uint32_t)(Lead & 0x1F) << 6) | (Utf8[i + 1] & 0x3F);
            i += 2;
        } else if ((Lead & 0xF0) == 0xE0 && i + 2 < Utf8Length &&
                   (Utf8[i + 1] & 0xC0) == 0x80 && (Utf8[i + 2] & 0xC0) == 0x80) {
            CodePoint =
                ((uint32_t)(Lead & 0x0F) << 12) |
                ((uint32_t)(Utf8[i + 1] & 0x3F) << 6) |
                (Utf8[i + 2] & 0x3F);
            i += 3;
        } else {
            //
            // Invalid UTF-8, or a character outside the BMP, which a BMPString
            // can't hold.
            //
            FreeSecret(Result->Bmp, 2 * Utf8Length + 2);
            Result->Bmp = NULL;
            return Unsupported("Password is not UTF-8 in the Basic Multilingual Plane");
        }
        CXPLAT_ANALYSIS_ASSUME(Out + 2 <= 2 * Utf8Length);
        Result->Bmp[Out++] = (uint8_t)(CodePoint >> 8);
        Result->Bmp[Out++] = (uint8_t)CodePoint;
    }
    //
    // Each character takes at most as many bytes in UTF-16 as in UTF-8, so
    // Out <= 2 * Utf8Length here.
    //
ANALYSIS_SUPPRESS(6386)
    Result->Bmp[Out++] = 0;
ANALYSIS_SUPPRESS(6386)
    Result->Bmp[Out++] = 0;
    Result->BmpLength = Out;
    return QUIC_STATUS_SUCCESS;
}

static
void
PasswordUninitialize(
    _Inout_ CXPLAT_PICOTLS_PASSWORD* Password
    )
{
    if (Password->Bmp != NULL) {
        //
        // The allocation was 2 * RawLength + 2 bytes; BmpLength never exceeds it.
        //
        FreeSecret(Password->Bmp, Password->BmpLength);
    }
    CxPlatZeroMemory(Password, sizeof(*Password));
}

//
// The PKCS#12 key derivation function, RFC 7292, Appendix B.2. Id is 1 for an
// encryption key, 2 for an IV and 3 for a MAC key.
//
static
QUIC_STATUS
Pkcs12Kdf(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_PICOTLS_HASH Hash,
    _In_ uint8_t Id,
    _In_ const CXPLAT_PICOTLS_PASSWORD* Password,
    _In_reads_bytes_(SaltLength) const uint8_t* Salt,
    _In_ size_t SaltLength,
    _In_ uint32_t Iterations,
    _Out_writes_bytes_(OutputLength) uint8_t* Output,
    _In_ size_t OutputLength
    )
{
    const size_t u = HashLength(Hash);
    const size_t v = HashBlockLength(Hash);
    const size_t SLength = v * ((SaltLength + v - 1) / v);
    const size_t PLength = v * ((Password->BmpLength + v - 1) / v);
    const size_t ILength = SLength + PLength;
    uint8_t A[64];
    uint8_t B[128];
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (Iterations == 0) {
        Iterations = 1;
    }

    //
    // Buffer holds D || I.
    //
    if (u == 0 || v == 0 || SaltLength > 0xFFFF || Password->BmpLength > 0xFFFF) {
        return Unsupported("PKCS#12 KDF parameters");
    }
    const size_t BufferLength = v + ILength;
    uint8_t* Buffer = CXPLAT_ALLOC_NONPAGED(BufferLength, QUIC_POOL_TLS_PFX);
    if (Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PKCS#12 KDF",
            (uint64_t)BufferLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    uint8_t* I = Buffer + v;
ANALYSIS_SUPPRESS(6386) // BufferLength is v + ILength.
    memset(Buffer, Id, v);
    for (size_t i = 0; i < SLength; ++i) {
        I[i] = Salt[i % SaltLength];
    }
    for (size_t i = 0; i < PLength; ++i) {
        I[SLength + i] = Password->Bmp[i % Password->BmpLength];
    }

    while (OutputLength > 0) {
        Status = CxPlatPicotlsCryptoHash(Crypto, Hash, Buffer, BufferLength, A);
        for (uint32_t r = 1; QUIC_SUCCEEDED(Status) && r < Iterations; ++r) {
            Status = CxPlatPicotlsCryptoHash(Crypto, Hash, A, u, A);
        }
        if (QUIC_FAILED(Status)) {
            break;
        }

        size_t Take = OutputLength < u ? OutputLength : u;
        memcpy(Output, A, Take);
        Output += Take;
        OutputLength -= Take;
        if (OutputLength == 0) {
            break;
        }

        //
        // I_j = (I_j + B + 1) mod 2^(8v) for each v-byte block of I, where B
        // is A repeated to v bytes.
        //
        for (size_t i = 0; i < v; ++i) {
            B[i] = A[i % u];
        }
        for (size_t j = 0; j < ILength; j += v) {
            uint32_t Carry = 1;
            for (size_t k = v; k-- > 0;) {
                Carry += (uint32_t)I[j + k] + B[k];
                I[j + k] = (uint8_t)Carry;
                Carry >>= 8;
            }
        }
    }

    CxPlatPicotlsSecureZero(A, sizeof(A));
    CxPlatPicotlsSecureZero(B, sizeof(B));
    FreeSecret(Buffer, BufferLength);
    return Status;
}

//
// Decrypts Data, protected with the password-based scheme described by the
// AlgorithmIdentifier Algorithm. On success *Plaintext (QUIC_POOL_TLS_PFX)
// holds the result without its padding. *BadPassword is set when the result
// doesn't decrypt to valid padding, which is what a wrong password looks like.
//
static
QUIC_STATUS
PbeDecrypt(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_DER Algorithm,
    _In_ const CXPLAT_PICOTLS_PASSWORD* Password,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ size_t DataLength,
    _Outptr_result_buffer_maybenull_(*PlaintextLength) uint8_t** Plaintext,
    _Out_ size_t* PlaintextLength,
    _Out_ BOOLEAN* BadPassword
    )
{
    CXPLAT_DER Oid, Params;
    CXPLAT_PICOTLS_CIPHER Cipher = CXPLAT_PICOTLS_CIPHER_AES_CBC;
    uint8_t Key[32] = {0};
    size_t KeyLength = 0;
    uint8_t Iv[16] = {0};
    size_t IvLength = 0;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    *Plaintext = NULL;
    *PlaintextLength = 0;
    *BadPassword = FALSE;

    if (!DerExpect(&Algorithm, DER_OID, &Oid)) {
        return Malformed("Malformed encryption AlgorithmIdentifier");
    }

    if (DER_IS_OID(&Oid, OidPbeSha3Des)) {
        //
        // pbeWithSHAAnd3-KeyTripleDES-CBC: PKCS12PbeParams.
        //
        CXPLAT_DER Salt;
        uint32_t Iterations;
        if (!DerExpect(&Algorithm, DER_SEQUENCE, &Params) ||
            !DerExpect(&Params, DER_OCTET_STRING, &Salt) ||
            !DerUint32(&Params, &Iterations)) {
            return Malformed("Malformed PKCS12PbeParams");
        }
        Cipher = CXPLAT_PICOTLS_CIPHER_3DES_CBC;
        KeyLength = 24;
        IvLength = 8;
        Status =
            Pkcs12Kdf(
                Crypto, CXPLAT_PICOTLS_HASH_SHA1, 1, Password,
                Salt.Data, Salt.Length, Iterations, Key, KeyLength);
        if (QUIC_SUCCEEDED(Status)) {
            Status =
                Pkcs12Kdf(
                    Crypto, CXPLAT_PICOTLS_HASH_SHA1, 2, Password,
                    Salt.Data, Salt.Length, Iterations, Iv, IvLength);
        }
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

    } else if (DER_IS_OID(&Oid, OidPbes2)) {
        //
        // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
        //
        CXPLAT_DER Kdf, KdfOid, KdfParams, Salt, Scheme, SchemeOid, IvString;
        uint32_t Iterations;
        uint32_t ExplicitKeyLength = 0;
        CXPLAT_PICOTLS_HASH Prf = CXPLAT_PICOTLS_HASH_SHA1;

        if (!DerExpect(&Algorithm, DER_SEQUENCE, &Params) ||
            !DerExpect(&Params, DER_SEQUENCE, &Kdf) ||
            !DerExpect(&Kdf, DER_OID, &KdfOid) ||
            !DerExpect(&Params, DER_SEQUENCE, &Scheme) ||
            !DerExpect(&Scheme, DER_OID, &SchemeOid)) {
            return Malformed("Malformed PBES2-params");
        }
        if (!DER_IS_OID(&KdfOid, OidPbkdf2)) {
            return Unsupported("PBES2 key derivation function other than PBKDF2");
        }

        //
        // PBKDF2-params ::= SEQUENCE { salt, iterationCount, keyLength OPTIONAL,
        //                              prf DEFAULT hmacWithSHA1 }
        //
        if (!DerExpect(&Kdf, DER_SEQUENCE, &KdfParams) ||
            !DerExpect(&KdfParams, DER_OCTET_STRING, &Salt) ||
            !DerUint32(&KdfParams, &Iterations)) {
            return Malformed("Malformed PBKDF2-params");
        }
        if (DerPeek(&KdfParams, DER_INTEGER) &&
            !DerUint32(&KdfParams, &ExplicitKeyLength)) {
            return Malformed("Malformed PBKDF2 keyLength");
        }
        if (DerPeek(&KdfParams, DER_SEQUENCE)) {
            CXPLAT_DER PrfAlgorithm, PrfOid;
            if (!DerExpect(&KdfParams, DER_SEQUENCE, &PrfAlgorithm) ||
                !DerExpect(&PrfAlgorithm, DER_OID, &PrfOid)) {
                return Malformed("Malformed PBKDF2 prf");
            }
            if (!ReadHashAlgorithm(&PrfOid, TRUE, &Prf)) {
                return Unsupported("PBKDF2 PRF");
            }
        }

        if (DER_IS_OID(&SchemeOid, OidAes128Cbc)) {
            Cipher = CXPLAT_PICOTLS_CIPHER_AES_CBC;
            KeyLength = 16;
            IvLength = 16;
        } else if (DER_IS_OID(&SchemeOid, OidAes192Cbc)) {
            Cipher = CXPLAT_PICOTLS_CIPHER_AES_CBC;
            KeyLength = 24;
            IvLength = 16;
        } else if (DER_IS_OID(&SchemeOid, OidAes256Cbc)) {
            Cipher = CXPLAT_PICOTLS_CIPHER_AES_CBC;
            KeyLength = 32;
            IvLength = 16;
        } else if (DER_IS_OID(&SchemeOid, OidDesEde3Cbc)) {
            Cipher = CXPLAT_PICOTLS_CIPHER_3DES_CBC;
            KeyLength = 24;
            IvLength = 8;
        } else {
            return Unsupported("PBES2 encryption scheme");
        }
        if (ExplicitKeyLength != 0 && ExplicitKeyLength != KeyLength) {
            return Malformed("PBKDF2 keyLength doesn't match the cipher");
        }
        if (!DerExpect(&Scheme, DER_OCTET_STRING, &IvString) ||
            IvString.Length != IvLength) {
            return Malformed("Malformed PBES2 IV");
        }
        memcpy(Iv, IvString.Data, IvLength);

        Status =
            CxPlatPicotlsCryptoPbkdf2(
                Crypto,
                Prf,
                Password->Raw, Password->RawLength,
                Salt.Data, Salt.Length,
                Iterations,
                Key, KeyLength);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

    } else if (DER_IS_OID(&Oid, OidPbeSha40BitRc2)) {
        return Unsupported("pbeWithSHAAnd40BitRC2-CBC (use AES or 3DES)");
    } else {
        return Unsupported("Password-based encryption scheme");
    }

    const size_t BlockLength = Cipher == CXPLAT_PICOTLS_CIPHER_AES_CBC ? 16 : 8;
    if (DataLength == 0 || DataLength % BlockLength != 0) {
        Status = Malformed("Encrypted data isn't a whole number of blocks");
        goto Exit;
    }

    uint8_t* Buffer = AllocCopy(Data, DataLength, QUIC_POOL_TLS_PFX, "PKCS#12 decryption");
    if (Buffer == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Status =
        CxPlatPicotlsCryptoCbcDecrypt(
            Crypto, Cipher, Key, KeyLength, Iv, IvLength, Buffer, DataLength);
    if (QUIC_FAILED(Status)) {
        FreeSecret(Buffer, DataLength);
        goto Exit;
    }

    //
    // PKCS#7 padding.
    //
    uint8_t Pad = Buffer[DataLength - 1];
    BOOLEAN PadValid = Pad != 0 && Pad <= BlockLength;
    for (size_t i = 0; PadValid && i < Pad; ++i) {
        PadValid = Buffer[DataLength - 1 - i] == Pad;
    }
    if (!PadValid) {
        FreeSecret(Buffer, DataLength);
        *BadPassword = TRUE;
        Status = Malformed("Decryption failed (wrong password?)");
        goto Exit;
    }

    *Plaintext = Buffer;
    *PlaintextLength = DataLength - Pad;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    CxPlatPicotlsSecureZero(Key, sizeof(Key));
    CxPlatPicotlsSecureZero(Iv, sizeof(Iv));
    return Status;
}

//
// Decrypts an EncryptedPrivateKeyInfo into a PrivateKeyInfo.
//
static
QUIC_STATUS
DecryptPrivateKeyInfo(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_DER EncryptedPrivateKeyInfo,
    _In_ const CXPLAT_PICOTLS_PASSWORD* Password,
    _Outptr_result_buffer_maybenull_(*KeyDerLength) uint8_t** KeyDer,
    _Out_ size_t* KeyDerLength,
    _Out_ BOOLEAN* BadPassword
    )
{
    CXPLAT_DER Sequence, Algorithm, Encrypted;
    *KeyDer = NULL;
    *KeyDerLength = 0;
    *BadPassword = FALSE;
    if (!DerExpect(&EncryptedPrivateKeyInfo, DER_SEQUENCE, &Sequence) ||
        !DerExpect(&Sequence, DER_SEQUENCE, &Algorithm) ||
        !DerExpect(&Sequence, DER_OCTET_STRING, &Encrypted)) {
        return Malformed("Malformed EncryptedPrivateKeyInfo");
    }
    return
        PbeDecrypt(
            Crypto, Algorithm, Password, Encrypted.Data, Encrypted.Length,
            KeyDer, KeyDerLength, BadPassword);
}

//
// PKCS#12.
//

#define PKCS12_MAX_KEY_ID_LENGTH 64
#define PKCS12_MAX_NESTING 4

typedef struct PKCS12_PARSE_STATE {
    const CXPLAT_PICOTLS_PASSWORD* Password;
    CXPLAT_PICOTLS_CRYPTO* Crypto;
    BOOLEAN BadPassword;

    //
    // Certificates in the order found, and the localKeyId of each.
    //
    CXPLAT_PICOTLS_PARSED_CREDENTIAL Found;
    uint8_t (*CertKeyIds)[PKCS12_MAX_KEY_ID_LENGTH];
    uint8_t* CertKeyIdLengths;

    uint8_t KeyId[PKCS12_MAX_KEY_ID_LENGTH];
    uint8_t KeyIdLength;

} PKCS12_PARSE_STATE;

//
// Finds the localKeyId in a SafeBag's bagAttributes.
//
static
void
ReadLocalKeyId(
    _In_ CXPLAT_DER Attributes,
    _Out_writes_bytes_to_(PKCS12_MAX_KEY_ID_LENGTH, *KeyIdLength) uint8_t* KeyId,
    _Out_ uint8_t* KeyIdLength
    )
{
    *KeyIdLength = 0;
    CXPLAT_DER Attribute;
    while (DerExpect(&Attributes, DER_SEQUENCE, &Attribute)) {
        CXPLAT_DER Oid, Values, Value;
        if (DerExpect(&Attribute, DER_OID, &Oid) &&
            DER_IS_OID(&Oid, OidLocalKeyId) &&
            DerExpect(&Attribute, DER_SET, &Values) &&
            DerExpect(&Values, DER_OCTET_STRING, &Value) &&
            Value.Length <= PKCS12_MAX_KEY_ID_LENGTH) {
            memcpy(KeyId, Value.Data, Value.Length);
            *KeyIdLength = (uint8_t)Value.Length;
            return;
        }
    }
}

static
QUIC_STATUS
Pkcs12AddCertificate(
    _Inout_ PKCS12_PARSE_STATE* State,
    _In_ CXPLAT_DER Der,
    _In_reads_bytes_(KeyIdLength) const uint8_t* KeyId,
    _In_ uint8_t KeyIdLength
    )
{
    size_t Count = State->Found.CertificateCount;
    if (Count >= CXPLAT_PICOTLS_MAX_CERTIFICATES || KeyIdLength > PKCS12_MAX_KEY_ID_LENGTH) {
        return Unsupported("More certificates than supported");
    }
    CXPLAT_ANALYSIS_ASSUME(Count < CXPLAT_PICOTLS_MAX_CERTIFICATES);
    uint8_t (*KeyIds)[PKCS12_MAX_KEY_ID_LENGTH] =
        CXPLAT_ALLOC_NONPAGED((Count + 1) * PKCS12_MAX_KEY_ID_LENGTH, QUIC_POOL_TLS_PFX);
    uint8_t* KeyIdLengths = CXPLAT_ALLOC_NONPAGED(Count + 1, QUIC_POOL_TLS_PFX);
    if (KeyIds == NULL || KeyIdLengths == NULL) {
        if (KeyIds != NULL) {
            CXPLAT_FREE(KeyIds, QUIC_POOL_TLS_PFX);
        }
        if (KeyIdLengths != NULL) {
            CXPLAT_FREE(KeyIdLengths, QUIC_POOL_TLS_PFX);
        }
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PKCS#12 key IDs",
            (uint64_t)((Count + 1) * (PKCS12_MAX_KEY_ID_LENGTH + 1)));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    if (Count != 0) {
        memcpy(KeyIds, State->CertKeyIds, Count * PKCS12_MAX_KEY_ID_LENGTH);
ANALYSIS_SUPPRESS(6386) // KeyIdLengths holds Count + 1 entries.
        memcpy(KeyIdLengths, State->CertKeyIdLengths, Count);
        CXPLAT_FREE(State->CertKeyIds, QUIC_POOL_TLS_PFX);
        CXPLAT_FREE(State->CertKeyIdLengths, QUIC_POOL_TLS_PFX);
    }
    State->CertKeyIds = KeyIds;
    State->CertKeyIdLengths = KeyIdLengths;
ANALYSIS_SUPPRESS(6385 6386) // Both arrays hold Count + 1 entries.
    memcpy(KeyIds[Count], KeyId, KeyIdLength);
ANALYSIS_SUPPRESS(6386)
    KeyIdLengths[Count] = KeyIdLength;

    QUIC_STATUS Status = AppendCertificate(&State->Found, Der.Data, Der.Length);
    if (QUIC_FAILED(Status)) {
        //
        // The key ID arrays may now be one longer than the certificate list,
        // which is harmless: only the first CertificateCount entries are read.
        //
        return Status;
    }
    return QUIC_STATUS_SUCCESS;
}

static
QUIC_STATUS
Pkcs12ParseSafeContents(
    _Inout_ PKCS12_PARSE_STATE* State,
    _In_ CXPLAT_DER SafeContents,
    _In_ uint32_t Depth
    );

static
QUIC_STATUS
Pkcs12ParseSafeBag(
    _Inout_ PKCS12_PARSE_STATE* State,
    _In_ CXPLAT_DER Bag,
    _In_ uint32_t Depth
    )
{
    CXPLAT_DER BagId, BagValue, Attributes = {0};
    uint8_t KeyId[PKCS12_MAX_KEY_ID_LENGTH] = {0};
    uint8_t KeyIdLength = 0;

    if (!DerExpect(&Bag, DER_OID, &BagId) ||
        !DerExpect(&Bag, DER_CONTEXT_0, &BagValue)) {
        return Malformed("Malformed SafeBag");
    }
    if (DerExpect(&Bag, DER_SET, &Attributes)) {
        ReadLocalKeyId(Attributes, KeyId, &KeyIdLength);
    }

    if (DER_IS_OID(&BagId, OidCertBag)) {
        //
        // CertBag ::= SEQUENCE { certId, certValue [0] EXPLICIT }
        //
        CXPLAT_DER CertBag, CertId, CertValue, Der;
        if (!DerExpect(&BagValue, DER_SEQUENCE, &CertBag) ||
            !DerExpect(&CertBag, DER_OID, &CertId) ||
            !DerExpect(&CertBag, DER_CONTEXT_0, &CertValue)) {
            return Malformed("Malformed CertBag");
        }
        if (!DER_IS_OID(&CertId, OidX509Certificate)) {
            return QUIC_STATUS_SUCCESS; // Not an X.509 certificate; skip it.
        }
        if (!DerExpect(&CertValue, DER_OCTET_STRING, &Der)) {
            return Malformed("Malformed x509Certificate");
        }
        return Pkcs12AddCertificate(State, Der, KeyId, KeyIdLength);
    }

    if (DER_IS_OID(&BagId, OidKeyBag) || DER_IS_OID(&BagId, OidShroudedKeyBag)) {
        if (State->Found.KeyDer != NULL) {
            return QUIC_STATUS_SUCCESS; // Only the first key is used.
        }

        if (DER_IS_OID(&BagId, OidKeyBag)) {
            uint8_t Tag;
            CXPLAT_DER Contents, Whole;
            if (!DerRead(&BagValue, &Tag, &Contents, &Whole) || Tag != DER_SEQUENCE) {
                return Malformed("Malformed KeyBag");
            }
            State->Found.KeyDer =
                AllocCopy(Whole.Data, Whole.Length, QUIC_POOL_TLS_PFX, "PKCS#8 key");
            if (State->Found.KeyDer == NULL) {
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            State->Found.KeyDerLength = Whole.Length;

        } else {
            QUIC_STATUS Status =
                DecryptPrivateKeyInfo(
                    State->Crypto,
                    BagValue,
                    State->Password,
                    &State->Found.KeyDer,
                    &State->Found.KeyDerLength,
                    &State->BadPassword);
            if (QUIC_FAILED(Status)) {
                return Status;
            }
        }

        State->Found.KeyFormat = CXPLAT_PICOTLS_KEY_FORMAT_PKCS8;
        memcpy(State->KeyId, KeyId, KeyIdLength);
        State->KeyIdLength = KeyIdLength;
        return QUIC_STATUS_SUCCESS;
    }

    if (DER_IS_OID(&BagId, OidSafeContentsBag)) {
        if (Depth >= PKCS12_MAX_NESTING) {
            return Malformed("SafeContents nested too deeply");
        }
        return Pkcs12ParseSafeContents(State, BagValue, Depth + 1);
    }

    return QUIC_STATUS_SUCCESS; // CRL, secret and other bags aren't used.
}

static
QUIC_STATUS
Pkcs12ParseSafeContents(
    _Inout_ PKCS12_PARSE_STATE* State,
    _In_ CXPLAT_DER SafeContents,
    _In_ uint32_t Depth
    )
{
    CXPLAT_DER Bags, Bag;
    if (!DerExpect(&SafeContents, DER_SEQUENCE, &Bags)) {
        return Malformed("Malformed SafeContents");
    }
    while (Bags.Length > 0) {
        if (!DerExpect(&Bags, DER_SEQUENCE, &Bag)) {
            return Malformed("Malformed SafeBag");
        }
        QUIC_STATUS Status = Pkcs12ParseSafeBag(State, Bag, Depth);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Reads one ContentInfo of the AuthenticatedSafe: data (plain SafeContents)
// or encryptedData (password-encrypted SafeContents).
//
static
QUIC_STATUS
Pkcs12ParseContentInfo(
    _Inout_ PKCS12_PARSE_STATE* State,
    _In_ CXPLAT_DER ContentInfo
    )
{
    CXPLAT_DER ContentType, Content;
    if (!DerExpect(&ContentInfo, DER_OID, &ContentType) ||
        !DerExpect(&ContentInfo, DER_CONTEXT_0, &Content)) {
        return Malformed("Malformed ContentInfo");
    }

    if (DER_IS_OID(&ContentType, OidData)) {
        CXPLAT_DER SafeContents;
        if (!DerExpect(&Content, DER_OCTET_STRING, &SafeContents)) {
            return Malformed("Malformed data ContentInfo");
        }
        return Pkcs12ParseSafeContents(State, SafeContents, 0);
    }

    if (!DER_IS_OID(&ContentType, OidEncryptedData)) {
        return Unsupported("PKCS#12 ContentInfo type (only data and encryptedData)");
    }

    //
    // EncryptedData ::= SEQUENCE { version, encryptedContentInfo }
    // EncryptedContentInfo ::= SEQUENCE { contentType, contentEncryptionAlgorithm,
    //                                     encryptedContent [0] IMPLICIT OPTIONAL }
    //
    CXPLAT_DER EncryptedData, EncryptedContentInfo, InnerType, Algorithm, Encrypted;
    uint32_t Version;
    if (!DerExpect(&Content, DER_SEQUENCE, &EncryptedData) ||
        !DerUint32(&EncryptedData, &Version) ||
        !DerExpect(&EncryptedData, DER_SEQUENCE, &EncryptedContentInfo) ||
        !DerExpect(&EncryptedContentInfo, DER_OID, &InnerType) ||
        !DerExpect(&EncryptedContentInfo, DER_SEQUENCE, &Algorithm)) {
        return Malformed("Malformed EncryptedData");
    }
    if (!DER_IS_OID(&InnerType, OidData)) {
        return Unsupported("EncryptedData content type");
    }

    uint8_t* Joined = NULL;
    size_t JoinedLength = 0;
    if (DerExpect(&EncryptedContentInfo, DER_CONTEXT_0_PRIMITIVE, &Encrypted)) {
        //
        // The usual, primitive form.
        //
    } else if (DerExpect(&EncryptedContentInfo, DER_CONTEXT_0, &Encrypted)) {
        //
        // Constructed form: the ciphertext is split across OCTET STRINGs.
        //
        CXPLAT_DER Pieces = Encrypted, Piece;
        while (Pieces.Length > 0) {
            if (!DerExpect(&Pieces, DER_OCTET_STRING, &Piece)) {
                return Malformed("Malformed constructed encryptedContent");
            }
            JoinedLength += Piece.Length;
        }
        Joined = CXPLAT_ALLOC_NONPAGED(JoinedLength == 0 ? 1 : JoinedLength, QUIC_POOL_TLS_PFX);
        if (Joined == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "PKCS#12 encrypted content",
                (uint64_t)JoinedLength);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        size_t Offset = 0;
        Pieces = Encrypted;
        while (DerExpect(&Pieces, DER_OCTET_STRING, &Piece)) {
            memcpy(Joined + Offset, Piece.Data, Piece.Length);
            Offset += Piece.Length;
        }
        Encrypted.Data = Joined;
        Encrypted.Length = JoinedLength;
    } else {
        return QUIC_STATUS_SUCCESS; // No content.
    }

    uint8_t* Plaintext;
    size_t PlaintextLength;
    QUIC_STATUS Status =
        PbeDecrypt(
            State->Crypto, Algorithm, State->Password, Encrypted.Data, Encrypted.Length,
            &Plaintext, &PlaintextLength, &State->BadPassword);
    if (Joined != NULL) {
        CXPLAT_FREE(Joined, QUIC_POOL_TLS_PFX);
    }
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    CXPLAT_DER SafeContents = { Plaintext, PlaintextLength };
    Status = Pkcs12ParseSafeContents(State, SafeContents, 0);
    FreeSecret(Plaintext, PlaintextLength);
    return Status;
}

//
// Checks the MacData of the PFX against AuthSafe (the contents of the
// authSafe data OCTET STRING). *BadPassword is set if the MAC doesn't match.
//
static
QUIC_STATUS
Pkcs12VerifyMac(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_DER MacData,
    _In_ CXPLAT_DER AuthSafe,
    _In_ const CXPLAT_PICOTLS_PASSWORD* Password,
    _Out_ BOOLEAN* BadPassword
    )
{
    CXPLAT_DER DigestInfo, Algorithm, Oid, Digest, Salt;
    uint32_t Iterations = 1;
    CXPLAT_PICOTLS_HASH Hash;
    uint8_t Key[64] = {0};
    uint8_t Mac[64] = {0};
    QUIC_STATUS Status;

    *BadPassword = FALSE;

    if (!DerExpect(&MacData, DER_SEQUENCE, &DigestInfo) ||
        !DerExpect(&DigestInfo, DER_SEQUENCE, &Algorithm) ||
        !DerExpect(&Algorithm, DER_OID, &Oid) ||
        !DerExpect(&DigestInfo, DER_OCTET_STRING, &Digest) ||
        !DerExpect(&MacData, DER_OCTET_STRING, &Salt)) {
        return Malformed("Malformed MacData");
    }
    if (DerPeek(&MacData, DER_INTEGER) && !DerUint32(&MacData, &Iterations)) {
        return Malformed("Malformed MacData iterations");
    }
    if (DER_IS_OID(&Oid, OidPbmac1)) {
        return Unsupported("PBMAC1 PKCS#12 integrity");
    }
    if (!ReadHashAlgorithm(&Oid, FALSE, &Hash)) {
        return Unsupported("PKCS#12 MAC digest");
    }

    const size_t Length = HashLength(Hash);
    Status = Pkcs12Kdf(Crypto, Hash, 3, Password, Salt.Data, Salt.Length, Iterations, Key, Length);
    if (QUIC_SUCCEEDED(Status)) {
        Status = CxPlatPicotlsCryptoHmac(Crypto, Hash, Key, Length, AuthSafe.Data, AuthSafe.Length, Mac);
    }
    if (QUIC_SUCCEEDED(Status)) {
        uint8_t Difference = Digest.Length == Length ? 0 : 1;
        for (size_t i = 0; i < Length && i < Digest.Length; ++i) {
            Difference |= (uint8_t)(Mac[i] ^ Digest.Data[i]);
        }
        if (Difference != 0) {
            *BadPassword = TRUE;
            Status = Malformed("PKCS#12 MAC mismatch (wrong password?)");
        }
    }

    CxPlatPicotlsSecureZero(Key, sizeof(Key));
    return Status;
}

static
void
Pkcs12StateClear(
    _Inout_ PKCS12_PARSE_STATE* State
    )
{
    CxPlatPicotlsCredentialClear(&State->Found);
    if (State->CertKeyIds != NULL) {
        CXPLAT_FREE(State->CertKeyIds, QUIC_POOL_TLS_PFX);
    }
    if (State->CertKeyIdLengths != NULL) {
        CXPLAT_FREE(State->CertKeyIdLengths, QUIC_POOL_TLS_PFX);
    }
    State->CertKeyIds = NULL;
    State->CertKeyIdLengths = NULL;
}

static
QUIC_STATUS
Pkcs12Parse(
    _In_reads_bytes_(PfxLength) const uint8_t* Pfx,
    _In_ size_t PfxLength,
    _In_ const CXPLAT_PICOTLS_PASSWORD* Password,
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _Out_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential,
    _Out_ BOOLEAN* BadPassword
    )
{
    PKCS12_PARSE_STATE State;
    CXPLAT_DER Input = { Pfx, PfxLength };
    CXPLAT_DER PfxSequence, AuthSafeInfo, ContentType, Content, AuthSafe, MacData;
    CXPLAT_DER ContentInfos, ContentInfo;
    uint32_t Version;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CxPlatZeroMemory(Credential, sizeof(*Credential));
    CxPlatZeroMemory(&State, sizeof(State));
    State.Password = Password;
    State.Crypto = Crypto;
    *BadPassword = FALSE;

    //
    // PFX ::= SEQUENCE { version, authSafe ContentInfo, macData OPTIONAL }
    //
    if (!DerExpect(&Input, DER_SEQUENCE, &PfxSequence) ||
        !DerUint32(&PfxSequence, &Version) ||
        !DerExpect(&PfxSequence, DER_SEQUENCE, &AuthSafeInfo) ||
        !DerExpect(&AuthSafeInfo, DER_OID, &ContentType) ||
        !DerExpect(&AuthSafeInfo, DER_CONTEXT_0, &Content)) {
        return Malformed("Malformed PFX");
    }
    if (Version != 3) {
        return Unsupported("PFX version");
    }
    if (!DER_IS_OID(&ContentType, OidData)) {
        return Unsupported("PFX authSafe type (only password integrity)");
    }
    if (!DerExpect(&Content, DER_OCTET_STRING, &AuthSafe)) {
        return Malformed("Malformed PFX authSafe");
    }

    if (DerExpect(&PfxSequence, DER_SEQUENCE, &MacData)) {
        Status = Pkcs12VerifyMac(Crypto, MacData, AuthSafe, Password, BadPassword);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
    }

    //
    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    //
    CXPLAT_DER AuthSafeCursor = AuthSafe;
    if (!DerExpect(&AuthSafeCursor, DER_SEQUENCE, &ContentInfos)) {
        return Malformed("Malformed AuthenticatedSafe");
    }
    while (ContentInfos.Length > 0) {
        if (!DerExpect(&ContentInfos, DER_SEQUENCE, &ContentInfo)) {
            Status = Malformed("Malformed AuthenticatedSafe ContentInfo");
            goto Exit;
        }
        Status = Pkcs12ParseContentInfo(&State, ContentInfo);
        if (QUIC_FAILED(Status)) {
            *BadPassword = State.BadPassword;
            goto Exit;
        }
    }

    if (State.Found.KeyDer == NULL) {
        Status = Malformed("PKCS#12 has no private key");
        goto Exit;
    }
    if (State.Found.CertificateCount == 0) {
        Status = Malformed("PKCS#12 has no certificate");
        goto Exit;
    }

    //
    // The leaf is the certificate with the key's localKeyId, or else the
    // first one. It goes first, the others follow in the order found.
    //
    size_t Leaf = 0;
    if (State.KeyIdLength != 0) {
        for (size_t i = 0; i < State.Found.CertificateCount; ++i) {
            if (State.CertKeyIdLengths[i] == State.KeyIdLength &&
                memcmp(State.CertKeyIds[i], State.KeyId, State.KeyIdLength) == 0) {
                Leaf = i;
                break;
            }
        }
    }
    if (Leaf != 0) {
        ptls_iovec_t LeafCert = State.Found.Certificates[Leaf];
        memmove(
            State.Found.Certificates + 1,
            State.Found.Certificates,
            Leaf * sizeof(ptls_iovec_t));
        State.Found.Certificates[0] = LeafCert;
    }

    *Credential = State.Found;
    CxPlatZeroMemory(&State.Found, sizeof(State.Found));
    Status = QUIC_STATUS_SUCCESS;

Exit:

    Pkcs12StateClear(&State);
    return Status;
}

QUIC_STATUS
CxPlatPicotlsParsePkcs12(
    _In_reads_bytes_(PfxLength) const uint8_t* Pfx,
    _In_ size_t PfxLength,
    _In_opt_z_ const char* Password,
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _Out_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    )
{
    CXPLAT_PICOTLS_PASSWORD Pwd;
    BOOLEAN BadPassword = FALSE;

    QUIC_STATUS Status = PasswordInitialize(Password, &Pwd);
    if (QUIC_FAILED(Status)) {
        CxPlatZeroMemory(Credential, sizeof(*Credential));
        return Status;
    }
    Status = Pkcs12Parse(Pfx, PfxLength, &Pwd, Crypto, Credential, &BadPassword);
    PasswordUninitialize(&Pwd);

    if (QUIC_FAILED(Status) && BadPassword && Password == NULL) {
        //
        // No password was given: an empty one is the other possibility.
        //
        Status = PasswordInitialize("", &Pwd);
        if (QUIC_SUCCEEDED(Status)) {
            Status = Pkcs12Parse(Pfx, PfxLength, &Pwd, Crypto, Credential, &BadPassword);
            PasswordUninitialize(&Pwd);
        }
    }

    return Status;
}

//
// Private keys.
//

static
QUIC_STATUS
DecodeRsaPrivateKey(
    _In_ CXPLAT_DER Input,
    _Out_ CXPLAT_PICOTLS_RAW_KEY* Key
    )
{
    //
    // RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent,
    //     privateExponent, prime1, prime2, exponent1, exponent2, coefficient }
    //
    CXPLAT_DER Sequence;
    uint32_t Version;
    ptls_iovec_t PrivateExponent;
    CxPlatZeroMemory(Key, sizeof(*Key));
    if (!DerExpect(&Input, DER_SEQUENCE, &Sequence) ||
        !DerUint32(&Sequence, &Version)) {
        return Malformed("Malformed RSAPrivateKey");
    }
    if (Version != 0) {
        return Unsupported("Multi-prime RSA keys");
    }
    if (!DerBigInteger(&Sequence, &Key->Modulus) ||
        !DerBigInteger(&Sequence, &Key->PublicExponent) ||
        !DerBigInteger(&Sequence, &PrivateExponent) ||
        !DerBigInteger(&Sequence, &Key->Prime1) ||
        !DerBigInteger(&Sequence, &Key->Prime2)) {
        return Malformed("Malformed RSAPrivateKey");
    }
    Key->Type = CXPLAT_PICOTLS_KEY_RSA;
    return QUIC_STATUS_SUCCESS;
}

static
BOOLEAN
CurveFromOid(
    _In_ const CXPLAT_DER* Oid,
    _Out_ uint32_t* CurveBits
    )
{
    if (DER_IS_OID(Oid, OidPrime256v1)) {
        *CurveBits = 256;
    } else if (DER_IS_OID(Oid, OidSecp384r1)) {
        *CurveBits = 384;
    } else if (DER_IS_OID(Oid, OidSecp521r1)) {
        *CurveBits = 521;
    } else {
        *CurveBits = 0;
        return FALSE;
    }
    return TRUE;
}

//
// Decodes an ECPrivateKey. CurveBits is the curve from the enclosing
// PrivateKeyInfo, or 0 if the key must name it itself.
//
static
QUIC_STATUS
DecodeEcPrivateKey(
    _In_ CXPLAT_DER Input,
    _In_ uint32_t CurveBits,
    _Out_ CXPLAT_PICOTLS_RAW_KEY* Key
    )
{
    //
    // ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING,
    //     parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }
    //
    CXPLAT_DER Sequence, PrivateKey, Field;
    uint32_t Version;
    CxPlatZeroMemory(Key, sizeof(*Key));
    if (!DerExpect(&Input, DER_SEQUENCE, &Sequence) ||
        !DerUint32(&Sequence, &Version) ||
        Version != 1 ||
        !DerExpect(&Sequence, DER_OCTET_STRING, &PrivateKey) ||
        PrivateKey.Length == 0) {
        return Malformed("Malformed ECPrivateKey");
    }
    if (DerExpect(&Sequence, DER_CONTEXT_0, &Field)) {
        CXPLAT_DER Oid;
        uint32_t KeyCurveBits;
        if (!DerExpect(&Field, DER_OID, &Oid) || !CurveFromOid(&Oid, &KeyCurveBits)) {
            return Unsupported("EC curve (only P-256, P-384 and P-521)");
        }
        if (CurveBits != 0 && CurveBits != KeyCurveBits) {
            return Malformed("ECPrivateKey curve doesn't match its PrivateKeyInfo");
        }
        CurveBits = KeyCurveBits;
    }
    if (CurveBits == 0) {
        return Malformed("ECPrivateKey doesn't name its curve");
    }

    CXPLAT_DER PublicKey;
    if (!DerExpect(&Sequence, DER_CONTEXT_1, &Field) ||
        !DerExpect(&Field, DER_BIT_STRING, &PublicKey)) {
        //
        // Computing the public point would take EC arithmetic BCrypt doesn't
        // expose; the encoders in use always include it.
        //
        return Unsupported("ECPrivateKey without its public key");
    }

    const size_t FieldLength = (CurveBits + 7) / 8;
    if (PublicKey.Length != 2 + 2 * FieldLength ||
        PublicKey.Data[0] != 0 ||       // Unused bits.
        PublicKey.Data[1] != 0x04) {    // Uncompressed point.
        return Unsupported("EC public key encoding (only uncompressed points)");
    }
    if (PrivateKey.Length > FieldLength) {
        return Malformed("EC private key longer than the curve");
    }

    Key->Type = CXPLAT_PICOTLS_KEY_EC;
    Key->CurveBits = CurveBits;
    Key->PrivateScalar = ptls_iovec_init(PrivateKey.Data, PrivateKey.Length);
    Key->PublicPoint = ptls_iovec_init(PublicKey.Data + 1, PublicKey.Length - 1);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatPicotlsDecodePrivateKey(
    _In_reads_bytes_(KeyDerLength) const uint8_t* KeyDer,
    _In_ size_t KeyDerLength,
    _In_ CXPLAT_PICOTLS_KEY_FORMAT KeyFormat,
    _Out_ CXPLAT_PICOTLS_RAW_KEY* Key
    )
{
    CXPLAT_DER Input = { KeyDer, KeyDerLength };
    CxPlatZeroMemory(Key, sizeof(*Key));

    if (KeyFormat == CXPLAT_PICOTLS_KEY_FORMAT_PKCS1) {
        return DecodeRsaPrivateKey(Input, Key);
    }
    if (KeyFormat == CXPLAT_PICOTLS_KEY_FORMAT_SEC1) {
        return DecodeEcPrivateKey(Input, 0, Key);
    }

    //
    // PrivateKeyInfo ::= SEQUENCE { version, privateKeyAlgorithm,
    //     privateKey OCTET STRING, attributes [0] OPTIONAL, ... }
    //
    CXPLAT_DER Sequence, Algorithm, Oid, PrivateKey;
    uint32_t Version;
    if (!DerExpect(&Input, DER_SEQUENCE, &Sequence) ||
        !DerUint32(&Sequence, &Version) ||
        Version > 1 ||
        !DerExpect(&Sequence, DER_SEQUENCE, &Algorithm) ||
        !DerExpect(&Algorithm, DER_OID, &Oid) ||
        !DerExpect(&Sequence, DER_OCTET_STRING, &PrivateKey)) {
        return Malformed("Malformed PrivateKeyInfo");
    }

    if (DER_IS_OID(&Oid, OidRsaEncryption)) {
        return DecodeRsaPrivateKey(PrivateKey, Key);
    }
    if (DER_IS_OID(&Oid, OidEcPublicKey)) {
        CXPLAT_DER Curve;
        uint32_t CurveBits;
        if (!DerExpect(&Algorithm, DER_OID, &Curve) || !CurveFromOid(&Curve, &CurveBits)) {
            return Unsupported("EC curve (only named P-256, P-384 and P-521)");
        }
        return DecodeEcPrivateKey(PrivateKey, CurveBits, Key);
    }
    return Unsupported("Private key algorithm (only RSA and ECDSA)");
}

//
// PEM.
//

static
int
Base64Value(
    _In_ char c
    )
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static
const char*
FindText(
    _In_reads_(Length) const char* Text,
    _In_ size_t Length,
    _In_z_ const char* Needle
    )
{
    size_t NeedleLength = strlen(Needle);
    for (size_t i = 0; i + NeedleLength <= Length; ++i) {
        if (memcmp(Text + i, Needle, NeedleLength) == 0) {
            return Text + i;
        }
    }
    return NULL;
}

//
// Finds the next PEM block at or after *Cursor. On success Label points at its
// label (not terminated) and *Der holds its decoded contents (QUIC_POOL_TLS_PFX).
// Returns QUIC_STATUS_NOT_FOUND when there are no more blocks.
//
static
QUIC_STATUS
PemNext(
    _Inout_ const char** Cursor,
    _In_ const char* End,
    _Out_ const char** Label,
    _Out_ size_t* LabelLength,
    _Outptr_result_buffer_maybenull_(*DerLength) uint8_t** Der,
    _Out_ size_t* DerLength
    )
{
    static const char Begin[] = "-----BEGIN ";
    static const char Dashes[] = "-----";

    *Label = NULL;
    *LabelLength = 0;
    *Der = NULL;
    *DerLength = 0;

    const char* Start = FindText(*Cursor, (size_t)(End - *Cursor), Begin);
    if (Start == NULL) {
        return QUIC_STATUS_NOT_FOUND;
    }
    const char* LabelStart = Start + sizeof(Begin) - 1;
    const char* LabelEnd = FindText(LabelStart, (size_t)(End - LabelStart), Dashes);
    if (LabelEnd == NULL || LabelEnd - LabelStart > 64) {
        return Malformed("Malformed PEM BEGIN line");
    }
    const char* Body = LabelEnd + sizeof(Dashes) - 1;

    //
    // The matching END line.
    //
    char EndLine[96];
    size_t LabelSize = (size_t)(LabelEnd - LabelStart);
    memcpy(EndLine, "-----END ", 9);
    memcpy(EndLine + 9, LabelStart, LabelSize);
    memcpy(EndLine + 9 + LabelSize, Dashes, sizeof(Dashes)); // Includes the terminator.
    const char* BodyEnd = FindText(Body, (size_t)(End - Body), EndLine);
    if (BodyEnd == NULL) {
        return Malformed("PEM block without its END line");
    }
    if (FindText(Body, (size_t)(BodyEnd - Body), ":") != NULL) {
        return Unsupported("PEM headers (such as legacy OpenSSL key encryption)");
    }

    uint8_t* Output = CXPLAT_ALLOC_NONPAGED((size_t)(BodyEnd - Body) / 4 * 3 + 3, QUIC_POOL_TLS_PFX);
    if (Output == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PEM contents",
            (uint64_t)((BodyEnd - Body) / 4 * 3 + 3));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    size_t OutputLength = 0;
    uint32_t Accumulator = 0;
    uint32_t Bits = 0;
    BOOLEAN Padding = FALSE;
    for (const char* c = Body; c < BodyEnd; ++c) {
        if (*c == ' ' || *c == '\t' || *c == '\r' || *c == '\n') {
            continue;
        }
        if (*c == '=') {
            Padding = TRUE;
            continue;
        }
        int Value = Base64Value(*c);
        if (Value < 0 || Padding) {
            FreeSecret(Output, (size_t)(BodyEnd - Body) / 4 * 3 + 3);
            return Malformed("Malformed PEM base64");
        }
        Accumulator = (Accumulator << 6) | (uint32_t)Value;
        Bits += 6;
        if (Bits >= 8) {
            Bits -= 8;
            Output[OutputLength++] = (uint8_t)(Accumulator >> Bits);
        }
    }

    *Cursor = BodyEnd + 9 + LabelSize + sizeof(Dashes) - 1;
    *Label = LabelStart;
    *LabelLength = LabelSize;
    *Der = Output;
    *DerLength = OutputLength;
    return QUIC_STATUS_SUCCESS;
}

static
BOOLEAN
LabelIs(
    _In_reads_(LabelLength) const char* Label,
    _In_ size_t LabelLength,
    _In_z_ const char* Expected
    )
{
    return strlen(Expected) == LabelLength && memcmp(Label, Expected, LabelLength) == 0;
}

QUIC_STATUS
CxPlatPicotlsParsePemCertificates(
    _In_reads_bytes_(PemLength) const char* Pem,
    _In_ size_t PemLength,
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    )
{
    const char* Cursor = Pem;
    const char* End = Pem + PemLength;
    QUIC_STATUS Status;

    for (;;) {
        const char* Label;
        size_t LabelLength;
        uint8_t* Der;
        size_t DerLength;
        Status = PemNext(&Cursor, End, &Label, &LabelLength, &Der, &DerLength);
        if (Status == QUIC_STATUS_NOT_FOUND) {
            break;
        }
        if (QUIC_FAILED(Status)) {
            return Status;
        }
        if (Der != NULL && LabelIs(Label, LabelLength, "CERTIFICATE")) {
            Status = AppendCertificate(Credential, Der, DerLength);
        }
        FreeSecret(Der, DerLength);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
    }

    if (Credential->CertificateCount == 0) {
        return Malformed("No CERTIFICATE in the PEM file");
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatPicotlsParsePemPrivateKey(
    _In_reads_bytes_(PemLength) const char* Pem,
    _In_ size_t PemLength,
    _In_opt_z_ const char* Password,
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    )
{
    const char* Cursor = Pem;
    const char* End = Pem + PemLength;
    QUIC_STATUS Status;

    for (;;) {
        const char* Label;
        size_t LabelLength;
        uint8_t* Der;
        size_t DerLength;
        Status = PemNext(&Cursor, End, &Label, &LabelLength, &Der, &DerLength);
        if (Status == QUIC_STATUS_NOT_FOUND) {
            return Malformed("No private key in the PEM file");
        }
        if (QUIC_FAILED(Status)) {
            return Status;
        }

        CXPLAT_PICOTLS_KEY_FORMAT Format = CXPLAT_PICOTLS_KEY_FORMAT_PKCS8;
        if (LabelIs(Label, LabelLength, "PRIVATE KEY")) {
            Format = CXPLAT_PICOTLS_KEY_FORMAT_PKCS8;
        } else if (LabelIs(Label, LabelLength, "RSA PRIVATE KEY")) {
            Format = CXPLAT_PICOTLS_KEY_FORMAT_PKCS1;
        } else if (LabelIs(Label, LabelLength, "EC PRIVATE KEY")) {
            Format = CXPLAT_PICOTLS_KEY_FORMAT_SEC1;
        } else if (LabelIs(Label, LabelLength, "ENCRYPTED PRIVATE KEY")) {
            if (Password == NULL) {
                FreeSecret(Der, DerLength);
                return Malformed("Encrypted private key without a password");
            }
            CXPLAT_PICOTLS_PASSWORD Pwd;
            BOOLEAN BadPassword;
            Status = PasswordInitialize(Password, &Pwd);
            if (QUIC_SUCCEEDED(Status)) {
                CXPLAT_DER Encrypted = { Der, DerLength };
                Status =
                    DecryptPrivateKeyInfo(
                        Crypto, Encrypted, &Pwd,
                        &Credential->KeyDer, &Credential->KeyDerLength,
                        &BadPassword);
                PasswordUninitialize(&Pwd);
            }
            FreeSecret(Der, DerLength);
            Credential->KeyFormat = CXPLAT_PICOTLS_KEY_FORMAT_PKCS8;
            return Status;
        } else {
            FreeSecret(Der, DerLength); // Such as EC PARAMETERS.
            continue;
        }

        Credential->KeyDer = Der;
        Credential->KeyDerLength = DerLength;
        Credential->KeyFormat = Format;
        return QUIC_STATUS_SUCCESS;
    }
}
