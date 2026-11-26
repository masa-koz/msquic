/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    DER reading for the picotls TLS provider on Windows, shared by the PKCS#12
    parser (picotls_pkcs12.c, which implements it) and the X.509 certificate
    verifier (picotls_x509.c). Only DER is accepted: no BER indefinite lengths
    and no high tag numbers.

--*/

#pragma once

//
// Silences a code analysis warning the analyzer can't see is wrong.
//
#ifdef _MSC_VER
#define ANALYSIS_SUPPRESS(Warnings) __pragma(warning(suppress:Warnings))
#else
#define ANALYSIS_SUPPRESS(Warnings)
#endif

#define DER_BOOLEAN             0x01
#define DER_INTEGER             0x02
#define DER_BIT_STRING          0x03
#define DER_OCTET_STRING        0x04
#define DER_NULL                0x05
#define DER_OID                 0x06
#define DER_UTF8_STRING         0x0C
#define DER_PRINTABLE_STRING    0x13
#define DER_T61_STRING          0x14
#define DER_IA5_STRING          0x16
#define DER_UTC_TIME            0x17
#define DER_GENERALIZED_TIME    0x18
#define DER_SEQUENCE            0x30
#define DER_SET                 0x31
#define DER_CONTEXT_0           0xA0    // [0], constructed
#define DER_CONTEXT_1           0xA1    // [1], constructed
#define DER_CONTEXT_2           0xA2    // [2], constructed
#define DER_CONTEXT_3           0xA3    // [3], constructed
#define DER_CONTEXT_0_PRIMITIVE 0x80    // [0] IMPLICIT, primitive

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct CXPLAT_DER {
    const uint8_t* Data;
    size_t Length;
} CXPLAT_DER;

//
// Reads one TLV. Value receives the contents, and Whole (if given) the whole
// encoding including tag and length.
//
BOOLEAN
CxPlatPicotlsDerRead(
    _Inout_ CXPLAT_DER* In,
    _Out_ uint8_t* Tag,
    _Out_ CXPLAT_DER* Value,
    _Out_opt_ CXPLAT_DER* Whole
    );

//
// Reads one TLV that must have tag Tag. In is left as it was on failure.
//
BOOLEAN
CxPlatPicotlsDerExpect(
    _Inout_ CXPLAT_DER* In,
    _In_ uint8_t Tag,
    _Out_ CXPLAT_DER* Value
    );

BOOLEAN
CxPlatPicotlsDerPeek(
    _In_ const CXPLAT_DER* In,
    _In_ uint8_t Tag
    );

//
// Reads a non-negative INTEGER that fits in 32 bits.
//
BOOLEAN
CxPlatPicotlsDerUint32(
    _Inout_ CXPLAT_DER* In,
    _Out_ uint32_t* Value
    );

//
// Reads a positive INTEGER of any size, without its leading zero bytes.
//
BOOLEAN
CxPlatPicotlsDerBigInteger(
    _Inout_ CXPLAT_DER* In,
    _Out_ ptls_iovec_t* Value
    );

BOOLEAN
CxPlatPicotlsDerIsOid(
    _In_ const CXPLAT_DER* Oid,
    _In_reads_bytes_(ExpectedLength) const uint8_t* Expected,
    _In_ size_t ExpectedLength
    );

#if defined(__cplusplus)
}
#endif

#define DerRead CxPlatPicotlsDerRead
#define DerExpect CxPlatPicotlsDerExpect
#define DerPeek CxPlatPicotlsDerPeek
#define DerUint32 CxPlatPicotlsDerUint32
#define DerBigInteger CxPlatPicotlsDerBigInteger
#define DerIsOid CxPlatPicotlsDerIsOid
#define DER_IS_OID(Oid, Expected) DerIsOid(Oid, Expected, sizeof(Expected))
