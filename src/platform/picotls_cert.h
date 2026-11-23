/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Server certificate and private key support for the picotls TLS provider on
    Windows (user mode and kernel mode), where OpenSSL is not available for
    certificates. The work is split in two:

    picotls_pkcs12.c    Parses PKCS#12, PKCS#8, PKCS#1, SEC1 and PEM. It does
                        no cryptography itself: decryption, MAC checks and key
                        derivation go through the CxPlatPicotlsCrypto*
                        functions below.

    picotls_cert_win.c  Implements those functions with BCrypt, imports the
                        private key into BCrypt (or, for certificates in a
                        Windows certificate store, uses its NCrypt key) and
                        signs the TLS 1.3 CertificateVerify.

--*/

#pragma once

#include "picotls.h"

#if defined(__cplusplus)
extern "C" {
#endif

//
// Parsing (picotls_pkcs12.c).
//

//
// State of the cryptographic primitives below (such as open algorithm
// providers), defined by their implementation and passed through as is.
//
typedef struct CXPLAT_PICOTLS_CRYPTO CXPLAT_PICOTLS_CRYPTO;

typedef enum CXPLAT_PICOTLS_KEY_TYPE {
    CXPLAT_PICOTLS_KEY_RSA,
    CXPLAT_PICOTLS_KEY_EC,
} CXPLAT_PICOTLS_KEY_TYPE;

//
// The components of a private key, as unsigned big-endian integers without
// leading zero bytes. They point into the buffer the key was decoded from.
//
typedef struct CXPLAT_PICOTLS_RAW_KEY {
    CXPLAT_PICOTLS_KEY_TYPE Type;

    //
    // RSA.
    //
    ptls_iovec_t Modulus;
    ptls_iovec_t PublicExponent;
    ptls_iovec_t Prime1;
    ptls_iovec_t Prime2;

    //
    // EC. CurveBits is 256, 384 or 521. PrivateScalar is the raw scalar (left
    // as encoded, so possibly shorter than the field size), PublicPoint the
    // uncompressed point 04 || X || Y.
    //
    uint32_t CurveBits;
    ptls_iovec_t PrivateScalar;
    ptls_iovec_t PublicPoint;

} CXPLAT_PICOTLS_RAW_KEY;

typedef enum CXPLAT_PICOTLS_KEY_FORMAT {
    CXPLAT_PICOTLS_KEY_FORMAT_PKCS8,    // PrivateKeyInfo
    CXPLAT_PICOTLS_KEY_FORMAT_PKCS1,    // RSAPrivateKey
    CXPLAT_PICOTLS_KEY_FORMAT_SEC1,     // ECPrivateKey
} CXPLAT_PICOTLS_KEY_FORMAT;

//
// A certificate chain (leaf first) and the private key that goes with the
// leaf. Certificates and Certificates[i].base are allocated with
// QUIC_POOL_TLS_CERT_DER; KeyDer with QUIC_POOL_TLS_PFX. Release it all with
// CxPlatPicotlsCredentialClear.
//
typedef struct CXPLAT_PICOTLS_PARSED_CREDENTIAL {
    ptls_iovec_t* Certificates;
    size_t CertificateCount;
    uint8_t* KeyDer;
    size_t KeyDerLength;
    CXPLAT_PICOTLS_KEY_FORMAT KeyFormat;
} CXPLAT_PICOTLS_PARSED_CREDENTIAL;

//
// Decodes a DER PKCS#12 (PFX) blob. Password may be NULL, in which case both
// the absent and the empty password are tried, as OpenSSL does. Supported
// protections: PBES2 (PBKDF2 with HMAC-SHA1/256/384/512, AES-128/192/256-CBC
// or 3DES-CBC), pbeWithSHAAnd3-KeyTripleDES-CBC, and none.
//
QUIC_STATUS
CxPlatPicotlsParsePkcs12(
    _In_reads_bytes_(PfxLength) const uint8_t* Pfx,
    _In_ size_t PfxLength,
    _In_opt_z_ const char* Password,
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _Out_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    );

//
// Decodes the certificates of a PEM file into Credential.
//
QUIC_STATUS
CxPlatPicotlsParsePemCertificates(
    _In_reads_bytes_(PemLength) const char* Pem,
    _In_ size_t PemLength,
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    );

//
// Decodes the private key of a PEM file into Credential: "PRIVATE KEY",
// "RSA PRIVATE KEY", "EC PRIVATE KEY", or, with a Password, "ENCRYPTED
// PRIVATE KEY" (PKCS#8 with PBES2).
//
QUIC_STATUS
CxPlatPicotlsParsePemPrivateKey(
    _In_reads_bytes_(PemLength) const char* Pem,
    _In_ size_t PemLength,
    _In_opt_z_ const char* Password,
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    );

//
// Splits a decoded private key into its components. Key points into KeyDer.
//
QUIC_STATUS
CxPlatPicotlsDecodePrivateKey(
    _In_reads_bytes_(KeyDerLength) const uint8_t* KeyDer,
    _In_ size_t KeyDerLength,
    _In_ CXPLAT_PICOTLS_KEY_FORMAT KeyFormat,
    _Out_ CXPLAT_PICOTLS_RAW_KEY* Key
    );

//
// Appends a copy of a DER certificate to Credential->Certificates.
//
QUIC_STATUS
CxPlatPicotlsCredentialAddCertificate(
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential,
    _In_reads_bytes_(Length) const uint8_t* Der,
    _In_ size_t Length
    );

void
CxPlatPicotlsCredentialClear(
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Credential
    );

void
CxPlatPicotlsFreeCertificates(
    _In_reads_opt_(Count) ptls_iovec_t* Certificates,
    _In_ size_t Count
    );

//
// Overwrites Length bytes at Buffer with zeros, in a way the compiler keeps.
//
void
CxPlatPicotlsSecureZero(
    _Out_writes_bytes_all_(Length) void* Buffer,
    _In_ size_t Length
    );

//
// Cryptographic primitives the parser needs (picotls_cert_win.c).
//

typedef enum CXPLAT_PICOTLS_HASH {
    CXPLAT_PICOTLS_HASH_SHA1,
    CXPLAT_PICOTLS_HASH_SHA256,
    CXPLAT_PICOTLS_HASH_SHA384,
    CXPLAT_PICOTLS_HASH_SHA512,
} CXPLAT_PICOTLS_HASH;

typedef enum CXPLAT_PICOTLS_CIPHER {
    CXPLAT_PICOTLS_CIPHER_AES_CBC,      // Key of 16, 24 or 32 bytes.
    CXPLAT_PICOTLS_CIPHER_3DES_CBC,     // Key of 24 bytes.
} CXPLAT_PICOTLS_CIPHER;

QUIC_STATUS
CxPlatPicotlsCryptoHash(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_PICOTLS_HASH Hash,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ size_t DataLength,
    _Out_writes_bytes_(64) uint8_t* Output
    );

QUIC_STATUS
CxPlatPicotlsCryptoHmac(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_PICOTLS_HASH Hash,
    _In_reads_bytes_(KeyLength) const uint8_t* Key,
    _In_ size_t KeyLength,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ size_t DataLength,
    _Out_writes_bytes_(64) uint8_t* Output
    );

QUIC_STATUS
CxPlatPicotlsCryptoPbkdf2(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_PICOTLS_HASH Prf,
    _In_reads_bytes_(PasswordLength) const uint8_t* Password,
    _In_ size_t PasswordLength,
    _In_reads_bytes_(SaltLength) const uint8_t* Salt,
    _In_ size_t SaltLength,
    _In_ uint32_t Iterations,
    _Out_writes_bytes_(OutputLength) uint8_t* Output,
    _In_ size_t OutputLength
    );

//
// Decrypts Data in place. Length is a multiple of the block size; the padding
// is left for the caller to check.
//
QUIC_STATUS
CxPlatPicotlsCryptoCbcDecrypt(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_PICOTLS_CIPHER Cipher,
    _In_reads_bytes_(KeyLength) const uint8_t* Key,
    _In_ size_t KeyLength,
    _In_reads_bytes_(IvLength) const uint8_t* Iv,
    _In_ size_t IvLength,
    _Inout_updates_bytes_(Length) uint8_t* Data,
    _In_ size_t Length
    );

//
// Loading and signing (picotls_cert_win.c).
//

typedef struct CXPLAT_PICOTLS_SIGNER CXPLAT_PICOTLS_SIGNER;

//
// Loads the certificate chain and private key of CredConfig. Kernel mode
// supports CERTIFICATE_PKCS12; user mode also CERTIFICATE_FILE,
// CERTIFICATE_FILE_PROTECTED, CERTIFICATE_HASH, CERTIFICATE_HASH_STORE and
// CERTIFICATE_CONTEXT.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatPicotlsLoadCredential(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Outptr_result_buffer_(*CertificateCount) ptls_iovec_t** Certificates,
    _Out_ size_t* CertificateCount,
    _Outptr_ CXPLAT_PICOTLS_SIGNER** Signer
    );

//
// Signs the CertificateVerify input with the first of Algorithms (in the
// peer's order of preference) the key supports. Returns 0 or a PTLS_ error.
//
int
CxPlatPicotlsSign(
    _In_ CXPLAT_PICOTLS_SIGNER* Signer,
    _In_ ptls_iovec_t Input,
    _In_reads_(AlgorithmCount) const uint16_t* Algorithms,
    _In_ size_t AlgorithmCount,
    _Out_ uint16_t* SelectedAlgorithm,
    _Inout_ ptls_buffer_t* Output
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPicotlsSignerFree(
    _In_ CXPLAT_PICOTLS_SIGNER* Signer
    );

#if defined(__cplusplus)
}
#endif
