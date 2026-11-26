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

//
// Verification of the server's certificate (client side).
//
// picotls_x509.c parses X.509 certificates and, in kernel mode, where there is
// no CryptoAPI, builds and validates the chain to a trust anchor. It does no
// cryptography itself: signatures are checked with
// CxPlatPicotlsCryptoVerifySignature.
//
// picotls_cert_win.c implements the TLS verify_certificate callback: it
// validates the chain (with CertGetCertificateChain in user mode; in kernel
// mode with picotls_x509.c, against the machine's root store read from the
// registry), then checks the CertificateVerify signature with BCrypt.
//

typedef enum CXPLAT_PICOTLS_SIGNATURE_PADDING {
    CXPLAT_PICOTLS_PADDING_RSA_PKCS1,
    CXPLAT_PICOTLS_PADDING_RSA_PSS,     // MGF1 with the signature's hash.
    CXPLAT_PICOTLS_PADDING_ECDSA,       // DER Ecdsa-Sig-Value.
} CXPLAT_PICOTLS_SIGNATURE_PADDING;

typedef struct CXPLAT_PICOTLS_SIGNATURE_ALGORITHM {
    CXPLAT_PICOTLS_HASH Hash;
    CXPLAT_PICOTLS_SIGNATURE_PADDING Padding;
    uint32_t SaltLength;                // RSA-PSS only.
} CXPLAT_PICOTLS_SIGNATURE_ALGORITHM;

//
// A public key, as unsigned big-endian integers without leading zero bytes
// (RSA) or the uncompressed point 04 || X || Y (EC, CurveBits 256, 384 or 521).
//
typedef struct CXPLAT_PICOTLS_PUBLIC_KEY {
    CXPLAT_PICOTLS_KEY_TYPE Type;
    ptls_iovec_t Modulus;
    ptls_iovec_t PublicExponent;
    uint32_t CurveBits;
    ptls_iovec_t PublicPoint;
} CXPLAT_PICOTLS_PUBLIC_KEY;

//
// The parts of an X.509 certificate needed to verify it. Everything points
// into Der.
//
typedef struct CXPLAT_PICOTLS_X509 {
    ptls_iovec_t Der;
    ptls_iovec_t TbsCertificate;        // Whole TLV: what the issuer signed.
    ptls_iovec_t Issuer;                // Whole Name TLV.
    ptls_iovec_t Subject;               // Whole Name TLV.
    int64_t NotBefore;                  // Seconds since 1970-01-01 UTC.
    int64_t NotAfter;

    BOOLEAN PublicKeySupported;
    CXPLAT_PICOTLS_PUBLIC_KEY PublicKey;

    BOOLEAN SignatureSupported;
    CXPLAT_PICOTLS_SIGNATURE_ALGORITHM SignatureAlgorithm;
    ptls_iovec_t Signature;

    BOOLEAN HasBasicConstraints;
    BOOLEAN IsCa;
    int32_t PathLength;                 // -1 when absent.
    BOOLEAN HasKeyUsage;
    uint8_t KeyUsage;                   // The first byte of the KeyUsage bits.
    BOOLEAN HasExtendedKeyUsage;
    BOOLEAN ServerAuth;                 // id-kp-serverAuth or anyExtendedKeyUsage.
    BOOLEAN HasSubjectAltName;
    ptls_iovec_t SubjectAltName;        // Contents of GeneralNames.
    BOOLEAN UnhandledCriticalExtension;
} CXPLAT_PICOTLS_X509;

#define CXPLAT_PICOTLS_KEY_USAGE_DIGITAL_SIGNATURE  0x80
#define CXPLAT_PICOTLS_KEY_USAGE_KEY_CERT_SIGN      0x04

QUIC_STATUS
CxPlatPicotlsParseCertificate(
    _In_reads_bytes_(Length) const uint8_t* Der,
    _In_ size_t Length,
    _Out_ CXPLAT_PICOTLS_X509* Certificate
    );

//
// Whether the certificate is valid for ServerName (a DNS name or an IPv4 or
// IPv6 literal): by its subjectAltName, or, when it has none, its subject's
// common name.
//
BOOLEAN
CxPlatPicotlsCertificateMatchesName(
    _In_ const CXPLAT_PICOTLS_X509* Certificate,
    _In_z_ const char* ServerName
    );

//
// Certificates the chain may end at, and certificates never to accept.
//
typedef struct CXPLAT_PICOTLS_TRUST_STORE {
    CXPLAT_PICOTLS_X509* Anchors;
    size_t AnchorCount;
    ptls_iovec_t* Disallowed;
    size_t DisallowedCount;
} CXPLAT_PICOTLS_TRUST_STORE;

//
// Builds a chain from Certificates[0] (the leaf) through the other
// Certificates (in any order) to a trust anchor, and validates it as a TLS
// server certificate chain for ServerName (if not NULL) at Now (seconds since
// 1970). Returns 0 or a PTLS_ALERT_ code.
//
int
CxPlatPicotlsVerifyChain(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ const CXPLAT_PICOTLS_TRUST_STORE* TrustStore,
    _In_reads_(CertificateCount) const ptls_iovec_t* Certificates,
    _In_ size_t CertificateCount,
    _In_opt_z_ const char* ServerName,
    _In_ int64_t Now
    );

//
// Checks Signature over Data with Key (picotls_cert_win.c). Returns
// QUIC_STATUS_SUCCESS only for a valid signature.
//
QUIC_STATUS
CxPlatPicotlsCryptoVerifySignature(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ const CXPLAT_PICOTLS_PUBLIC_KEY* Key,
    _In_ const CXPLAT_PICOTLS_SIGNATURE_ALGORITHM* Algorithm,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ size_t DataLength,
    _In_reads_bytes_(SignatureLength) const uint8_t* Signature,
    _In_ size_t SignatureLength
    );

typedef struct CXPLAT_PICOTLS_VERIFIER CXPLAT_PICOTLS_VERIFIER;

//
// Prepares to verify server certificates for a client credential: opens the
// algorithms and, in kernel mode, loads the trust store.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatPicotlsVerifierCreate(
    _In_ QUIC_CREDENTIAL_FLAGS Flags,
    _Outptr_ CXPLAT_PICOTLS_VERIFIER** Verifier
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPicotlsVerifierFree(
    _In_ CXPLAT_PICOTLS_VERIFIER* Verifier
    );

//
// The TLS 1.3 signature schemes CxPlatPicotlsVerifyCertificate accepts,
// terminated by UINT16_MAX: for ptls_verify_certificate_t.algos.
//
extern const uint16_t CxPlatPicotlsVerifyAlgorithms[];

//
// The body of a ptls_verify_certificate_t callback.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
int
CxPlatPicotlsVerifyCertificate(
    _In_ CXPLAT_PICOTLS_VERIFIER* Verifier,
    _In_opt_z_ const char* ServerName,
    _In_reads_(CertificateCount) const ptls_iovec_t* Certificates,
    _In_ size_t CertificateCount,
    _Out_ int (**VerifySign)(void* VerifyContext, uint16_t Algorithm, ptls_iovec_t Data, ptls_iovec_t Signature),
    _Out_ void** VerifyContext
    );

#if defined(__cplusplus)
}
#endif
