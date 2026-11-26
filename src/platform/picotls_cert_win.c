/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Server certificate loading and CertificateVerify signing for the picotls
    TLS provider on Windows, with BCrypt (and, in user mode, NCrypt for keys
    held by a Windows certificate store). See picotls_cert.h.

    Kernel mode:  CERTIFICATE_PKCS12.
    User mode:    CERTIFICATE_PKCS12, CERTIFICATE_FILE, CERTIFICATE_FILE_PROTECTED,
                  CERTIFICATE_HASH, CERTIFICATE_HASH_STORE, CERTIFICATE_CONTEXT.

    Signature schemes: rsa_pss_rsae_sha256/384/512 for RSA keys, and
    ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384 and ecdsa_secp521r1_sha512
    for EC keys on the matching curve.

    Server certificate verification (client side): the chain is validated
    with CertGetCertificateChain in user mode, and in kernel mode with
    picotls_x509.c against the machine's root store, read from the registry.
    The CertificateVerify signature is then checked with BCrypt.

--*/

#include "platform_internal.h"
#include "picotls_cert.h"
#include "picotls_der.h"
#include <limits.h>
#ifndef _KERNEL_MODE
#include <wincrypt.h>
#endif
#ifdef QUIC_CLOG
#include "picotls_cert_win.c.clog.h"
#endif

#ifdef _KERNEL_MODE
#define NtStatusToQuicStatus(x) (x)
#else
#define NtStatusToQuicStatus(x) HRESULT_FROM_WIN32(RtlNtStatusToDosError(x))
#endif

//
// Cryptographic primitives for the parser.
//

struct CXPLAT_PICOTLS_CRYPTO {
    BCRYPT_ALG_HANDLE Hash[4];
    BCRYPT_ALG_HANDLE Hmac[4];
    BCRYPT_ALG_HANDLE Aes;
    BCRYPT_ALG_HANDLE TripleDes;

    //
    // For signature verification.
    //
    BCRYPT_ALG_HANDLE Rsa;
    BCRYPT_ALG_HANDLE EcdsaP256;
    BCRYPT_ALG_HANDLE EcdsaP384;
    BCRYPT_ALG_HANDLE EcdsaP521;
};

static
LPCWSTR
HashAlgorithmName(
    _In_ CXPLAT_PICOTLS_HASH Hash
    )
{
    switch (Hash) {
    case CXPLAT_PICOTLS_HASH_SHA1: return BCRYPT_SHA1_ALGORITHM;
    case CXPLAT_PICOTLS_HASH_SHA256: return BCRYPT_SHA256_ALGORITHM;
    case CXPLAT_PICOTLS_HASH_SHA384: return BCRYPT_SHA384_ALGORITHM;
    default: return BCRYPT_SHA512_ALGORITHM;
    }
}

static
ULONG
HashAlgorithmLength(
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
QUIC_STATUS
OpenAlgorithm(
    _Inout_ BCRYPT_ALG_HANDLE* Handle,
    _In_z_ LPCWSTR Name,
    _In_ ULONG Flags
    )
{
    if (*Handle != NULL) {
        return QUIC_STATUS_SUCCESS;
    }
    NTSTATUS Status = BCryptOpenAlgorithmProvider(Handle, Name, NULL, Flags);
    if (!NT_SUCCESS(Status)) {
        *Handle = NULL;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptOpenAlgorithmProvider failed");
        return NtStatusToQuicStatus(Status);
    }
    return QUIC_STATUS_SUCCESS;
}

static
void
CloseAlgorithm(
    _Inout_ BCRYPT_ALG_HANDLE* Handle
    )
{
    if (*Handle != NULL) {
        BCryptCloseAlgorithmProvider(*Handle, 0);
        *Handle = NULL;
    }
}

static
void
CryptoClose(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto
    )
{
    for (size_t i = 0; i < ARRAYSIZE(Crypto->Hash); ++i) {
        CloseAlgorithm(&Crypto->Hash[i]);
        CloseAlgorithm(&Crypto->Hmac[i]);
    }
    CloseAlgorithm(&Crypto->Aes);
    CloseAlgorithm(&Crypto->TripleDes);
    CloseAlgorithm(&Crypto->Rsa);
    CloseAlgorithm(&Crypto->EcdsaP256);
    CloseAlgorithm(&Crypto->EcdsaP384);
    CloseAlgorithm(&Crypto->EcdsaP521);
}

//
// Hashes Data, or computes its HMAC when Secret is given (Algorithm must then
// have been opened with BCRYPT_ALG_HANDLE_HMAC_FLAG).
//
static
QUIC_STATUS
HashData(
    _In_ BCRYPT_ALG_HANDLE Algorithm,
    _In_reads_bytes_opt_(SecretLength) const uint8_t* Secret,
    _In_ ULONG SecretLength,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ size_t DataLength,
    _Out_writes_bytes_all_(OutputLength) uint8_t* Output,
    _In_ ULONG OutputLength
    )
{
    BCRYPT_HASH_HANDLE Hash = NULL;
    NTSTATUS Status;

    if (DataLength > ULONG_MAX) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status =
        BCryptCreateHash(
            Algorithm,
            &Hash,
            NULL,
            0,
            (PUCHAR)Secret,
            SecretLength,
            0);
    if (NT_SUCCESS(Status) && DataLength != 0) {
        Status = BCryptHashData(Hash, (PUCHAR)Data, (ULONG)DataLength, 0);
    }
    if (NT_SUCCESS(Status)) {
        Status = BCryptFinishHash(Hash, Output, OutputLength, 0);
    }
    if (Hash != NULL) {
        BCryptDestroyHash(Hash);
    }
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCrypt hash failed");
        return NtStatusToQuicStatus(Status);
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatPicotlsCryptoHash(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_PICOTLS_HASH Hash,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ size_t DataLength,
    _Out_writes_bytes_(64) uint8_t* Output
    )
{
    QUIC_STATUS Status = OpenAlgorithm(&Crypto->Hash[Hash], HashAlgorithmName(Hash), 0);
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    return
        HashData(
            Crypto->Hash[Hash], NULL, 0, Data, DataLength,
            Output, HashAlgorithmLength(Hash));
}

QUIC_STATUS
CxPlatPicotlsCryptoHmac(
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _In_ CXPLAT_PICOTLS_HASH Hash,
    _In_reads_bytes_(KeyLength) const uint8_t* Key,
    _In_ size_t KeyLength,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ size_t DataLength,
    _Out_writes_bytes_(64) uint8_t* Output
    )
{
    if (KeyLength > ULONG_MAX) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    QUIC_STATUS Status =
        OpenAlgorithm(
            &Crypto->Hmac[Hash], HashAlgorithmName(Hash), BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    return
        HashData(
            Crypto->Hmac[Hash], Key, (ULONG)KeyLength, Data, DataLength,
            Output, HashAlgorithmLength(Hash));
}

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
    )
{
    static UCHAR Empty = 0;

    if (PasswordLength > ULONG_MAX || SaltLength > ULONG_MAX || OutputLength > ULONG_MAX) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    QUIC_STATUS Status =
        OpenAlgorithm(
            &Crypto->Hmac[Prf], HashAlgorithmName(Prf), BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    NTSTATUS NtStatus =
        BCryptDeriveKeyPBKDF2(
            Crypto->Hmac[Prf],
            PasswordLength != 0 ? (PUCHAR)Password : &Empty,
            (ULONG)PasswordLength,
            SaltLength != 0 ? (PUCHAR)Salt : &Empty,
            (ULONG)SaltLength,
            Iterations == 0 ? 1 : Iterations,
            Output,
            (ULONG)OutputLength,
            0);
    if (!NT_SUCCESS(NtStatus)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            NtStatus,
            "BCryptDeriveKeyPBKDF2 failed");
        return NtStatusToQuicStatus(NtStatus);
    }
    return QUIC_STATUS_SUCCESS;
}

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
    )
{
    BCRYPT_ALG_HANDLE* Algorithm =
        Cipher == CXPLAT_PICOTLS_CIPHER_AES_CBC ? &Crypto->Aes : &Crypto->TripleDes;
    BCRYPT_KEY_HANDLE KeyHandle = NULL;
    uint8_t IvCopy[16];
    ULONG Result = 0;
    NTSTATUS NtStatus;

    if (KeyLength > 32 || IvLength > sizeof(IvCopy) || Length > ULONG_MAX) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (*Algorithm == NULL) {
        QUIC_STATUS Status =
            OpenAlgorithm(
                Algorithm,
                Cipher == CXPLAT_PICOTLS_CIPHER_AES_CBC ?
                    BCRYPT_AES_ALGORITHM : BCRYPT_3DES_ALGORITHM,
                0);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
        NtStatus =
            BCryptSetProperty(
                *Algorithm,
                BCRYPT_CHAINING_MODE,
                (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                sizeof(BCRYPT_CHAIN_MODE_CBC),
                0);
        if (!NT_SUCCESS(NtStatus)) {
            CloseAlgorithm(Algorithm);
            goto Error;
        }
    }

    NtStatus =
        BCryptGenerateSymmetricKey(
            *Algorithm,
            &KeyHandle,
            NULL,
            0,
            (PUCHAR)Key,
            (ULONG)KeyLength,
            0);
    if (!NT_SUCCESS(NtStatus)) {
        goto Error;
    }

    memcpy(IvCopy, Iv, IvLength); // BCryptDecrypt updates the IV.
    NtStatus =
        BCryptDecrypt(
            KeyHandle,
            Data,
            (ULONG)Length,
            NULL,
            IvCopy,
            (ULONG)IvLength,
            Data,
            (ULONG)Length,
            &Result,
            0);
    BCryptDestroyKey(KeyHandle);
    if (NT_SUCCESS(NtStatus)) {
        return Result == Length ? QUIC_STATUS_SUCCESS : QUIC_STATUS_INVALID_PARAMETER;
    }

Error:

    QuicTraceEvent(
        LibraryErrorStatus,
        "[ lib] ERROR, %u, %s.",
        NtStatus,
        "BCrypt CBC decryption failed");
    return NtStatusToQuicStatus(NtStatus);
}

//
// Signing.
//

struct CXPLAT_PICOTLS_SIGNER {
    CXPLAT_PICOTLS_KEY_TYPE Type;

    //
    // For EC keys: 256, 384 or 521.
    //
    uint32_t CurveBits;

    //
    // The key: imported into BCrypt, or (user mode) held by a certificate
    // store's key storage provider.
    //
    BCRYPT_ALG_HANDLE KeyAlgorithm;
    BCRYPT_KEY_HANDLE Key;
#ifndef _KERNEL_MODE
    NCRYPT_KEY_HANDLE NcryptKey;
#endif

    //
    // Digests for the CertificateVerify input, opened at load time (PASSIVE).
    //
    BCRYPT_ALG_HANDLE Sha256;
    BCRYPT_ALG_HANDLE Sha384;
    BCRYPT_ALG_HANDLE Sha512;
};

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPicotlsSignerFree(
    _In_ CXPLAT_PICOTLS_SIGNER* Signer
    )
{
    if (Signer->Key != NULL) {
        BCryptDestroyKey(Signer->Key);
    }
    CloseAlgorithm(&Signer->KeyAlgorithm);
#ifndef _KERNEL_MODE
    if (Signer->NcryptKey != 0) {
        NCryptFreeObject(Signer->NcryptKey);
    }
#endif
    CloseAlgorithm(&Signer->Sha256);
    CloseAlgorithm(&Signer->Sha384);
    CloseAlgorithm(&Signer->Sha512);
    CXPLAT_FREE(Signer, QUIC_POOL_TLS_SECCONF);
}

//
// Imports the decoded private key into BCrypt.
//
static
QUIC_STATUS
ImportPrivateKey(
    _In_ const CXPLAT_PICOTLS_PARSED_CREDENTIAL* Parsed,
    _Inout_ CXPLAT_PICOTLS_SIGNER* Signer
    )
{
    CXPLAT_PICOTLS_RAW_KEY Raw;
    LPCWSTR AlgorithmName = NULL;
    LPCWSTR BlobType = NULL;
    uint8_t* Blob = NULL;
    size_t BlobLength = 0;
    QUIC_STATUS Status;

    Status =
        CxPlatPicotlsDecodePrivateKey(
            Parsed->KeyDer, Parsed->KeyDerLength, Parsed->KeyFormat, &Raw);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    if (Raw.Type == CXPLAT_PICOTLS_KEY_RSA) {
        //
        // BCRYPT_RSAKEY_BLOB, then PublicExponent, Modulus, Prime1, Prime2,
        // all big-endian. BCrypt derives the remaining private values.
        //
        if (Raw.Modulus.len > 2048 || Raw.PublicExponent.len > 8 ||
            Raw.Prime1.len > Raw.Modulus.len || Raw.Prime2.len > Raw.Modulus.len) {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        BlobLength =
            sizeof(BCRYPT_RSAKEY_BLOB) +
            Raw.PublicExponent.len + Raw.Modulus.len + Raw.Prime1.len + Raw.Prime2.len;
        Blob = CXPLAT_ALLOC_NONPAGED(BlobLength, QUIC_POOL_TLS_PFX);
        if (Blob == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "RSA key blob",
                (uint64_t)BlobLength);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        uint32_t LeadingZeroBits = 0;
        while (LeadingZeroBits < 8 && !(Raw.Modulus.base[0] & (0x80 >> LeadingZeroBits))) {
            LeadingZeroBits++;
        }

        BCRYPT_RSAKEY_BLOB* Header = (BCRYPT_RSAKEY_BLOB*)Blob;
        Header->Magic = BCRYPT_RSAPRIVATE_MAGIC;
        Header->BitLength = (ULONG)(Raw.Modulus.len * 8 - LeadingZeroBits);
        Header->cbPublicExp = (ULONG)Raw.PublicExponent.len;
        Header->cbModulus = (ULONG)Raw.Modulus.len;
        Header->cbPrime1 = (ULONG)Raw.Prime1.len;
        Header->cbPrime2 = (ULONG)Raw.Prime2.len;
        uint8_t* Cursor = Blob + sizeof(BCRYPT_RSAKEY_BLOB);
        memcpy(Cursor, Raw.PublicExponent.base, Raw.PublicExponent.len);
        Cursor += Raw.PublicExponent.len;
        memcpy(Cursor, Raw.Modulus.base, Raw.Modulus.len);
        Cursor += Raw.Modulus.len;
        memcpy(Cursor, Raw.Prime1.base, Raw.Prime1.len);
        Cursor += Raw.Prime1.len;
        memcpy(Cursor, Raw.Prime2.base, Raw.Prime2.len);

        AlgorithmName = BCRYPT_RSA_ALGORITHM;
        BlobType = BCRYPT_RSAPRIVATE_BLOB;

    } else {
        //
        // BCRYPT_ECCKEY_BLOB, then X, Y and d, each the size of the field.
        //
        ULONG Magic;
        switch (Raw.CurveBits) {
        case 256:
            Magic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
            AlgorithmName = BCRYPT_ECDSA_P256_ALGORITHM;
            break;
        case 384:
            Magic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
            AlgorithmName = BCRYPT_ECDSA_P384_ALGORITHM;
            break;
        default:
            Magic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
            AlgorithmName = BCRYPT_ECDSA_P521_ALGORITHM;
            break;
        }
        const size_t FieldLength = (Raw.CurveBits + 7) / 8;
        if (Raw.PublicPoint.len != 1 + 2 * FieldLength ||
            Raw.PrivateScalar.len > FieldLength) {
            return QUIC_STATUS_INVALID_PARAMETER; // Checked by the decoder.
        }
        BlobLength = sizeof(BCRYPT_ECCKEY_BLOB) + 3 * FieldLength;
        Blob = CXPLAT_ALLOC_NONPAGED(BlobLength, QUIC_POOL_TLS_PFX);
        if (Blob == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "EC key blob",
                (uint64_t)BlobLength);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        CxPlatZeroMemory(Blob, BlobLength);

        BCRYPT_ECCKEY_BLOB* Header = (BCRYPT_ECCKEY_BLOB*)Blob;
        Header->dwMagic = Magic;
        Header->cbKey = (ULONG)FieldLength;
        uint8_t* Cursor = Blob + sizeof(BCRYPT_ECCKEY_BLOB);
        memcpy(Cursor, Raw.PublicPoint.base + 1, 2 * FieldLength);
        Cursor += 2 * FieldLength;
        memcpy(
            Cursor + FieldLength - Raw.PrivateScalar.len,
            Raw.PrivateScalar.base,
            Raw.PrivateScalar.len);

        BlobType = BCRYPT_ECCPRIVATE_BLOB;
        Signer->CurveBits = Raw.CurveBits;
    }

    Signer->Type = Raw.Type;

    Status = OpenAlgorithm(&Signer->KeyAlgorithm, AlgorithmName, 0);
    if (QUIC_SUCCEEDED(Status)) {
        NTSTATUS NtStatus =
            BCryptImportKeyPair(
                Signer->KeyAlgorithm,
                NULL,
                BlobType,
                &Signer->Key,
                Blob,
                (ULONG)BlobLength,
                0);
        if (!NT_SUCCESS(NtStatus)) {
            Signer->Key = NULL;
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                NtStatus,
                "BCryptImportKeyPair failed");
            Status = NtStatusToQuicStatus(NtStatus);
        }
    }

    CxPlatPicotlsSecureZero(Blob, BlobLength);
    CXPLAT_FREE(Blob, QUIC_POOL_TLS_PFX);
    return Status;
}

#ifndef _KERNEL_MODE

//
// Reads a whole (small) file into a QUIC_POOL_TLS_PFX buffer.
//
static
QUIC_STATUS
ReadWholeFile(
    _In_z_ const char* Path,
    _Outptr_result_buffer_(*Length) char** Contents,
    _Out_ size_t* Length
    )
{
    const LONGLONG MaxFileSize = 1024 * 1024;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    LARGE_INTEGER Size;
    char* Buffer = NULL;
    DWORD Read = 0;

    *Contents = NULL;
    *Length = 0;

    HANDLE File =
        CreateFileA(
            Path,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (File == INVALID_HANDLE_VALUE) {
        DWORD Error = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "CreateFileA failed");
        return HRESULT_FROM_WIN32(Error);
    }

    if (!GetFileSizeEx(File, &Size)) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }
    if (Size.QuadPart > MaxFileSize) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    Buffer = CXPLAT_ALLOC_NONPAGED((size_t)Size.QuadPart + 1, QUIC_POOL_TLS_PFX);
    if (Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PEM file",
            (uint64_t)Size.QuadPart + 1);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    if (!ReadFile(File, Buffer, (DWORD)Size.QuadPart, &Read, NULL)) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }
    Buffer[Read] = 0;

    *Contents = Buffer;
    *Length = Read;
    Buffer = NULL;

Exit:

    if (Buffer != NULL) {
        CXPLAT_FREE(Buffer, QUIC_POOL_TLS_PFX);
    }
    CloseHandle(File);
    return Status;
}

static
QUIC_STATUS
LoadPemFiles(
    _In_z_ const char* CertificateFile,
    _In_z_ const char* PrivateKeyFile,
    _In_opt_z_ const char* Password,
    _Inout_ CXPLAT_PICOTLS_CRYPTO* Crypto,
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Parsed
    )
{
    char* Contents = NULL;
    size_t Length = 0;

    QUIC_STATUS Status = ReadWholeFile(CertificateFile, &Contents, &Length);
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    Status = CxPlatPicotlsParsePemCertificates(Contents, Length, Parsed);
    CXPLAT_FREE(Contents, QUIC_POOL_TLS_PFX);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    Status = ReadWholeFile(PrivateKeyFile, &Contents, &Length);
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    Status = CxPlatPicotlsParsePemPrivateKey(Contents, Length, Password, Crypto, Parsed);
    CxPlatPicotlsSecureZero(Contents, Length);
    CXPLAT_FREE(Contents, QUIC_POOL_TLS_PFX);
    return Status;
}

//
// Uses a certificate from a Windows certificate store: the leaf certificate
// is sent on its own, and its key is used through NCrypt.
//
static
QUIC_STATUS
LoadFromStore(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Inout_ CXPLAT_PICOTLS_PARSED_CREDENTIAL* Parsed,
    _Inout_ CXPLAT_PICOTLS_SIGNER* Signer
    )
{
    QUIC_CERTIFICATE* Certificate = NULL;
    NCRYPT_KEY_HANDLE Key = 0;
    WCHAR AlgorithmGroup[32];
    DWORD Bits = 0;
    DWORD Length = 0;
    SECURITY_STATUS SecStatus;

    QUIC_STATUS Status = CxPlatCertCreate(CredConfig, &Certificate);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatCertCreate failed");
        return Status;
    }
    PCCERT_CONTEXT CertContext = (PCCERT_CONTEXT)Certificate;

    Status =
        CxPlatPicotlsCredentialAddCertificate(
            Parsed, CertContext->pbCertEncoded, CertContext->cbCertEncoded);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    Key = (NCRYPT_KEY_HANDLE)CxPlatCertGetPrivateKey(Certificate);
    if (Key == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER; // No (CNG) private key.
        goto Exit;
    }

    SecStatus =
        NCryptGetProperty(
            Key,
            NCRYPT_ALGORITHM_GROUP_PROPERTY,
            (PBYTE)AlgorithmGroup,
            sizeof(AlgorithmGroup),
            &Length,
            0);
    if (FAILED(SecStatus)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "NCryptGetProperty(NCRYPT_ALGORITHM_GROUP_PROPERTY) failed");
        Status = SecStatus;
        goto Exit;
    }
    AlgorithmGroup[ARRAYSIZE(AlgorithmGroup) - 1] = L'\0';

    if (wcscmp(AlgorithmGroup, NCRYPT_RSA_ALGORITHM_GROUP) == 0) {
        Signer->Type = CXPLAT_PICOTLS_KEY_RSA;
    } else if (wcscmp(AlgorithmGroup, NCRYPT_ECDSA_ALGORITHM_GROUP) == 0) {
        SecStatus =
            NCryptGetProperty(
                Key,
                NCRYPT_LENGTH_PROPERTY,
                (PBYTE)&Bits,
                sizeof(Bits),
                &Length,
                0);
        if (FAILED(SecStatus) || (Bits != 256 && Bits != 384 && Bits != 521)) {
            Status = QUIC_STATUS_NOT_SUPPORTED;
            goto Exit;
        }
        Signer->Type = CXPLAT_PICOTLS_KEY_EC;
        Signer->CurveBits = Bits;
    } else {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Certificate key is neither RSA nor ECDSA");
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    Signer->NcryptKey = Key;
    Key = 0;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (Key != 0) {
        NCryptFreeObject(Key);
    }
    if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        CxPlatCertFree(Certificate); // Looked up by CxPlatCertCreate.
    }
    return Status;
}

#endif // !_KERNEL_MODE

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatPicotlsLoadCredential(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Outptr_result_buffer_(*CertificateCount) ptls_iovec_t** Certificates,
    _Out_ size_t* CertificateCount,
    _Outptr_ CXPLAT_PICOTLS_SIGNER** Signer
    )
{
    CXPLAT_PICOTLS_CRYPTO Crypto;
    CXPLAT_PICOTLS_PARSED_CREDENTIAL Parsed;
    QUIC_STATUS Status;

    *Certificates = NULL;
    *CertificateCount = 0;
    *Signer = NULL;
    CxPlatZeroMemory(&Crypto, sizeof(Crypto));
    CxPlatZeroMemory(&Parsed, sizeof(Parsed));

    CXPLAT_PICOTLS_SIGNER* NewSigner =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_PICOTLS_SIGNER), QUIC_POOL_TLS_SECCONF);
    if (NewSigner == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_PICOTLS_SIGNER",
            sizeof(CXPLAT_PICOTLS_SIGNER));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(NewSigner, sizeof(*NewSigner));

    switch (CredConfig->Type) {
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12:
        Status =
            CxPlatPicotlsParsePkcs12(
                CredConfig->CertificatePkcs12->Asn1Blob,
                CredConfig->CertificatePkcs12->Asn1BlobLength,
                CredConfig->CertificatePkcs12->PrivateKeyPassword,
                &Crypto,
                &Parsed);
        break;
#ifndef _KERNEL_MODE
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
        Status =
            LoadPemFiles(
                CredConfig->CertificateFile->CertificateFile,
                CredConfig->CertificateFile->PrivateKeyFile,
                NULL,
                &Crypto,
                &Parsed);
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED:
        Status =
            LoadPemFiles(
                CredConfig->CertificateFileProtected->CertificateFile,
                CredConfig->CertificateFileProtected->PrivateKeyFile,
                CredConfig->CertificateFileProtected->PrivateKeyPassword,
                &Crypto,
                &Parsed);
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
        Status = LoadFromStore(CredConfig, &Parsed, NewSigner);
        break;
#endif
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        break;
    }
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    if (Parsed.KeyDer != NULL) {
        Status = ImportPrivateKey(&Parsed, NewSigner);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    if (NewSigner->Type == CXPLAT_PICOTLS_KEY_RSA ||
        NewSigner->CurveBits == 256) {
        Status = OpenAlgorithm(&NewSigner->Sha256, BCRYPT_SHA256_ALGORITHM, 0);
    }
    if (QUIC_SUCCEEDED(Status) &&
        (NewSigner->Type == CXPLAT_PICOTLS_KEY_RSA || NewSigner->CurveBits == 384)) {
        Status = OpenAlgorithm(&NewSigner->Sha384, BCRYPT_SHA384_ALGORITHM, 0);
    }
    if (QUIC_SUCCEEDED(Status) &&
        (NewSigner->Type == CXPLAT_PICOTLS_KEY_RSA || NewSigner->CurveBits == 521)) {
        Status = OpenAlgorithm(&NewSigner->Sha512, BCRYPT_SHA512_ALGORITHM, 0);
    }
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    *Certificates = Parsed.Certificates;
    *CertificateCount = Parsed.CertificateCount;
    Parsed.Certificates = NULL;
    Parsed.CertificateCount = 0;
    *Signer = NewSigner;
    NewSigner = NULL;

Exit:

    CxPlatPicotlsCredentialClear(&Parsed);
    CryptoClose(&Crypto);
    if (NewSigner != NULL) {
        CxPlatPicotlsSignerFree(NewSigner);
    }
    return Status;
}

//
// Picks the digest for a TLS 1.3 SignatureScheme, if the key supports it.
//
static
BOOLEAN
SchemeDigest(
    _In_ const CXPLAT_PICOTLS_SIGNER* Signer,
    _In_ uint16_t Scheme,
    _Out_ BCRYPT_ALG_HANDLE* Digest,
    _Out_ LPCWSTR* DigestName,
    _Out_ ULONG* DigestLength
    )
{
    *Digest = NULL;
    *DigestName = NULL;
    *DigestLength = 0;

    uint32_t Bits;
    if (Signer->Type == CXPLAT_PICOTLS_KEY_RSA) {
        switch (Scheme) {
        case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256: Bits = 256; break;
        case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384: Bits = 384; break;
        case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512: Bits = 512; break;
        default: return FALSE;
        }
    } else {
        //
        // In TLS 1.3 each ECDSA scheme is bound to one curve.
        //
        if (Scheme == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 && Signer->CurveBits == 256) {
            Bits = 256;
        } else if (Scheme == PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 && Signer->CurveBits == 384) {
            Bits = 384;
        } else if (Scheme == PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512 && Signer->CurveBits == 521) {
            Bits = 512;
        } else {
            return FALSE;
        }
    }

    switch (Bits) {
    case 256:
        *Digest = Signer->Sha256;
        *DigestName = BCRYPT_SHA256_ALGORITHM;
        *DigestLength = 32;
        break;
    case 384:
        *Digest = Signer->Sha384;
        *DigestName = BCRYPT_SHA384_ALGORITHM;
        *DigestLength = 48;
        break;
    default:
        *Digest = Signer->Sha512;
        *DigestName = BCRYPT_SHA512_ALGORITHM;
        *DigestLength = 64;
        break;
    }
    return *Digest != NULL;
}

//
// Writes a DER INTEGER holding the unsigned big-endian Value.
//
static
size_t
EncodeDerInteger(
    _In_reads_bytes_(Length) const uint8_t* Value,
    _In_ size_t Length,
    _Out_writes_bytes_to_opt_(70, return) uint8_t* Output
    )
{
    while (Length > 1 && Value[0] == 0) {
        Value++;
        Length--;
    }
    const BOOLEAN Pad = (Value[0] & 0x80) != 0;
    const size_t ContentLength = Length + (Pad ? 1 : 0);
    if (Output != NULL) {
        size_t i = 0;
        Output[i++] = 0x02;
        Output[i++] = (uint8_t)ContentLength;
        if (Pad) {
            Output[i++] = 0;
        }
        memcpy(Output + i, Value, Length);
    }
    return 2 + ContentLength;
}

int
CxPlatPicotlsSign(
    _In_ CXPLAT_PICOTLS_SIGNER* Signer,
    _In_ ptls_iovec_t Input,
    _In_reads_(AlgorithmCount) const uint16_t* Algorithms,
    _In_ size_t AlgorithmCount,
    _Out_ uint16_t* SelectedAlgorithm,
    _Inout_ ptls_buffer_t* Output
    )
{
    BCRYPT_ALG_HANDLE Digest = NULL;
    LPCWSTR DigestName = NULL;
    ULONG DigestLength = 0;
    uint8_t Hash[64];
    size_t i;
    int Ret;

    *SelectedAlgorithm = 0;

    //
    // Take the first scheme in the peer's order of preference the key supports.
    //
    for (i = 0; i < AlgorithmCount; ++i) {
        if (SchemeDigest(Signer, Algorithms[i], &Digest, &DigestName, &DigestLength)) {
            break;
        }
    }
    if (i == AlgorithmCount) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No signature algorithm in common with the peer");
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }

    if (QUIC_FAILED(HashData(Digest, NULL, 0, Input.base, Input.len, Hash, DigestLength))) {
        return PTLS_ERROR_LIBRARY;
    }

    if (Signer->Type == CXPLAT_PICOTLS_KEY_RSA) {
        BCRYPT_PSS_PADDING_INFO Padding = { DigestName, DigestLength };
        ULONG SignatureLength = 0;

        //
        // The first call reports the signature length.
        //
#ifndef _KERNEL_MODE
        if (Signer->NcryptKey != 0) {
            SECURITY_STATUS SecStatus =
                NCryptSignHash(
                    Signer->NcryptKey, &Padding, Hash, DigestLength,
                    NULL, 0, &SignatureLength, NCRYPT_PAD_PSS_FLAG);
            if (FAILED(SecStatus)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    SecStatus,
                    "NCryptSignHash failed");
                return PTLS_ERROR_LIBRARY;
            }
            if ((Ret = ptls_buffer_reserve(Output, SignatureLength)) != 0) {
                return Ret;
            }
            SecStatus =
                NCryptSignHash(
                    Signer->NcryptKey, &Padding, Hash, DigestLength,
                    Output->base + Output->off, SignatureLength, &SignatureLength,
                    NCRYPT_PAD_PSS_FLAG);
            if (FAILED(SecStatus)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    SecStatus,
                    "NCryptSignHash failed");
                return PTLS_ERROR_LIBRARY;
            }
        } else
#endif
        {
            NTSTATUS NtStatus =
                BCryptSignHash(
                    Signer->Key, &Padding, Hash, DigestLength,
                    NULL, 0, &SignatureLength, BCRYPT_PAD_PSS);
            if (!NT_SUCCESS(NtStatus)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    NtStatus,
                    "BCryptSignHash failed");
                return PTLS_ERROR_LIBRARY;
            }
            if ((Ret = ptls_buffer_reserve(Output, SignatureLength)) != 0) {
                return Ret;
            }
            NtStatus =
                BCryptSignHash(
                    Signer->Key, &Padding, Hash, DigestLength,
                    Output->base + Output->off, SignatureLength, &SignatureLength,
                    BCRYPT_PAD_PSS);
            if (!NT_SUCCESS(NtStatus)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    NtStatus,
                    "BCryptSignHash failed");
                return PTLS_ERROR_LIBRARY;
            }
        }
        Output->off += SignatureLength;

    } else {
        //
        // CNG returns r || s; TLS wants Ecdsa-Sig-Value ::= SEQUENCE { r, s }.
        //
        const ULONG FieldLength = (Signer->CurveBits + 7) / 8;
        uint8_t Raw[2 * 66];
        ULONG RawLength = 0;

#ifndef _KERNEL_MODE
        if (Signer->NcryptKey != 0) {
            SECURITY_STATUS SecStatus =
                NCryptSignHash(
                    Signer->NcryptKey, NULL, Hash, DigestLength,
                    Raw, 2 * FieldLength, &RawLength, 0);
            if (FAILED(SecStatus)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    SecStatus,
                    "NCryptSignHash failed");
                return PTLS_ERROR_LIBRARY;
            }
        } else
#endif
        {
            NTSTATUS NtStatus =
                BCryptSignHash(
                    Signer->Key, NULL, Hash, DigestLength,
                    Raw, 2 * FieldLength, &RawLength, 0);
            if (!NT_SUCCESS(NtStatus)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    NtStatus,
                    "BCryptSignHash failed");
                return PTLS_ERROR_LIBRARY;
            }
        }
        if (RawLength != 2 * FieldLength) {
            return PTLS_ERROR_LIBRARY;
        }

        const size_t RLength = EncodeDerInteger(Raw, FieldLength, NULL);
        const size_t SLength = EncodeDerInteger(Raw + FieldLength, FieldLength, NULL);
        const size_t ContentLength = RLength + SLength;
        const size_t HeaderLength = ContentLength < 0x80 ? 2 : 3;
        if ((Ret = ptls_buffer_reserve(Output, HeaderLength + ContentLength)) != 0) {
            return Ret;
        }
        uint8_t* Cursor = Output->base + Output->off;
        *Cursor++ = 0x30;
        if (HeaderLength == 3) {
            *Cursor++ = 0x81;
        }
        *Cursor++ = (uint8_t)ContentLength;
        Cursor += EncodeDerInteger(Raw, FieldLength, Cursor);
        (void)EncodeDerInteger(Raw + FieldLength, FieldLength, Cursor);
        Output->off += HeaderLength + ContentLength;
    }

    *SelectedAlgorithm = Algorithms[i];
    return 0;
}

//
// Signature verification.
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
    )
{
    uint8_t Hash[64];
    uint8_t RawSignature[2 * 66];
    uint8_t* Blob = NULL;
    size_t BlobLength;
    LPCWSTR BlobType;
    BCRYPT_ALG_HANDLE* KeyAlgorithm;
    LPCWSTR KeyAlgorithmName;
    BCRYPT_KEY_HANDLE KeyHandle = NULL;
    QUIC_STATUS Status;

    if (Algorithm->Hash == CXPLAT_PICOTLS_HASH_SHA1 ||
        SignatureLength > ULONG_MAX ||
        (Key->Type == CXPLAT_PICOTLS_KEY_RSA) ==
            (Algorithm->Padding == CXPLAT_PICOTLS_PADDING_ECDSA)) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    const ULONG HashLength = HashAlgorithmLength(Algorithm->Hash);
    Status = CxPlatPicotlsCryptoHash(Crypto, Algorithm->Hash, Data, DataLength, Hash);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    if (Key->Type == CXPLAT_PICOTLS_KEY_RSA) {
        //
        // BCRYPT_RSAKEY_BLOB, then PublicExponent and Modulus, big-endian.
        //
        if (Key->Modulus.len == 0 || Key->Modulus.len > 2048 ||
            Key->PublicExponent.len == 0 || Key->PublicExponent.len > 8) {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        BlobLength = sizeof(BCRYPT_RSAKEY_BLOB) + Key->PublicExponent.len + Key->Modulus.len;
        Blob = CXPLAT_ALLOC_NONPAGED(BlobLength, QUIC_POOL_TLS_CERT_DER);
        if (Blob == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "RSA public key blob",
                (uint64_t)BlobLength);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        uint32_t LeadingZeroBits = 0;
        while (LeadingZeroBits < 8 && !(Key->Modulus.base[0] & (0x80 >> LeadingZeroBits))) {
            LeadingZeroBits++;
        }
        BCRYPT_RSAKEY_BLOB* Header = (BCRYPT_RSAKEY_BLOB*)Blob;
        CxPlatZeroMemory(Header, sizeof(*Header));
        Header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        Header->BitLength = (ULONG)(Key->Modulus.len * 8 - LeadingZeroBits);
        Header->cbPublicExp = (ULONG)Key->PublicExponent.len;
        Header->cbModulus = (ULONG)Key->Modulus.len;
        memcpy(Blob + sizeof(*Header), Key->PublicExponent.base, Key->PublicExponent.len);
        memcpy(
            Blob + sizeof(*Header) + Key->PublicExponent.len,
            Key->Modulus.base,
            Key->Modulus.len);
        BlobType = BCRYPT_RSAPUBLIC_BLOB;
        KeyAlgorithm = &Crypto->Rsa;
        KeyAlgorithmName = BCRYPT_RSA_ALGORITHM;

    } else {
        //
        // BCRYPT_ECCKEY_BLOB, then X and Y.
        //
        ULONG Magic;
        switch (Key->CurveBits) {
        case 256:
            Magic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            KeyAlgorithm = &Crypto->EcdsaP256;
            KeyAlgorithmName = BCRYPT_ECDSA_P256_ALGORITHM;
            break;
        case 384:
            Magic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
            KeyAlgorithm = &Crypto->EcdsaP384;
            KeyAlgorithmName = BCRYPT_ECDSA_P384_ALGORITHM;
            break;
        case 521:
            Magic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
            KeyAlgorithm = &Crypto->EcdsaP521;
            KeyAlgorithmName = BCRYPT_ECDSA_P521_ALGORITHM;
            break;
        default:
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        const size_t FieldLength = (Key->CurveBits + 7) / 8;
        if (Key->PublicPoint.len != 1 + 2 * FieldLength || Key->PublicPoint.base[0] != 0x04) {
            return QUIC_STATUS_NOT_SUPPORTED;
        }

        //
        // TLS and X.509 carry Ecdsa-Sig-Value ::= SEQUENCE { r, s }; CNG
        // wants r || s, each the size of the field.
        //
        CXPLAT_DER In = { Signature, SignatureLength };
        CXPLAT_DER Sequence;
        ptls_iovec_t R, S;
        if (!DerExpect(&In, DER_SEQUENCE, &Sequence) || In.Length != 0 ||
            !DerBigInteger(&Sequence, &R) || !DerBigInteger(&Sequence, &S) ||
            Sequence.Length != 0 ||
            R.len > FieldLength || S.len > FieldLength) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        CxPlatZeroMemory(RawSignature, sizeof(RawSignature));
        memcpy(RawSignature + FieldLength - R.len, R.base, R.len);
        memcpy(RawSignature + 2 * FieldLength - S.len, S.base, S.len);
        Signature = RawSignature;
        SignatureLength = 2 * FieldLength;

        BlobLength = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * FieldLength;
        Blob = CXPLAT_ALLOC_NONPAGED(BlobLength, QUIC_POOL_TLS_CERT_DER);
        if (Blob == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "EC public key blob",
                (uint64_t)BlobLength);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        BCRYPT_ECCKEY_BLOB* Header = (BCRYPT_ECCKEY_BLOB*)Blob;
        Header->dwMagic = Magic;
        Header->cbKey = (ULONG)FieldLength;
        memcpy(Blob + sizeof(*Header), Key->PublicPoint.base + 1, 2 * FieldLength);
        BlobType = BCRYPT_ECCPUBLIC_BLOB;
    }

    Status = OpenAlgorithm(KeyAlgorithm, KeyAlgorithmName, 0);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    NTSTATUS NtStatus =
        BCryptImportKeyPair(
            *KeyAlgorithm,
            NULL,
            BlobType,
            &KeyHandle,
            Blob,
            (ULONG)BlobLength,
            0);
    if (!NT_SUCCESS(NtStatus)) {
        KeyHandle = NULL;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            NtStatus,
            "BCryptImportKeyPair (public key) failed");
        Status = NtStatusToQuicStatus(NtStatus);
        goto Exit;
    }

    BCRYPT_PKCS1_PADDING_INFO Pkcs1 = { HashAlgorithmName(Algorithm->Hash) };
    BCRYPT_PSS_PADDING_INFO Pss = { HashAlgorithmName(Algorithm->Hash), Algorithm->SaltLength };
    void* PaddingInfo = NULL;
    ULONG Flags = 0;
    if (Algorithm->Padding == CXPLAT_PICOTLS_PADDING_RSA_PKCS1) {
        PaddingInfo = &Pkcs1;
        Flags = BCRYPT_PAD_PKCS1;
    } else if (Algorithm->Padding == CXPLAT_PICOTLS_PADDING_RSA_PSS) {
        PaddingInfo = &Pss;
        Flags = BCRYPT_PAD_PSS;
    }
    NtStatus =
        BCryptVerifySignature(
            KeyHandle,
            PaddingInfo,
            Hash,
            HashLength,
            (PUCHAR)Signature,
            (ULONG)SignatureLength,
            Flags);
    if (!NT_SUCCESS(NtStatus)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            NtStatus,
            "BCryptVerifySignature failed");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (KeyHandle != NULL) {
        BCryptDestroyKey(KeyHandle);
    }
    CXPLAT_FREE(Blob, QUIC_POOL_TLS_CERT_DER);
    return Status;
}

//
// Server certificate verification.
//

struct CXPLAT_PICOTLS_VERIFIER {
    QUIC_CREDENTIAL_FLAGS Flags;

    //
    // Every algorithm is opened up front, so that connections sharing the
    // verifier only read it.
    //
    CXPLAT_PICOTLS_CRYPTO Crypto;

#ifdef _KERNEL_MODE
    //
    // Anchors[i].Der and Disallowed[i].base are allocated with
    // QUIC_POOL_TLS_CERT_DER, from paged pool.
    //
    CXPLAT_PICOTLS_TRUST_STORE TrustStore;
#endif
};

const uint16_t CxPlatPicotlsVerifyAlgorithms[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
    PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
    //
    // Only for the signatures in certificates (RFC 8446, Section 4.2.3):
    // the CertificateVerify can't use them.
    //
    PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
    UINT16_MAX
};

#ifdef _KERNEL_MODE

//
// The registry keys of the stores CryptoAPI combines into the machine's Root
// store, and those it combines into its Disallowed store.
//
static const PCWSTR RootStoreKeys[] = {
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates",
    L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates",
};

static const PCWSTR DisallowedStoreKeys[] = {
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed\\Certificates",
    L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Disallowed\\Certificates",
};

#define CXPLAT_PICOTLS_MAX_STORE_CERTIFICATES 4096
#define CXPLAT_PICOTLS_MAX_STORE_BLOB (64 * 1024)

//
// The property of a serialized certificate that holds its encoding.
//
#define CERT_CERT_PROP_ID 32

typedef struct CXPLAT_PICOTLS_DER_LIST {
    ptls_iovec_t* Items;
    size_t Count;
    size_t Capacity;
} CXPLAT_PICOTLS_DER_LIST;

static
void
DerListFree(
    _Inout_ CXPLAT_PICOTLS_DER_LIST* List
    )
{
    for (size_t i = 0; i < List->Count; ++i) {
        CXPLAT_FREE(List->Items[i].base, QUIC_POOL_TLS_CERT_DER);
    }
    if (List->Items != NULL) {
        CXPLAT_FREE(List->Items, QUIC_POOL_TLS_CERT_DER);
    }
    CxPlatZeroMemory(List, sizeof(*List));
}

static
QUIC_STATUS
DerListAppend(
    _Inout_ CXPLAT_PICOTLS_DER_LIST* List,
    _In_reads_bytes_(Length) const uint8_t* Der,
    _In_ size_t Length
    )
{
    if (List->Count == CXPLAT_PICOTLS_MAX_STORE_CERTIFICATES) {
        return QUIC_STATUS_SUCCESS; // Ignore the rest.
    }
    if (List->Count == List->Capacity) {
        const size_t NewCapacity = List->Capacity == 0 ? 64 : List->Capacity * 2;
        ptls_iovec_t* NewItems =
            CXPLAT_ALLOC_PAGED(NewCapacity * sizeof(ptls_iovec_t), QUIC_POOL_TLS_CERT_DER);
        if (NewItems == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Trust store list",
                (uint64_t)(NewCapacity * sizeof(ptls_iovec_t)));
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        if (List->Count != 0) {
            memcpy(NewItems, List->Items, List->Count * sizeof(ptls_iovec_t));
        }
        if (List->Items != NULL) {
            CXPLAT_FREE(List->Items, QUIC_POOL_TLS_CERT_DER);
        }
        List->Items = NewItems;
        List->Capacity = NewCapacity;
    }
    uint8_t* Copy = CXPLAT_ALLOC_PAGED(Length, QUIC_POOL_TLS_CERT_DER);
    if (Copy == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Trust store certificate",
            (uint64_t)Length);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    memcpy(Copy, Der, Length);
    ANALYSIS_SUPPRESS(6386) // Items holds Capacity > Count entries.
    List->Items[List->Count++] = ptls_iovec_init(Copy, Length);
    return QUIC_STATUS_SUCCESS;
}

//
// Finds the encoded certificate in a serialized certificate (the "Blob" value
// of a certificate in the registry): a sequence of properties, each a 32-bit
// ID, a 32-bit reserved field and a 32-bit length (little-endian), then the
// value.
//
static
BOOLEAN
FindEncodedCertificate(
    _In_reads_bytes_(Length) const uint8_t* Blob,
    _In_ size_t Length,
    _Out_ ptls_iovec_t* Der
    )
{
    *Der = ptls_iovec_init(NULL, 0);
    while (Length >= 12) {
        const uint32_t Id =
            (uint32_t)Blob[0] | ((uint32_t)Blob[1] << 8) |
            ((uint32_t)Blob[2] << 16) | ((uint32_t)Blob[3] << 24);
        const uint32_t ValueLength =
            (uint32_t)Blob[8] | ((uint32_t)Blob[9] << 8) |
            ((uint32_t)Blob[10] << 16) | ((uint32_t)Blob[11] << 24);
        if (ValueLength > Length - 12) {
            return FALSE;
        }
        if (Id == CERT_CERT_PROP_ID) {
            *Der = ptls_iovec_init(Blob + 12, ValueLength);
            return ValueLength != 0;
        }
        Blob += 12 + (size_t)ValueLength;
        Length -= 12 + (size_t)ValueLength;
    }
    return FALSE;
}

//
// Adds the certificates of one registry store (a key with a subkey, named by
// the thumbprint, per certificate) to List. A store that doesn't exist is
// empty.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
LoadRegistryStore(
    _In_z_ PCWSTR Path,
    _Inout_ CXPLAT_PICOTLS_DER_LIST* List
    )
{
    UNICODE_STRING KeyName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE StoreKey = NULL;
    uint8_t* Value = NULL;
    const ULONG ValueAllocLength =
        FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + CXPLAT_PICOTLS_MAX_STORE_BLOB;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DECLARE_CONST_UNICODE_STRING(BlobName, L"Blob");

    RtlInitUnicodeString(&KeyName, Path);
    InitializeObjectAttributes(
        &Attributes,
        &KeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    NTSTATUS NtStatus = ZwOpenKey(&StoreKey, KEY_READ, &Attributes);
    if (!NT_SUCCESS(NtStatus)) {
        return QUIC_STATUS_SUCCESS;
    }

    Value = CXPLAT_ALLOC_PAGED(ValueAllocLength, QUIC_POOL_TLS_CERT_DER);
    if (Value == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Registry certificate blob",
            (uint64_t)ValueAllocLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    for (ULONG Index = 0; ; ++Index) {
        union {
            KEY_BASIC_INFORMATION Info;
            uint8_t Buffer[sizeof(KEY_BASIC_INFORMATION) + 256 * sizeof(WCHAR)];
        } SubkeyInfo;
        ULONG ResultLength = 0;
        NtStatus =
            ZwEnumerateKey(
                StoreKey,
                Index,
                KeyBasicInformation,
                &SubkeyInfo,
                sizeof(SubkeyInfo),
                &ResultLength);
        if (NtStatus == STATUS_NO_MORE_ENTRIES) {
            break;
        }
        if (!NT_SUCCESS(NtStatus) ||
            SubkeyInfo.Info.NameLength > 256 * sizeof(WCHAR)) {
            continue; // A name too long for a thumbprint.
        }

        UNICODE_STRING SubkeyName;
        SubkeyName.Buffer = SubkeyInfo.Info.Name;
        SubkeyName.Length = (USHORT)SubkeyInfo.Info.NameLength;
        SubkeyName.MaximumLength = (USHORT)SubkeyInfo.Info.NameLength;
        InitializeObjectAttributes(
            &Attributes,
            &SubkeyName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            StoreKey,
            NULL);
        HANDLE CertificateKey = NULL;
        if (!NT_SUCCESS(ZwOpenKey(&CertificateKey, KEY_READ, &Attributes))) {
            continue;
        }
        NtStatus =
            ZwQueryValueKey(
                CertificateKey,
                (PUNICODE_STRING)&BlobName,
                KeyValuePartialInformation,
                Value,
                ValueAllocLength,
                &ResultLength);
        ZwClose(CertificateKey);
        if (!NT_SUCCESS(NtStatus)) {
            continue;
        }

        const KEY_VALUE_PARTIAL_INFORMATION* Partial =
            (const KEY_VALUE_PARTIAL_INFORMATION*)Value;
        ptls_iovec_t Der;
        if (Partial->Type == REG_BINARY &&
            Partial->DataLength <= CXPLAT_PICOTLS_MAX_STORE_BLOB &&
            FindEncodedCertificate(Partial->Data, Partial->DataLength, &Der)) {
            Status = DerListAppend(List, Der.base, Der.len);
            if (QUIC_FAILED(Status)) {
                goto Exit;
            }
        }
    }

Exit:

    if (Value != NULL) {
        CXPLAT_FREE(Value, QUIC_POOL_TLS_CERT_DER);
    }
    ZwClose(StoreKey);
    return Status;
}

static
void
TrustStoreFree(
    _Inout_ CXPLAT_PICOTLS_TRUST_STORE* TrustStore
    )
{
    if (TrustStore->Anchors != NULL) {
        for (size_t i = 0; i < TrustStore->AnchorCount; ++i) {
            CXPLAT_FREE((void*)TrustStore->Anchors[i].Der.base, QUIC_POOL_TLS_CERT_DER);
        }
        CXPLAT_FREE(TrustStore->Anchors, QUIC_POOL_TLS_CERT_DER);
    }
    if (TrustStore->Disallowed != NULL) {
        for (size_t i = 0; i < TrustStore->DisallowedCount; ++i) {
            CXPLAT_FREE(TrustStore->Disallowed[i].base, QUIC_POOL_TLS_CERT_DER);
        }
        CXPLAT_FREE(TrustStore->Disallowed, QUIC_POOL_TLS_CERT_DER);
    }
    CxPlatZeroMemory(TrustStore, sizeof(*TrustStore));
}

//
// Reads the machine's Root and Disallowed stores from the registry.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
TrustStoreLoad(
    _Out_ CXPLAT_PICOTLS_TRUST_STORE* TrustStore
    )
{
    CXPLAT_PICOTLS_DER_LIST Roots, Disallowed;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CxPlatZeroMemory(TrustStore, sizeof(*TrustStore));
    CxPlatZeroMemory(&Roots, sizeof(Roots));
    CxPlatZeroMemory(&Disallowed, sizeof(Disallowed));

    for (size_t i = 0; QUIC_SUCCEEDED(Status) && i < ARRAYSIZE(RootStoreKeys); ++i) {
        Status = LoadRegistryStore(RootStoreKeys[i], &Roots);
    }
    for (size_t i = 0; QUIC_SUCCEEDED(Status) && i < ARRAYSIZE(DisallowedStoreKeys); ++i) {
        Status = LoadRegistryStore(DisallowedStoreKeys[i], &Disallowed);
    }
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    if (Roots.Count != 0) {
        TrustStore->Anchors =
            CXPLAT_ALLOC_PAGED(Roots.Count * sizeof(CXPLAT_PICOTLS_X509), QUIC_POOL_TLS_CERT_DER);
        if (TrustStore->Anchors == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Trust anchors",
                (uint64_t)(Roots.Count * sizeof(CXPLAT_PICOTLS_X509)));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
    }

    //
    // Parse the roots once. One that can't be parsed can't anchor a chain.
    //
    for (size_t i = 0; i < Roots.Count; ++i) {
        CXPLAT_PICOTLS_X509* Anchor = &TrustStore->Anchors[TrustStore->AnchorCount];
        if (QUIC_SUCCEEDED(
                CxPlatPicotlsParseCertificate(
                    Roots.Items[i].base, Roots.Items[i].len, Anchor))) {
            TrustStore->AnchorCount++;
            Roots.Items[i].base = NULL; // Now owned by the anchor.
        } else {
            CXPLAT_FREE(Roots.Items[i].base, QUIC_POOL_TLS_CERT_DER);
            Roots.Items[i].base = NULL;
        }
    }
    Roots.Count = 0;

    TrustStore->Disallowed = Disallowed.Items;
    TrustStore->DisallowedCount = Disallowed.Count;
    CxPlatZeroMemory(&Disallowed, sizeof(Disallowed));

    QuicTraceLogInfo(
        PicotlsTrustStoreLoaded,
        "[ tls] Loaded %u trusted root certificates (%u disallowed)",
        (uint32_t)TrustStore->AnchorCount,
        (uint32_t)TrustStore->DisallowedCount);

Exit:

    DerListFree(&Roots);
    DerListFree(&Disallowed);
    if (QUIC_FAILED(Status)) {
        TrustStoreFree(TrustStore);
    }
    return Status;
}

#endif // _KERNEL_MODE

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPicotlsVerifierFree(
    _In_ CXPLAT_PICOTLS_VERIFIER* Verifier
    )
{
#ifdef _KERNEL_MODE
    TrustStoreFree(&Verifier->TrustStore);
#endif
    CryptoClose(&Verifier->Crypto);
    CXPLAT_FREE(Verifier, QUIC_POOL_TLS_SECCONF);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatPicotlsVerifierCreate(
    _In_ QUIC_CREDENTIAL_FLAGS Flags,
    _Outptr_ CXPLAT_PICOTLS_VERIFIER** Verifier
    )
{
    QUIC_STATUS Status;
    *Verifier = NULL;

    CXPLAT_PICOTLS_VERIFIER* NewVerifier =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_PICOTLS_VERIFIER), QUIC_POOL_TLS_SECCONF);
    if (NewVerifier == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_PICOTLS_VERIFIER",
            sizeof(CXPLAT_PICOTLS_VERIFIER));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(NewVerifier, sizeof(*NewVerifier));
    NewVerifier->Flags = Flags;

    CXPLAT_PICOTLS_CRYPTO* Crypto = &NewVerifier->Crypto;
    Status = OpenAlgorithm(&Crypto->Hash[CXPLAT_PICOTLS_HASH_SHA256], BCRYPT_SHA256_ALGORITHM, 0);
    if (QUIC_SUCCEEDED(Status)) {
        Status = OpenAlgorithm(&Crypto->Hash[CXPLAT_PICOTLS_HASH_SHA384], BCRYPT_SHA384_ALGORITHM, 0);
    }
    if (QUIC_SUCCEEDED(Status)) {
        Status = OpenAlgorithm(&Crypto->Hash[CXPLAT_PICOTLS_HASH_SHA512], BCRYPT_SHA512_ALGORITHM, 0);
    }
    if (QUIC_SUCCEEDED(Status)) {
        Status = OpenAlgorithm(&Crypto->Rsa, BCRYPT_RSA_ALGORITHM, 0);
    }
    if (QUIC_SUCCEEDED(Status)) {
        Status = OpenAlgorithm(&Crypto->EcdsaP256, BCRYPT_ECDSA_P256_ALGORITHM, 0);
    }
    if (QUIC_SUCCEEDED(Status)) {
        Status = OpenAlgorithm(&Crypto->EcdsaP384, BCRYPT_ECDSA_P384_ALGORITHM, 0);
    }
    if (QUIC_SUCCEEDED(Status)) {
        Status = OpenAlgorithm(&Crypto->EcdsaP521, BCRYPT_ECDSA_P521_ALGORITHM, 0);
    }
#ifdef _KERNEL_MODE
    if (QUIC_SUCCEEDED(Status)) {
        Status = TrustStoreLoad(&NewVerifier->TrustStore);
    }
#endif
    if (QUIC_FAILED(Status)) {
        CxPlatPicotlsVerifierFree(NewVerifier);
        return Status;
    }

    *Verifier = NewVerifier;
    return QUIC_STATUS_SUCCESS;
}

#ifndef _KERNEL_MODE

//
// Maps a CryptoAPI chain error to a TLS alert.
//
static
int
ChainErrorToAlert(
    _In_ uint32_t Error
    )
{
    switch ((HRESULT)Error) {
    case CERT_E_EXPIRED:
    case CERT_E_VALIDITYPERIODNESTING:
        return PTLS_ALERT_CERTIFICATE_EXPIRED;
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_UNTRUSTEDTESTROOT:
    case CERT_E_CHAINING:
        return PTLS_ALERT_UNKNOWN_CA;
    case CRYPT_E_REVOKED:
        return PTLS_ALERT_CERTIFICATE_REVOKED;
    case CERT_E_WRONG_USAGE:
        return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
    default:
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
}

//
// Validates the chain with CertGetCertificateChain, giving it the
// certificates the server sent to build it with.
//
static
int
VerifyChainCapi(
    _In_ const CXPLAT_PICOTLS_VERIFIER* Verifier,
    _In_opt_z_ const char* ServerName,
    _In_reads_(CertificateCount) const ptls_iovec_t* Certificates,
    _In_ size_t CertificateCount
    )
{
    int Ret = PTLS_ALERT_BAD_CERTIFICATE;
    PCCERT_CONTEXT Leaf = NULL;
    HCERTSTORE Store =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (Store == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertOpenStore failed");
        return PTLS_ERROR_LIBRARY;
    }

    for (size_t i = 0; i < CertificateCount; ++i) {
        if (Certificates[i].len > ULONG_MAX ||
            !CertAddEncodedCertificateToStore(
                Store,
                X509_ASN_ENCODING,
                Certificates[i].base,
                (DWORD)Certificates[i].len,
                CERT_STORE_ADD_ALWAYS,
                i == 0 ? &Leaf : NULL)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                GetLastError(),
                "CertAddEncodedCertificateToStore failed");
            goto Exit;
        }
    }

    uint32_t CertFlags = 0;
    if (Verifier->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT) {
        CertFlags |= CERT_CHAIN_REVOCATION_CHECK_END_CERT;
    }
    if (Verifier->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN) {
        CertFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    }
    if (Verifier->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT) {
        CertFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    }
    if (Verifier->Flags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL) {
        CertFlags |= CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    }
    if (Verifier->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY) {
        CertFlags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
    }
    if (Verifier->Flags & QUIC_CREDENTIAL_FLAG_DISABLE_AIA) {
        CertFlags |= CERT_CHAIN_DISABLE_AIA;
    }

    uint32_t Error = 0;
    if (CxPlatCertValidateChain(
            (const QUIC_CERTIFICATE*)Leaf,
            ServerName,
            CertFlags,
            Verifier->Flags,
            &Error)) {
        Ret = 0;
    } else {
        Ret = ChainErrorToAlert(Error);
    }

Exit:

    if (Leaf != NULL) {
        CertFreeCertificateContext(Leaf);
    }
    CertCloseStore(Store, 0);
    return Ret;
}

#endif // !_KERNEL_MODE

//
// What CertificateVerify is checked with: the leaf's public key. The
// certificates are only valid during the verify_certificate callback, so the
// leaf is copied.
//
typedef struct CXPLAT_PICOTLS_VERIFY_SIGN {
    CXPLAT_PICOTLS_VERIFIER* Verifier;
    CXPLAT_PICOTLS_X509 Leaf;   // Points into the copy, which follows.
} CXPLAT_PICOTLS_VERIFY_SIGN;

static
int
CxPlatPicotlsVerifySign(
    _In_ void* VerifyContext,
    _In_ uint16_t Algorithm,
    _In_ ptls_iovec_t Data,
    _In_ ptls_iovec_t Signature
    )
{
    CXPLAT_PICOTLS_VERIFY_SIGN* Context = (CXPLAT_PICOTLS_VERIFY_SIGN*)VerifyContext;
    const CXPLAT_PICOTLS_PUBLIC_KEY* Key = &Context->Leaf.PublicKey;
    CXPLAT_PICOTLS_SIGNATURE_ALGORITHM SignatureAlgorithm;
    uint32_t CurveBits = 0;
    int Ret;

    if (Data.base == NULL) {
        Ret = 0; // The handshake failed before CertificateVerify: just clean up.
        goto Exit;
    }

    CxPlatZeroMemory(&SignatureAlgorithm, sizeof(SignatureAlgorithm));
    switch (Algorithm) {
    case PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
        SignatureAlgorithm.Hash = CXPLAT_PICOTLS_HASH_SHA256;
        SignatureAlgorithm.Padding = CXPLAT_PICOTLS_PADDING_ECDSA;
        CurveBits = 256;
        break;
    case PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384:
        SignatureAlgorithm.Hash = CXPLAT_PICOTLS_HASH_SHA384;
        SignatureAlgorithm.Padding = CXPLAT_PICOTLS_PADDING_ECDSA;
        CurveBits = 384;
        break;
    case PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512:
        SignatureAlgorithm.Hash = CXPLAT_PICOTLS_HASH_SHA512;
        SignatureAlgorithm.Padding = CXPLAT_PICOTLS_PADDING_ECDSA;
        CurveBits = 521;
        break;
    case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
        SignatureAlgorithm.Hash = CXPLAT_PICOTLS_HASH_SHA256;
        break;
    case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
        SignatureAlgorithm.Hash = CXPLAT_PICOTLS_HASH_SHA384;
        break;
    case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512:
        SignatureAlgorithm.Hash = CXPLAT_PICOTLS_HASH_SHA512;
        break;
    default:
        Ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }
    if (CurveBits == 0) {
        SignatureAlgorithm.Padding = CXPLAT_PICOTLS_PADDING_RSA_PSS;
        SignatureAlgorithm.SaltLength = HashAlgorithmLength(SignatureAlgorithm.Hash);
    }

    //
    // In TLS 1.3 each ECDSA scheme is bound to one curve.
    //
    if (!Context->Leaf.PublicKeySupported ||
        (CurveBits == 0 ?
            Key->Type != CXPLAT_PICOTLS_KEY_RSA :
            (Key->Type != CXPLAT_PICOTLS_KEY_EC || Key->CurveBits != CurveBits))) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CertificateVerify algorithm doesn't match the server's key");
        Ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        goto Exit;
    }

    if (QUIC_FAILED(
            CxPlatPicotlsCryptoVerifySignature(
                &Context->Verifier->Crypto,
                Key,
                &SignatureAlgorithm,
                Data.base,
                Data.len,
                Signature.base,
                Signature.len))) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CertificateVerify signature is invalid");
        Ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    Ret = 0;

Exit:

    CXPLAT_FREE(Context, QUIC_POOL_TLS_CERT_DER);
    return Ret;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int
CxPlatPicotlsVerifyCertificate(
    _In_ CXPLAT_PICOTLS_VERIFIER* Verifier,
    _In_opt_z_ const char* ServerName,
    _In_reads_(CertificateCount) const ptls_iovec_t* Certificates,
    _In_ size_t CertificateCount,
    _Out_ int (**VerifySign)(void* VerifyContext, uint16_t Algorithm, ptls_iovec_t Data, ptls_iovec_t Signature),
    _Out_ void** VerifyContext
    )
{
    int Ret;
    *VerifySign = NULL;
    *VerifyContext = NULL;

    if (CertificateCount == 0) {
        return PTLS_ALERT_CERTIFICATE_REQUIRED;
    }

#ifdef _KERNEL_MODE
    Ret =
        CxPlatPicotlsVerifyChain(
            &Verifier->Crypto,
            &Verifier->TrustStore,
            Certificates,
            CertificateCount,
            ServerName,
            CxPlatTimeEpochMs64() / 1000);
#else
    Ret = VerifyChainCapi(Verifier, ServerName, Certificates, CertificateCount);
#endif
    if (Ret != 0) {
        return Ret;
    }

    const size_t LeafLength = Certificates[0].len;
    CXPLAT_PICOTLS_VERIFY_SIGN* Context =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_PICOTLS_VERIFY_SIGN) + LeafLength, QUIC_POOL_TLS_CERT_DER);
    if (Context == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_PICOTLS_VERIFY_SIGN",
            (uint64_t)(sizeof(CXPLAT_PICOTLS_VERIFY_SIGN) + LeafLength));
        return PTLS_ERROR_NO_MEMORY;
    }
    Context->Verifier = Verifier;
    uint8_t* LeafCopy = (uint8_t*)(Context + 1);
    memcpy(LeafCopy, Certificates[0].base, LeafLength);
    if (QUIC_FAILED(CxPlatPicotlsParseCertificate(LeafCopy, LeafLength, &Context->Leaf))) {
        CXPLAT_FREE(Context, QUIC_POOL_TLS_CERT_DER);
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    *VerifySign = CxPlatPicotlsVerifySign;
    *VerifyContext = Context;
    return 0;
}
