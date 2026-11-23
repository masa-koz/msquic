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

--*/

#include "platform_internal.h"
#include "picotls_cert.h"
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
