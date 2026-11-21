#include "platform_internal.h"
#include "picotls.h"
#include "picotls/minicrypto.h"
#ifndef _WIN32
//
// On non-Windows platforms the server certificate and private key are loaded
// and used for signing with OpenSSL, which is already linked for crypt_openssl.c.
//
#define CXPLAT_PICOTLS_OPENSSL_CERTS 1
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#endif
#ifdef QUIC_CLOG
#include "tls_picotls.c.clog.h"
#endif

typedef struct CXPLAT_SEC_CONFIG {

    //
    // SSL context used for establishing TLS connections.
    //
    ptls_context_t Ctx;

    //
    // Callbacks referenced by Ctx. They are stored here (rather than in each
    // CXPLAT_TLS) because Ctx is shared by every connection using this config.
    //
    ptls_update_traffic_key_t UpdateTrafficKey;
    ptls_on_client_hello_t OnClientHello;
    ptls_sign_certificate_t SignCertificate;

#ifdef CXPLAT_PICOTLS_OPENSSL_CERTS
    //
    // Private key used to sign the CertificateVerify message.
    //
    EVP_PKEY* PrivateKey;
#endif

    //
    // Pointer to the ticket key configuration for session resumption.
    //
    QUIC_TICKET_KEY_CONFIG* TicketKey;

    //
    // TLS-related callbacks for handling crypto events.
    //
    CXPLAT_TLS_CALLBACKS Callbacks;

    //
    // Credential flags specifying various QUIC credential options.
    //
    QUIC_CREDENTIAL_FLAGS Flags;

    //
    // Flags that specify behavior for TLS credential handling.
    //
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags;

} CXPLAT_SEC_CONFIG;

typedef struct CXPLAT_TLS {

    //
    // Pointer to the security configuration used for the TLS session.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

    //
    // Pointer to HKDF label definitions used in the key derivation process.
    //
    const QUIC_HKDF_LABELS* HkdfLabels;

    //
    // Indicates if the endpoint is acting as a server.
    //
    BOOLEAN IsServer : 1;

    //
    // Indicates if a peer certificate has been received.
    //
    BOOLEAN PeerCertReceived : 1;

    //
    // Indicates if the peer's transport parameters have been received.
    //
    BOOLEAN PeerTPReceived : 1;

    //
    // QUIC transport parameter extension type used in the session.
    //
    uint16_t QuicTpExtType;

    //
    // Length of the ALPN buffer.
    //
    uint16_t AlpnBufferLength;

    //
    // Pointer to the ALPN buffer data.
    //
    const uint8_t* AlpnBuffer;

    ptls_iovec_t* AlpnVec;

    //
    // Picotls SSL object used for the TLS handshake and encryption.
    //
    ptls_t *Tls;

    ptls_handshake_properties_t HandshakeProperties;
    ptls_raw_extension_t Extensions[2];

    //
    // Pointer to internal TLS processing state.
    //
    CXPLAT_TLS_PROCESS_STATE* State;

    //
    // Flags indicating the results of TLS processing.
    //
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    //
    // Pointer to the QUIC connection associated with this TLS session.
    //
    QUIC_CONNECTION* Connection;

    //
    // Pointer to derived TLS secrets for encryption and decryption.
    //
    QUIC_TLS_SECRETS* TlsSecrets;

} CXPLAT_TLS;

uint16_t CxPlatTlsTPHeaderSize = 0;

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_TLS_PROVIDER
CxPlatTlsGetProvider(
    void
    )
{
    return QUIC_TLS_PROVIDER_PICOTLS;
}

int
CxPlatTlsUpdateTrafficKeyCallback(
    _In_ ptls_update_traffic_key_t* Self,
    _In_ ptls_t* Tls,
    _In_ int IsEnc,
    _In_ size_t Epoch,
    _In_ const void *NewSecret
    );

//
// Server-side ClientHello hook. The QUIC core has already parsed the
// ClientHello and picked the ALPN (State->NegotiatedAlpn), so this only hands
// that choice to picotls, which sends it in EncryptedExtensions.
//
static
int
CxPlatTlsOnClientHelloCallback(
    _In_ ptls_on_client_hello_t* Self,
    _In_ ptls_t* Tls,
    _In_ ptls_on_client_hello_parameters_t* Params
    )
{
    UNREFERENCED_PARAMETER(Self);
    CXPLAT_TLS* TlsContext = *ptls_get_data_ptr(Tls);
    const uint8_t* NegotiatedAlpn = TlsContext->State->NegotiatedAlpn;

    if (NegotiatedAlpn == NULL) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "No negotiated ALPN");
        return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    }

    if (Params->server_name.base != NULL) {
        //
        // Acknowledge the SNI extension, as the other TLS providers do.
        //
        int Ret =
            ptls_set_server_name(
                Tls,
                (const char*)Params->server_name.base,
                Params->server_name.len);
        if (Ret != 0) {
            return Ret;
        }
    }

    for (size_t i = 0; i < Params->negotiated_protocols.count; ++i) {
        const ptls_iovec_t* Offered = &Params->negotiated_protocols.list[i];
        if (Offered->len == NegotiatedAlpn[0] &&
            memcmp(Offered->base, NegotiatedAlpn + 1, NegotiatedAlpn[0]) == 0) {
            return
                ptls_set_negotiated_protocol(
                    Tls,
                    (const char*)NegotiatedAlpn + 1,
                    NegotiatedAlpn[0]);
        }
    }

    QuicTraceEvent(
        TlsError,
        "[ tls][%p] ERROR, %s.",
        TlsContext->Connection,
        "Client did not offer the negotiated ALPN");
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

#ifdef CXPLAT_PICOTLS_OPENSSL_CERTS

//
// Returns TRUE if Key can produce signatures for the TLS 1.3 SignatureScheme,
// and the digest to use with it (NULL for Ed25519).
//
static
BOOLEAN
CxPlatTlsKeySupportsScheme(
    _In_ EVP_PKEY* Key,
    _In_ uint16_t Scheme,
    _Out_ const EVP_MD** Md
    )
{
    *Md = NULL;

    switch (EVP_PKEY_get_base_id(Key)) {
    case EVP_PKEY_RSA:
        switch (Scheme) {
        case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
            *Md = EVP_sha256();
            return TRUE;
        case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
            *Md = EVP_sha384();
            return TRUE;
        case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512:
            *Md = EVP_sha512();
            return TRUE;
        default:
            return FALSE;
        }

    case EVP_PKEY_EC: {
        //
        // In TLS 1.3 each ECDSA scheme is bound to one curve.
        //
        char Group[32];
        if (EVP_PKEY_get_group_name(Key, Group, sizeof(Group), NULL) != 1) {
            return FALSE;
        }
        if (Scheme == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 &&
            strcmp(Group, SN_X9_62_prime256v1) == 0) {
            *Md = EVP_sha256();
            return TRUE;
        }
        if (Scheme == PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 &&
            strcmp(Group, SN_secp384r1) == 0) {
            *Md = EVP_sha384();
            return TRUE;
        }
        if (Scheme == PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512 &&
            strcmp(Group, SN_secp521r1) == 0) {
            *Md = EVP_sha512();
            return TRUE;
        }
        return FALSE;
    }

    case EVP_PKEY_ED25519:
        return Scheme == PTLS_SIGNATURE_ED25519;

    default:
        return FALSE;
    }
}

//
// Signs the server's CertificateVerify. Signing is always synchronous, so the
// async job slot is never used.
//
static
int
CxPlatTlsSignCertificateCallback(
    _In_ ptls_sign_certificate_t* Self,
    _In_ ptls_t* Tls,
    _Inout_opt_ ptls_async_job_t** Async,
    _Out_ uint16_t* SelectedAlgorithm,
    _Inout_ ptls_buffer_t* Output,
    _In_ ptls_iovec_t Input,
    _In_reads_(NumAlgorithms) const uint16_t* Algorithms,
    _In_ size_t NumAlgorithms
    )
{
    UNREFERENCED_PARAMETER(Async);
    CXPLAT_SEC_CONFIG* SecConfig =
        CXPLAT_CONTAINING_RECORD(Self, CXPLAT_SEC_CONFIG, SignCertificate);
    CXPLAT_TLS* TlsContext = *ptls_get_data_ptr(Tls);
    EVP_PKEY* Key = SecConfig->PrivateKey;
    const EVP_MD* Md = NULL;
    EVP_MD_CTX* MdCtx = NULL;
    EVP_PKEY_CTX* PkeyCtx = NULL;
    size_t SigLength = 0;
    size_t i;
    int Ret;

    *SelectedAlgorithm = 0;

    //
    // Take the first scheme in the client's preference order that the key
    // supports.
    //
    for (i = 0; i < NumAlgorithms; ++i) {
        if (CxPlatTlsKeySupportsScheme(Key, Algorithms[i], &Md)) {
            break;
        }
    }
    if (i == NumAlgorithms) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "No signature algorithm in common with the client");
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }

    MdCtx = EVP_MD_CTX_new();
    if (MdCtx == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }

    Ret = PTLS_ERROR_LIBRARY;

    if (EVP_DigestSignInit(MdCtx, &PkeyCtx, Md, NULL, Key) != 1) {
        goto Exit;
    }

    if (EVP_PKEY_get_base_id(Key) == EVP_PKEY_RSA &&
        (EVP_PKEY_CTX_set_rsa_padding(PkeyCtx, RSA_PKCS1_PSS_PADDING) != 1 ||
         EVP_PKEY_CTX_set_rsa_pss_saltlen(PkeyCtx, RSA_PSS_SALTLEN_DIGEST) != 1 ||
         EVP_PKEY_CTX_set_rsa_mgf1_md(PkeyCtx, Md) != 1)) {
        goto Exit;
    }

    //
    // The first call only reports the maximum signature length.
    //
    if (EVP_DigestSign(MdCtx, NULL, &SigLength, Input.base, Input.len) != 1) {
        goto Exit;
    }

    if ((Ret = ptls_buffer_reserve(Output, SigLength)) != 0) {
        goto Exit;
    }

    if (EVP_DigestSign(
            MdCtx,
            Output->base + Output->off,
            &SigLength,
            Input.base,
            Input.len) != 1) {
        Ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    Output->off += SigLength;
    *SelectedAlgorithm = Algorithms[i];
    Ret = 0;

Exit:

    if (Ret == PTLS_ERROR_LIBRARY) {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            (uint32_t)ERR_get_error(),
            "Signing CertificateVerify failed");
    }
    EVP_MD_CTX_free(MdCtx);
    return Ret;
}

//
// Supplies the PEM private key password, and refuses to prompt on the
// terminal when there is none.
//
static
int
CxPlatTlsPemPasswordCallback(
    _Out_writes_bytes_(Size) char* Buffer,
    _In_ int Size,
    _In_ int RwFlag,
    _In_opt_ void* UserData
    )
{
    UNREFERENCED_PARAMETER(RwFlag);
    const char* Password = (const char*)UserData;
    if (Password == NULL || Size <= 0) {
        return -1;
    }
    size_t Length = strnlen(Password, (size_t)Size);
    if (Length == (size_t)Size) {
        return -1; // Too long for OpenSSL's buffer.
    }
    memcpy(Buffer, Password, Length);
    return (int)Length;
}

//
// Stores the leaf certificate followed by its chain in DER form, as picotls
// sends Ctx.certificates as-is in the Certificate message.
//
static
QUIC_STATUS
CxPlatTlsSetCertificates(
    _Inout_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ X509* Leaf,
    _In_opt_ STACK_OF(X509)* Chain
    )
{
    size_t Count = 1 + (Chain != NULL ? (size_t)sk_X509_num(Chain) : 0);
    ptls_iovec_t* List =
        CXPLAT_ALLOC_NONPAGED(sizeof(ptls_iovec_t) * Count, QUIC_POOL_TLS_CERT_DER);
    if (List == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "certificate list",
            sizeof(ptls_iovec_t) * Count);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(List, sizeof(ptls_iovec_t) * Count);

    //
    // Hand the list over now, so CxPlatTlsSecConfigDelete frees whatever has
    // been converted if a later certificate fails.
    //
    SecConfig->Ctx.certificates.list = List;
    SecConfig->Ctx.certificates.count = 0;

    for (size_t i = 0; i < Count; ++i) {
        X509* Cert = i == 0 ? Leaf : sk_X509_value(Chain, (int)(i - 1));
        int Length = i2d_X509(Cert, NULL);
        if (Length <= 0) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                NULL,
                (uint32_t)ERR_get_error(),
                "i2d_X509 failed");
            return QUIC_STATUS_TLS_ERROR;
        }

        uint8_t* Der = CXPLAT_ALLOC_NONPAGED((size_t)Length, QUIC_POOL_TLS_CERT_DER);
        if (Der == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "DER certificate",
                (uint64_t)Length);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        uint8_t* Cursor = Der;
        i2d_X509(Cert, &Cursor);
        List[i].base = Der;
        List[i].len = (size_t)Length;
        SecConfig->Ctx.certificates.count++;
    }

    return QUIC_STATUS_SUCCESS;
}

//
// Loads the certificate (with its chain) and private key of a
// CERTIFICATE_FILE, CERTIFICATE_FILE_PROTECTED or CERTIFICATE_PKCS12
// credential into the security config.
//
static
QUIC_STATUS
CxPlatTlsLoadCredential(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Inout_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
    QUIC_STATUS Status = QUIC_STATUS_TLS_ERROR;
    BIO* Bio = NULL;
    PKCS12* Pkcs12 = NULL;
    EVP_PKEY* PrivateKey = NULL;
    X509* Leaf = NULL;
    STACK_OF(X509)* Chain = NULL;
    const char* Error = NULL;

    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ||
        CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {

        const char* CertificateFile;
        const char* PrivateKeyFile;
        const char* Password = NULL;
        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            CertificateFile = CredConfig->CertificateFile->CertificateFile;
            PrivateKeyFile = CredConfig->CertificateFile->PrivateKeyFile;
        } else {
            CertificateFile = CredConfig->CertificateFileProtected->CertificateFile;
            PrivateKeyFile = CredConfig->CertificateFileProtected->PrivateKeyFile;
            Password = CredConfig->CertificateFileProtected->PrivateKeyPassword;
        }

        Bio = BIO_new_file(PrivateKeyFile, "r");
        if (Bio == NULL) {
            Error = "Opening the private key file failed";
            goto Exit;
        }
        PrivateKey =
            PEM_read_bio_PrivateKey(
                Bio, NULL, CxPlatTlsPemPasswordCallback, (void*)Password);
        if (PrivateKey == NULL) {
            Error = "PEM_read_bio_PrivateKey failed";
            goto Exit;
        }
        BIO_free(Bio);

        Bio = BIO_new_file(CertificateFile, "r");
        if (Bio == NULL) {
            Error = "Opening the certificate file failed";
            goto Exit;
        }
        Leaf = PEM_read_bio_X509_AUX(Bio, NULL, NULL, NULL);
        if (Leaf == NULL) {
            Error = "PEM_read_bio_X509_AUX failed";
            goto Exit;
        }

        //
        // Any further certificates in the file form the chain.
        //
        Chain = sk_X509_new_null();
        if (Chain == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
        X509* ChainCert;
        while ((ChainCert = PEM_read_bio_X509(Bio, NULL, NULL, NULL)) != NULL) {
            if (sk_X509_push(Chain, ChainCert) <= 0) {
                X509_free(ChainCert);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Exit;
            }
        }
        ERR_clear_error(); // Reaching the end of the file is reported as an error.

    } else {
        CXPLAT_DBG_ASSERT(CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12);

        const uint8_t* Blob = CredConfig->CertificatePkcs12->Asn1Blob;
        Pkcs12 =
            d2i_PKCS12(
                NULL, &Blob, (long)CredConfig->CertificatePkcs12->Asn1BlobLength);
        if (Pkcs12 == NULL) {
            Error = "d2i_PKCS12 failed";
            goto Exit;
        }
        if (PKCS12_parse(
                Pkcs12,
                CredConfig->CertificatePkcs12->PrivateKeyPassword,
                &PrivateKey,
                &Leaf,
                &Chain) != 1 ||
            PrivateKey == NULL ||
            Leaf == NULL) {
            Error = "PKCS12_parse failed";
            goto Exit;
        }
    }

    if (X509_check_private_key(Leaf, PrivateKey) != 1) {
        Error = "The private key does not match the certificate";
        goto Exit;
    }

    Status = CxPlatTlsSetCertificates(SecConfig, Leaf, Chain);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    SecConfig->PrivateKey = PrivateKey;
    PrivateKey = NULL;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (Error != NULL) {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            NULL,
            (uint32_t)ERR_get_error(),
            Error);
    }
    if (Bio != NULL) {
        BIO_free(Bio);
    }
    if (Pkcs12 != NULL) {
        PKCS12_free(Pkcs12);
    }
    if (Chain != NULL) {
        sk_X509_pop_free(Chain, X509_free);
    }
    if (Leaf != NULL) {
        X509_free(Leaf);
    }
    if (PrivateKey != NULL) {
        EVP_PKEY_free(PrivateKey);
    }
    return Status;
}

#endif // CXPLAT_PICOTLS_OPENSSL_CERTS

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    _In_ const CXPLAT_TLS_CALLBACKS* TlsCallbacks,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    CXPLAT_DBG_ASSERT(CredConfig && CompletionHandler);

    QUIC_CREDENTIAL_FLAGS CredConfigFlags = CredConfig->Flags;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN IsClient = !!(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT);

    if (CredConfig->Reserved != NULL) {
        return QUIC_STATUS_INVALID_PARAMETER; // Not currently used and should be NULL.
    }

    switch (CredConfig->Type) {
    case QUIC_CREDENTIAL_TYPE_NONE:
        if (!IsClient) {
            return QUIC_STATUS_INVALID_PARAMETER; // Server requires a certificate.
        }
        break;
#ifdef CXPLAT_PICOTLS_OPENSSL_CERTS
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
        if (CredConfig->CertificateFile == NULL ||
            CredConfig->CertificateFile->CertificateFile == NULL ||
            CredConfig->CertificateFile->PrivateKeyFile == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED:
        if (CredConfig->CertificateFileProtected == NULL ||
            CredConfig->CertificateFileProtected->CertificateFile == NULL ||
            CredConfig->CertificateFileProtected->PrivateKeyFile == NULL ||
            CredConfig->CertificateFileProtected->PrivateKeyPassword == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12:
        if (CredConfig->CertificatePkcs12 == NULL ||
            CredConfig->CertificatePkcs12->Asn1Blob == NULL ||
            CredConfig->CertificatePkcs12->Asn1BlobLength == 0) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        break;
#endif
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (!IsClient &&
        (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION)) {
        //
        // Verifying client certificates isn't implemented yet. Refuse rather
        // than accept unauthenticated clients.
        //
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    CXPLAT_SEC_CONFIG* SecurityConfig = NULL;
    //
    // Create a security config.
    //

    SecurityConfig = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (SecurityConfig == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEC_CONFIG",
            sizeof(CXPLAT_SEC_CONFIG));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(SecurityConfig, sizeof(CXPLAT_SEC_CONFIG));
    SecurityConfig->Callbacks = *TlsCallbacks;
    SecurityConfig->Flags = CredConfigFlags;
    SecurityConfig->TlsFlags = TlsCredFlags;

    //
    // Create the a SSL context for the security config.
    //

    SecurityConfig->Ctx.random_bytes = ptls_minicrypto_random_bytes;
    SecurityConfig->Ctx.get_time = &ptls_get_time;
    SecurityConfig->Ctx.key_exchanges = ptls_minicrypto_key_exchanges;
    SecurityConfig->Ctx.cipher_suites = ptls_minicrypto_cipher_suites;

    //
    // QUIC carries no EndOfEarlyData message (RFC 9001, Section 8.3), and the
    // exporter secret is needed by CxPlatTlsExportKeyingMaterial.
    //
    SecurityConfig->Ctx.omit_end_of_early_data = 1;
    SecurityConfig->Ctx.use_exporter = 1;

    SecurityConfig->UpdateTrafficKey.cb = CxPlatTlsUpdateTrafficKeyCallback;
    SecurityConfig->Ctx.update_traffic_key = &SecurityConfig->UpdateTrafficKey;

    if (!IsClient) {
        SecurityConfig->OnClientHello.cb = CxPlatTlsOnClientHelloCallback;
        SecurityConfig->Ctx.on_client_hello = &SecurityConfig->OnClientHello;
    }

#ifdef CXPLAT_PICOTLS_OPENSSL_CERTS
    if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        Status = CxPlatTlsLoadCredential(CredConfig, SecurityConfig);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
        SecurityConfig->SignCertificate.cb = CxPlatTlsSignCertificateCallback;
        SecurityConfig->Ctx.sign_certificate = &SecurityConfig->SignCertificate;
    }
#endif

    //
    // Invoke completion inline.
    //

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = NULL;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = QUIC_STATUS_PENDING;
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

Exit:

    if (SecurityConfig != NULL) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsSecConfigDelete(
    __drv_freesMem(SecurityConfig) _Frees_ptr_ _In_
        CXPLAT_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->Ctx.certificates.list != NULL) {
        for (size_t i = 0; i < SecurityConfig->Ctx.certificates.count; ++i) {
            CXPLAT_FREE(SecurityConfig->Ctx.certificates.list[i].base, QUIC_POOL_TLS_CERT_DER);
        }
        CXPLAT_FREE(SecurityConfig->Ctx.certificates.list, QUIC_POOL_TLS_CERT_DER);
    }
#ifdef CXPLAT_PICOTLS_OPENSSL_CERTS
    if (SecurityConfig->PrivateKey != NULL) {
        EVP_PKEY_free(SecurityConfig->PrivateKey);
    }
#endif
    CXPLAT_FREE(SecurityConfig, QUIC_POOL_TLS_SECCONF);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigSetTicketKeys(
    _In_ CXPLAT_SEC_CONFIG* SecurityConfig,
    _In_reads_(KeyCount) QUIC_TICKET_KEY_CONFIG* KeyConfig,
    _In_ uint8_t KeyCount
    )
{
    CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now
    UNREFERENCED_PARAMETER(SecurityConfig);
    UNREFERENCED_PARAMETER(KeyConfig);
    UNREFERENCED_PARAMETER(KeyCount);

    return QUIC_STATUS_NOT_SUPPORTED;
}

int
CxPlatTlsCollectExtenionCallback(
    _In_ ptls_t* Tls,
    _In_ ptls_handshake_properties_t* HandshakeProperties,
    _In_ uint16_t Type
    )
{
    UNREFERENCED_PARAMETER(HandshakeProperties);
    CXPLAT_TLS* TlsContext = *ptls_get_data_ptr(Tls);

    return TlsContext->QuicTpExtType == Type;
}

int
CxPlatTlsCollectedExtenionsCallback(
    _In_ ptls_t* Tls,
    _In_ ptls_handshake_properties_t* HandshakeProperties,
    _In_ ptls_raw_extension_t* Slots
    )
{
    UNREFERENCED_PARAMETER(HandshakeProperties);
    CXPLAT_TLS* TlsContext = *ptls_get_data_ptr(Tls);

    int i;
    for (i = 0; Slots[i].type != 0xffff; i++) {
        if (Slots[i].type == TlsContext->QuicTpExtType) {
            TlsContext->PeerTPReceived = TRUE;
            if (TlsContext->IsServer) {
                //
                // The core has already decoded the client's transport
                // parameters from the ClientHello itself.
                //
                continue;
            }
            if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                                TlsContext->Connection,
                                (uint16_t)Slots[i].data.len,
                                Slots[i].data.base)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                return PTLS_ERROR_LIBRARY;
            }
        }
    }
    return 0;
}

int
CxPlatTlsUpdateTrafficKeyCallback(
    _In_ ptls_update_traffic_key_t* Self,
    _In_ ptls_t* Tls,
    _In_ int IsEnc,
    _In_ size_t Epoch,
    _In_ const void *NewSecret
    )
{
    UNREFERENCED_PARAMETER(Self);
    ptls_cipher_suite_t* Cipher = ptls_get_cipher(Tls);
    CXPLAT_TLS* TlsContext = *ptls_get_data_ptr(Tls);
    CXPLAT_TLS_PROCESS_STATE* TlsState = TlsContext->State;
    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Epoch;
    QUIC_STATUS Status;
    CXPLAT_SECRET Secret;

    if (IsEnc) {
        //
        // Tx/Write Secret
        //
        if (TlsState->WriteKeys[KeyType] == NULL) {
            CxPlatZeroMemory(&Secret, sizeof(Secret));
            CxPlatCopyMemory(Secret.Secret, NewSecret, Cipher->hash->digest_size);
            switch (Cipher->hash->digest_size) {
            case CXPLAT_HASH_SHA256_SIZE:
                Secret.Hash = CXPLAT_HASH_SHA256;
                break;
            case CXPLAT_HASH_SHA384_SIZE:
                Secret.Hash = CXPLAT_HASH_SHA384;
                break;
            case CXPLAT_HASH_SHA512_SIZE:
                Secret.Hash = CXPLAT_HASH_SHA512;
                break;
            default:
                break;
            }
            if (memcmp(Cipher->aead->name, "AES128-GCM", 10) == 0) {
                Secret.Aead = CXPLAT_AEAD_AES_128_GCM;
            } else if (memcmp(Cipher->aead->name, "AES256-GCM", 10) == 0) {
                Secret.Aead = CXPLAT_AEAD_AES_256_GCM;
            } else if (memcmp(Cipher->aead->name, "CHACHA20-POLY1305", 17) == 0) {
                Secret.Aead = CXPLAT_AEAD_CHACHA20_POLY1305;
            }
            Status =
                QuicPacketKeyDerive(
                    KeyType,
                    TlsContext->HkdfLabels,
                    &Secret,
                    "write Secret",
                    TRUE,
                    &TlsState->WriteKeys[KeyType]);
            if (QUIC_FAILED(Status)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                return PTLS_ERROR_LIBRARY;
            }
            if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_0_RTT) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;
                TlsContext->State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
            }
            TlsState->WriteKey = KeyType;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
        }
    } else {
        //
        // Rx/Read Secret
        //
        if (TlsState->ReadKeys[KeyType] == NULL) {
            CxPlatZeroMemory(&Secret, sizeof(Secret));
            CxPlatCopyMemory(Secret.Secret, NewSecret, Cipher->hash->digest_size);
            switch (Cipher->hash->digest_size) {
            case CXPLAT_HASH_SHA256_SIZE:
                Secret.Hash = CXPLAT_HASH_SHA256;
                break;
            case CXPLAT_HASH_SHA384_SIZE:
                Secret.Hash = CXPLAT_HASH_SHA384;
                break;
            case CXPLAT_HASH_SHA512_SIZE:
                Secret.Hash = CXPLAT_HASH_SHA512;
                break;
            default:
                break;
            }
            if (memcmp(Cipher->aead->name, "AES128-GCM", 10) == 0) {
                Secret.Aead = CXPLAT_AEAD_AES_128_GCM;
            } else if (memcmp(Cipher->aead->name, "AES256-GCM", 10) == 0) {
                Secret.Aead = CXPLAT_AEAD_AES_256_GCM;
            } else if (memcmp(Cipher->aead->name, "CHACHA20-POLY1305", 17) == 0) {
                Secret.Aead = CXPLAT_AEAD_CHACHA20_POLY1305;
            }
            Status =
                QuicPacketKeyDerive(
                    KeyType,
                    TlsContext->HkdfLabels,
                    &Secret,
                    "read Secret",
                    TRUE,
                    &TlsState->ReadKeys[KeyType]);
            if (QUIC_FAILED(Status)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                return PTLS_ERROR_LIBRARY;
            }
            if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_1_RTT) {
                // The 1-RTT read keys aren't actually allowed to be used until the 
                // handshake completes.
                // 
            } else { 
                TlsState->ReadKey = KeyType;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
            }
        }
    }

    //
    // If we are installing initial Secrets TlsSecrets aren't allocated yet
    //
    if (TlsContext->TlsSecrets != NULL) {
        //
        // We pass our Secrets one at a time instead of together
        // So we need to map which Secret we're assigning based
        // on whether we are a server, what type of key we're writing
        // and the IsEnc (1 for write, 0 for read)
        //
        TlsContext->TlsSecrets->SecretLength = (uint8_t)Cipher->hash->digest_size;
        switch(KeyType) {
        case QUIC_PACKET_KEY_HANDSHAKE:
            if (TlsContext->IsServer) {
                if (IsEnc) {
                    memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
                } else {
                    memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
                }
            } else {
                if (IsEnc) {
                    memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
                } else {
                    memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
                }
            }
            break;
        case QUIC_PACKET_KEY_0_RTT:
            if (TlsContext->IsServer) {
                if (!IsEnc) {
                    memcpy(TlsContext->TlsSecrets->ClientEarlyTrafficSecret,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
                }
            } else {
                if (IsEnc) {
                    memcpy(TlsContext->TlsSecrets->ClientEarlyTrafficSecret,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
                }
            }
            break;
        case QUIC_PACKET_KEY_1_RTT:
            if (TlsContext->IsServer) {
                if (!IsEnc) {
                    memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
                } else {
                    memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
                }
            } else {
                if (!IsEnc) {
                    memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
                } else {
                    memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0,
                           NewSecret, Cipher->hash->digest_size);
                    TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
                }
            }
            break;
        default:
            break;
        }
    }

    return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_TLS* TlsContext = NULL;
    UNREFERENCED_PARAMETER(State);

    CXPLAT_DBG_ASSERT(Config->HkdfLabels);
    if (Config->SecConfig == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    TlsContext = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_TLS), QUIC_POOL_TLS_CTX);
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(TlsContext, sizeof(CXPLAT_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->HkdfLabels = Config->HkdfLabels;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
    TlsContext->TlsSecrets = Config->TlsSecrets;

    QuicTraceLogConnVerbose(
        PicotlsContextCreated,
        TlsContext->Connection,
        "TLS context Created");

    //
    // Create a SSL object for the connection.
    //

    TlsContext->Tls = ptls_new(&TlsContext->SecConfig->Ctx, Config->IsServer);
    if (TlsContext->Tls == NULL) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "ptls_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    *ptls_get_data_ptr(TlsContext->Tls) = TlsContext;

    if (!Config->IsServer) {
        if (Config->ServerName != NULL) {
            uint16_t ServerNameLength = (uint16_t)strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);
            if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Exit;
            }
            ptls_set_server_name(TlsContext->Tls, Config->ServerName, ServerNameLength);
        }

        uint16_t AlpnListLength = TlsContext->AlpnBufferLength;
        const uint8_t* AlpnList = TlsContext->AlpnBuffer;
        size_t AlpnListCount = 0;
        while (AlpnListLength != 0) {
            CXPLAT_DBG_ASSERT(AlpnList[0] + 1 <= AlpnListLength);
            AlpnListLength -= AlpnList[0] + 1;
            AlpnList += (size_t)AlpnList[0] + (size_t)1;
            AlpnListCount++;
        }

        TlsContext->AlpnVec = CXPLAT_ALLOC_NONPAGED(
            sizeof(ptls_iovec_t) * AlpnListCount,
            QUIC_POOL_TLS_ALPN_VEC);
        if (TlsContext->AlpnVec == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "AlpnVec",
                sizeof(ptls_iovec_t) * AlpnListCount);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        AlpnListLength = TlsContext->AlpnBufferLength;
        AlpnList = TlsContext->AlpnBuffer;
        size_t i = 0;
        while (AlpnListLength != 0 && i < AlpnListCount) {
            CXPLAT_DBG_ASSERT(AlpnList[0] + 1 <= AlpnListLength);
            TlsContext->AlpnVec[i].base = (uint8_t *)&AlpnList[1];
            TlsContext->AlpnVec[i].len = AlpnList[0];
            AlpnListLength -= AlpnList[0] + 1;
            AlpnList += (size_t)AlpnList[0] + (size_t)1;
            i++;
        }

        TlsContext->HandshakeProperties.client.negotiated_protocols.list = TlsContext->AlpnVec;
        TlsContext->HandshakeProperties.client.negotiated_protocols.count = AlpnListCount;
    }


    TlsContext->HandshakeProperties.collect_extension = CxPlatTlsCollectExtenionCallback;
    TlsContext->HandshakeProperties.collected_extensions = CxPlatTlsCollectedExtenionsCallback;

    TlsContext->Extensions[0].type = TlsContext->QuicTpExtType;
    TlsContext->Extensions[0].data.base = (uint8_t *)Config->LocalTPBuffer;
    TlsContext->Extensions[0].data.len = Config->LocalTPLength;
    TlsContext->Extensions[1].type = 0xFFFF;
    TlsContext->Extensions[1].data.base = NULL;
    TlsContext->Extensions[1].data.len = 0;
    TlsContext->HandshakeProperties.additional_extensions = TlsContext->Extensions;

    //
    // On success the TLS layer owns LocalTPBuffer (freed in
    // CxPlatTlsUninitialize) and ResumptionTicketBuffer. Resumption isn't
    // supported, so the ticket is dropped.
    //
    if (Config->ResumptionTicketBuffer != NULL) {
        CXPLAT_FREE(Config->ResumptionTicketBuffer, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
    }

    Status = QUIC_STATUS_SUCCESS;
    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Exit:
    if (TlsContext) {
        //
        // LocalTPBuffer is still the caller's on failure, so it isn't freed here.
        //
        if (TlsContext->AlpnVec != NULL) {
            CXPLAT_FREE(TlsContext->AlpnVec, QUIC_POOL_TLS_ALPN_VEC);
        }
        if (TlsContext->Tls != NULL) {
            ptls_free(TlsContext->Tls);
        }
        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        QuicTraceLogConnVerbose(
            PicotlsContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        if (TlsContext->AlpnVec != NULL) {
            CXPLAT_FREE(TlsContext->AlpnVec, QUIC_POOL_TLS_ALPN_VEC);
            TlsContext->AlpnVec = NULL;
        }

        if (TlsContext->Tls != NULL) {
            ptls_free(TlsContext->Tls);
            TlsContext->Tls = NULL;
        }

        if (TlsContext->Extensions[0].data.base != NULL) {
            CXPLAT_FREE(TlsContext->Extensions[0].data.base, QUIC_POOL_TLS_TRANSPARAMS);
            TlsContext->Extensions[0].data.base = NULL;
        }

        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUpdateHkdfLabels(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ const QUIC_HKDF_LABELS* const Labels
    )
{
    TlsContext->HkdfLabels = Labels;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
    size_t EpochOffsets[5] = { 0, 0, 0, 0, 0 };
    ptls_buffer_t Sendbuf;
    int Ret;
    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    ptls_buffer_init(&Sendbuf, "", 0);

    if (DataType == CXPLAT_TLS_TICKET_DATA) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        goto Exit;
    }

    Ret = ptls_handle_message(
        TlsContext->Tls,
        &Sendbuf,
        EpochOffsets,
        TlsContext->State->ReadKey,
        Buffer,
        *BufferLength,
        &TlsContext->HandshakeProperties);
    if (Ret == 0 || Ret == PTLS_ERROR_IN_PROGRESS) {
        //
        // Make sure that we don't violate handshake data lengths
        //
        if (Sendbuf.off + State->BufferLength > 0xF000) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Too much handshake data");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        if (Sendbuf.off + State->BufferLength > (size_t)State->BufferAllocLength) {
            //
            // Double the allocated Buffer length until there's enough room for the
            // new data.
            // 
            uint16_t NewBufferAllocLength = State->BufferAllocLength;
            while (Sendbuf.off + State->BufferLength > (size_t)NewBufferAllocLength) {
                NewBufferAllocLength <<= 1;
            }

            uint8_t* NewBuffer = CXPLAT_ALLOC_NONPAGED(NewBufferAllocLength, QUIC_POOL_TLS_BUFFER);
            if (NewBuffer == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "New crypto Buffer",
                    NewBufferAllocLength);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }

            CxPlatCopyMemory(
                NewBuffer,
                State->Buffer,
                State->BufferLength);
            CXPLAT_FREE(State->Buffer, QUIC_POOL_TLS_BUFFER);
            State->Buffer = NewBuffer;
            State->BufferAllocLength = NewBufferAllocLength;
        }

        if (Sendbuf.off > 0) {
            if (State->BufferOffsetHandshake == 0 && 
                State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] != NULL) {
                State->BufferOffsetHandshake = State->BufferTotalLength + (uint32_t)EpochOffsets[QUIC_PACKET_KEY_HANDSHAKE];
                QuicTraceLogConnInfo(
                    PicotlsHandshakeDataStart,
                    TlsContext->Connection,
                    "Writing Handshake data starts at %u",
                    State->BufferOffsetHandshake);
            }

            if (State->BufferOffset1Rtt == 0 &&
                State->WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL) {
                State->BufferOffset1Rtt = State->BufferTotalLength + (uint32_t)EpochOffsets[QUIC_PACKET_KEY_1_RTT];
                QuicTraceLogConnInfo(
                    Picotls1RttDataStart,
                    TlsContext->Connection,
                    "Writing 1-RTT data starts at %u",
                    State->BufferOffset1Rtt);
            }

            CxPlatCopyMemory(
                State->Buffer + State->BufferLength,
                Sendbuf.base,
                Sendbuf.off);
            State->BufferLength += (uint16_t)Sendbuf.off;
            State->BufferTotalLength += (uint16_t)Sendbuf.off;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_DATA;
        }
    }

    if (Ret == 0 && !State->HandshakeComplete) {
        if (ptls_handshake_is_complete(TlsContext->Tls)) {
            if (!TlsContext->IsServer) {
                const char* NegotiatedAlpn;
                size_t NegotiatedAlpnLength;
                NegotiatedAlpn = ptls_get_negotiated_protocol(TlsContext->Tls);
                NegotiatedAlpnLength = NegotiatedAlpn != NULL ? strnlen(NegotiatedAlpn, UINT8_MAX) : 0;
                if (NegotiatedAlpnLength == 0) {
                    QuicTraceLogConnError(
                        PicotlsAlpnNegotiationFailure,
                        TlsContext->Connection,
                        "Failed to negotiate ALPN");
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                    goto Exit;
                }
                if (NegotiatedAlpnLength > UINT8_MAX) {
                    QuicTraceLogConnError(
                        PicotlsInvalidAlpnLength,
                        TlsContext->Connection,
                        "Invalid negotiated ALPN length");
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                    goto Exit;
                }
                TlsContext->State->NegotiatedAlpn =
                    CxPlatTlsAlpnFindInList(
                        TlsContext->AlpnBufferLength,
                        TlsContext->AlpnBuffer,
                        (uint8_t)NegotiatedAlpnLength,
                        (uint8_t*)NegotiatedAlpn);
                if (TlsContext->State->NegotiatedAlpn == NULL) {
                    QuicTraceLogConnError(
                        PicotlsNoMatchingAlpn,
                        TlsContext->Connection,
                        "Failed to find a matching ALPN");
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                    goto Exit;
                }
            }
            State->HandshakeComplete = TRUE;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE;

            if (TlsContext->IsServer) {
                //
                // The 1-RTT read key was held back in
                // CxPlatTlsUpdateTrafficKeyCallback until now.
                //
                State->ReadKey = QUIC_PACKET_KEY_1_RTT;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
            }

            QuicTraceLogConnInfo(
                PicotlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
        }
    } else if (Ret != 0 && Ret != PTLS_ERROR_IN_PROGRESS) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "ptls_handle_message failed");
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        goto Exit;
    }
    
Exit:
    //
    // Always set buffer offsets if keys have been installed to preserve code
    // invariants, even if no data was written at that level (e.g. on error).
    //
    if (State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] != NULL &&
        State->BufferOffsetHandshake == 0) {
        State->BufferOffsetHandshake = State->BufferTotalLength;
    }
    if (State->WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL &&
        State->BufferOffset1Rtt == 0) {
        State->BufferOffset1Rtt = State->BufferTotalLength;
    }

    ptls_buffer_dispose(&Sendbuf);
    return TlsContext->ResultFlags;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSecConfigParamSet(
    _In_ CXPLAT_SEC_CONFIG* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSecConfigParamGet(
    _In_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(SecConfig);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsExportKeyingMaterial(
    _In_ CXPLAT_TLS* TlsContext,
    _In_z_ const char* Label,
    _In_reads_bytes_opt_(ContextLength)
        const uint8_t* Context,
    _In_ uint32_t ContextLength,
    _Out_writes_bytes_(OutputLength)
        uint8_t* Output,
    _In_ uint32_t OutputLength
    )
{
    //
    // In TLS 1.3 an absent exporter context is equivalent to an empty one
    // (RFC 8446, Section 7.5).
    //
    if (ptls_export_secret(
            TlsContext->Tls,
            Output,
            OutputLength,
            Label,
            ptls_iovec_init(Context, Context != NULL ? ContextLength : 0),
            0) != 0) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "ptls_export_secret failed");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

_Success_(return==TRUE)
BOOLEAN
QuicTlsPopulateOffloadKeys(
    _Inout_ CXPLAT_TLS* TlsContext,
    _In_ const QUIC_PACKET_KEY* const PacketKey,
    _In_z_ const char* const SecretName,
    _Inout_ CXPLAT_QEO_CONNECTION* Offload
    )
{
    QUIC_STATUS Status =
        QuicPacketKeyDeriveOffload(
            TlsContext->HkdfLabels,
            PacketKey,
            SecretName,
            Offload);
    if (!QUIC_SUCCEEDED(Status)) {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            Status,
            "QuicTlsPopulateOffloadKeys");
        goto Error;
    }

Error:

    return QUIC_SUCCEEDED(Status);
}
