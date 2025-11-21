#include "platform_internal.h"
#include "picotls.h"
#include "picotls/minicrypto.h"
#ifdef QUIC_CLOG
#include "tls_picotls.c.clog.h"
#endif

typedef struct CXPLAT_SEC_CONFIG {

    //
    // SSL context used for establishing TLS connections.
    //
    ptls_context_t Ctx;

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

    //
    // Pointer to the Server Name Indication (SNI) string.
    //
    const char* SNI;

    //
    // Picotls SSL object used for the TLS handshake and encryption.
    //
    ptls_t *Tls;

    ptls_update_traffic_key_t UpdateTrafficKey;
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
    default:
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
    // Invoke completion inline.
    //

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = NULL;

    if (TlsCredFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
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
            if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                                TlsContext->Connection,
                                Slots[i].data.len,
                                Slots[i].data.base)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                return 0;
            }
        }
    }
    return 1;
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
            CxPlatCopyMemory(Secret.Secret, NewSecret, Cipher->hash->digest_size);
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
                return 0;
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
            CxPlatCopyMemory(Secret.Secret, NewSecret, Cipher->hash->digest_size);
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
                return 0;
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

    return 1;
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
    uint16_t ServerNameLength = 0;
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

    if (!Config->IsServer) {

        if (Config->ServerName != NULL) {

            ServerNameLength = (uint16_t)strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);
            if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            TlsContext->SNI = CXPLAT_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_TLS_SNI);
            if (TlsContext->SNI == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "SNI",
                    ServerNameLength + 1);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Exit;
            }

            memcpy((char*)TlsContext->SNI, Config->ServerName, ServerNameLength + 1);
        }
    }

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

    TlsContext->UpdateTrafficKey.cb = CxPlatTlsUpdateTrafficKeyCallback;
    TlsContext->SecConfig->Ctx.update_traffic_key = &TlsContext->UpdateTrafficKey;

    TlsContext->HandshakeProperties.collect_extension = CxPlatTlsCollectExtenionCallback;
    TlsContext->HandshakeProperties.collected_extensions = CxPlatTlsCollectedExtenionsCallback;

    TlsContext->Extensions[0].type = TlsContext->QuicTpExtType;
    TlsContext->Extensions[0].data.base = (uint8_t *)Config->LocalTPBuffer;
    TlsContext->Extensions[0].data.len = Config->LocalTPLength;
    TlsContext->Extensions[1].type = 0xFFFF;
    TlsContext->Extensions[1].data.base = NULL;
    TlsContext->Extensions[1].data.len = 0;
    TlsContext->HandshakeProperties.additional_extensions = TlsContext->Extensions;

    Status = QUIC_STATUS_SUCCESS;
    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Exit:

    if (TlsContext) {
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

        if (TlsContext->SNI != NULL) {
            CXPLAT_FREE(TlsContext->SNI, QUIC_POOL_TLS_SNI);
            TlsContext->SNI = NULL;
        }

        if (TlsContext->Tls != NULL) {
            ptls_free(TlsContext->Tls);
            TlsContext->Tls = NULL;
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
    *BufferLength = 0;
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
                (EpochOffsets[QUIC_PACKET_KEY_HANDSHAKE] < EpochOffsets[QUIC_PACKET_KEY_HANDSHAKE + 1])) {
                State->BufferOffsetHandshake = EpochOffsets[QUIC_PACKET_KEY_HANDSHAKE];
                QuicTraceLogConnInfo(
                    PicotlsHandshakeDataStart,
                    TlsContext->Connection,
                    "Writing Handshake data starts at %u",
                    State->BufferOffsetHandshake);
            }

            if (State->BufferOffset1Rtt == 0 &&
                (EpochOffsets[QUIC_PACKET_KEY_1_RTT] < EpochOffsets[QUIC_PACKET_KEY_1_RTT + 1])) {
                State->BufferOffset1Rtt = EpochOffsets[QUIC_PACKET_KEY_1_RTT];
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
        }
    }

    if (Ret == 0 && !State->HandshakeComplete) {
        if (ptls_handshake_is_complete(TlsContext->Tls)) {
            State->HandshakeComplete = TRUE;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE;

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
    ptls_buffer_dispose(&Sendbuf);
    return TlsContext->ResultFlags;
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
