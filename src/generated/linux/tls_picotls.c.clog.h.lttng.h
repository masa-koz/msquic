


/*----------------------------------------------------------
// Decoder Ring for PicotlsHandshakeDataStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                    PicotlsHandshakeDataStart,
                    TlsContext->Connection,
                    "Writing Handshake data starts at %u",
                    State->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->BufferOffsetHandshake = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_PICOTLS_C, PicotlsHandshakeDataStart,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for Picotls1RttDataStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                    Picotls1RttDataStart,
                    TlsContext->Connection,
                    "Writing 1-RTT data starts at %u",
                    State->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->BufferOffset1Rtt = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_PICOTLS_C, Picotls1RttDataStart,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PicotlsHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnInfo(
                PicotlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_PICOTLS_C, PicotlsHandshakeComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_PICOTLS_C, OpenSslContextCreated,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_PICOTLS_C, OpenSslContextCleaningUp,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEC_CONFIG",
            sizeof(CXPLAT_SEC_CONFIG));
// arg2 = arg2 = "CXPLAT_SEC_CONFIG" = arg2
// arg3 = arg3 = sizeof(CXPLAT_SEC_CONFIG) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_PICOTLS_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = "SNI Too Long" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_PICOTLS_C, TlsError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)
