#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TLS_PICOTLS_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tls_picotls.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_TLS_PICOTLS_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TLS_PICOTLS_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "tls_picotls.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnError
#define _clog_MACRO_QuicTraceLogConnError  1
#define QuicTraceLogConnError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PicotlsAlpnNegotiationFailure
// [conn][%p] Failed to negotiate ALPN
// QuicTraceLogConnError(
                        PicotlsAlpnNegotiationFailure,
                        TlsContext->Connection,
                        "Failed to negotiate ALPN");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PicotlsAlpnNegotiationFailure
#define _clog_3_ARGS_TRACE_PicotlsAlpnNegotiationFailure(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_PICOTLS_C, PicotlsAlpnNegotiationFailure , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PicotlsInvalidAlpnLength
// [conn][%p] Invalid negotiated ALPN length
// QuicTraceLogConnError(
                        PicotlsInvalidAlpnLength,
                        TlsContext->Connection,
                        "Invalid negotiated ALPN length");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PicotlsInvalidAlpnLength
#define _clog_3_ARGS_TRACE_PicotlsInvalidAlpnLength(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_PICOTLS_C, PicotlsInvalidAlpnLength , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PicotlsNoMatchingAlpn
// [conn][%p] Failed to find a matching ALPN
// QuicTraceLogConnError(
                        PicotlsNoMatchingAlpn,
                        TlsContext->Connection,
                        "Failed to find a matching ALPN");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PicotlsNoMatchingAlpn
#define _clog_3_ARGS_TRACE_PicotlsNoMatchingAlpn(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_PICOTLS_C, PicotlsNoMatchingAlpn , arg1);\

#endif




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
#ifndef _clog_4_ARGS_TRACE_PicotlsHandshakeDataStart
#define _clog_4_ARGS_TRACE_PicotlsHandshakeDataStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_PICOTLS_C, PicotlsHandshakeDataStart , arg1, arg3);\

#endif




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
#ifndef _clog_4_ARGS_TRACE_Picotls1RttDataStart
#define _clog_4_ARGS_TRACE_Picotls1RttDataStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_PICOTLS_C, Picotls1RttDataStart , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PicotlsHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnInfo(
                PicotlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PicotlsHandshakeComplete
#define _clog_3_ARGS_TRACE_PicotlsHandshakeComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_PICOTLS_C, PicotlsHandshakeComplete , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PicotlsContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        PicotlsContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PicotlsContextCreated
#define _clog_3_ARGS_TRACE_PicotlsContextCreated(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_PICOTLS_C, PicotlsContextCreated , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PicotlsContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            PicotlsContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PicotlsContextCleaningUp
#define _clog_3_ARGS_TRACE_PicotlsContextCleaningUp(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_PICOTLS_C, PicotlsContextCleaningUp , arg1);\

#endif




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
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_PICOTLS_C, AllocFailure , arg2, arg3);\

#endif




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
#ifndef _clog_4_ARGS_TRACE_TlsError
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_PICOTLS_C, TlsError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            Status,
            "QuicTlsPopulateOffloadKeys");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "QuicTlsPopulateOffloadKeys" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_PICOTLS_C, TlsErrorStatus , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_picotls.c.clog.h.c"
#endif
