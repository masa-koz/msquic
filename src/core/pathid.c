/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A path id manages the resources for multipath. This file
    contains the initialization and cleanup functionality for the path id.

--*/

#include "precomp.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPathIDInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OpenedRemotely,
    _Outptr_ _At_(*PathID, __drv_allocatesMem(Mem))
        QUIC_PATHID** NewPathID
    )
{
    QUIC_STATUS Status;
    QUIC_PATHID* PathID;
    QUIC_WORKER* Worker = Connection->Worker;

    PathID = CxPlatPoolAlloc(&Worker->PathIDPool);
    if (PathID == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(PathID, sizeof(QUIC_PATHID));

    PathID->ID = UINT32_MAX;
    *NewPathID = PathID;
    Status = QUIC_STATUS_SUCCESS;

Exit:
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPathIDFree(
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    )
{
    
}
