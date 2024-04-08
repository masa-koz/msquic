/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A path id set manages all PathID-related state for a single connection. It
    keeps track of locally and remotely initiated path ids, and synchronizes max
    path ids with the peer.

--*/

#include "precomp.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUninitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    if (PathIDSet->PathIDTable != NULL) {
        CxPlatHashtableUninitialize(PathIDSet->PathIDTable);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitializeTransportParameters(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t ClientPathCount,
    _In_ uint32_t ServerPathCount
    )
{
    QUIC_CONNECTION* Connection = QuicPathIDSetGetConnection(PathIDSet);
 
    if (ClientPathCount != 0) {
        PathIDSet->Types[PATHID_ID_FLAG_IS_CLIENT].MaxTotalPathIDCount = ClientPathCount;
    }

    if (ServerPathCount != 0) {
        PathIDSet->Types[PATHID_ID_FLAG_IS_SERVER].MaxTotalPathIDCount = ServerPathCount;
    }
}