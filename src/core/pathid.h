/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define NUMBER_OF_PATHID_TYPES          4

#define PATHID_ID_MASK                  0b1

#define PATHID_ID_FLAG_IS_CLIENT        0b00
#define PATHID_ID_FLAG_IS_SERVER        0b01

#define PATHID_ID_IS_CLIENT(ID)         ((ID & 1) == 0)
#define PATHID_ID_IS_SERVER(ID)         ((ID & 1) == 1)

//
// This structure represents all the per path id specific data.
//
typedef struct QUIC_PATHID {
} QUIC_PATHID;

//
// Allocates and partially initializes a new path id object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPathIDInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OpenedRemotely,
    _Outptr_ _At_(*PathID, __drv_allocatesMem(Mem))
        QUIC_STREAM** PathID
    );

//
// Free the path id object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPathIDFree(
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    );
