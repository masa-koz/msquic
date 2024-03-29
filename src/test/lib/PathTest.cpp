/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Path Unittest

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "PathTest.cpp.clog.h"
#endif

struct PathTestContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent PeerAddrChangedEvent;

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestContext* Ctx = static_cast<PathTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->PeerAddrChangedEvent.Set();
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED) {
            MsQuicSettings Settings;
            Conn->GetSettings(&Settings);
            Settings.IsSetFlags = 0;
            Settings.SetPeerBidiStreamCount(Settings.PeerBidiStreamCount + 1);
            Conn->SetSettings(Settings);
            Ctx->PeerAddrChangedEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

static
QUIC_STATUS
QUIC_API
ClientCallback(
    _In_ MsQuicConnection* /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept
{
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
        CxPlatEvent* StreamCountEvent = static_cast<CxPlatEvent*>(Context);
        StreamCountEvent->Set();
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestLocalPathChanges(
    _In_ int Family
    )
{
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
    MsQuicRegistration Registration{true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicSettings Settings;
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);
    TEST_TRUE(Context.Connection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr OrigLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(OrigLocalAddr));
    ReplaceAddressHelper AddrHelper(OrigLocalAddr.SockAddr, OrigLocalAddr.SockAddr);

    uint16_t ServerPort = ServerLocalAddr.GetPort();
    for (int i = 0; i < 50; i++) {
        uint16_t NextPort = QuicAddrGetPort(&AddrHelper.New) + 1;
        if (NextPort == ServerPort) {
            // Skip the port if it is same as that of server
            // This is to avoid Loopback test failure
            NextPort++;
        }
        QuicAddrSetPort(&AddrHelper.New, NextPort);
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

        TEST_TRUE(Context.PeerAddrChangedEvent.WaitTimeout(1500));
        Context.PeerAddrChangedEvent.Reset();
        QuicAddr ServerRemoteAddr;
        TEST_QUIC_SUCCEEDED(Context.Connection->GetRemoteAddr(ServerRemoteAddr));
        TEST_TRUE(QuicAddrCompare(&AddrHelper.New, &ServerRemoteAddr.SockAddr));
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
        TEST_TRUE(PeerStreamsChanged.WaitTimeout(1500));
        PeerStreamsChanged.Reset();
    }
}

struct ProbeTestContext {
    bool Connected {false};
    BOOLEAN IsServer;
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent PathValidatedEvent;
    QUIC_ADDR NewAddr;
    ProbeTestContext(BOOLEAN IsServer) : IsServer(IsServer) {};
    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        auto This = static_cast<ProbeTestContext*>(Context);
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            This->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            This->Connected = true;
            This->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_VALIDATED) {
            if (!This->IsServer && QuicAddrCompare(Event->PATH_VALIDATED.LocalAddress, &This->NewAddr)) {
                This->PathValidatedEvent.Set();
            }
            if (This->IsServer && QuicAddrCompare(Event->PATH_VALIDATED.PeerAddress, &This->NewAddr)) {
                This->PathValidatedEvent.Set();
            }
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestProbePath(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ uint32_t DropPacketCount
    )
{
    ProbeTestContext ServerContext(TRUE), ClientContext(FALSE);
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, ProbeTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, ProbeTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.Connected);

    uint16_t Count = 0;
    uint32_t Try = 0;

    do {
        if (Try != 0) {
            CxPlatSleep(100);
        }
        uint32_t Size = sizeof(Count);
        QUIC_STATUS Status =
            Connection.GetParam(
                QUIC_PARAM_CONN_LOCAL_UNUSED_DEST_CID_COUNT,
                &Size,
                &Count);
        if (QUIC_FAILED(Status)) {
            break;
        }
    } while (Count == 0 && ++Try <= 3);
    TEST_NOT_EQUAL(Count, 0);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.IncrementPort();

    ServerContext.NewAddr = SecondLocalAddr.SockAddr;
    ClientContext.NewAddr = SecondLocalAddr.SockAddr;

    PathProbeHelper ProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);

    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(
            QUIC_PARAM_CONN_ADD_LOCAL_ADDRESS,
            sizeof(SecondLocalAddr.SockAddr),
            &SecondLocalAddr.SockAddr));

    TEST_TRUE(ProbeHelper.ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper.ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    QUIC_STATISTICS_V2 Stats;
    uint32_t Size = sizeof(Stats);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(
            QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
            &Size,
            &Stats));
    TEST_EQUAL(Stats.RecvDroppedPackets, 0);

    TEST_TRUE(ClientContext.PathValidatedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.PathValidatedEvent.WaitTimeout(TestWaitTimeout));

}

struct MigrationTestClientContext {
    bool Connected {false};
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent PathValidatedEvent;
    CxPlatEvent StreamCountEvent;
    QUIC_ADDR NewAddr;
    
    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection*, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        auto This = static_cast<MigrationTestClientContext*>(Context);
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            This->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            This->Connected = true;
            This->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_VALIDATED) {
            if (QuicAddrCompare(Event->PATH_VALIDATED.LocalAddress, &This->NewAddr)) {
                This->PathValidatedEvent.Set();
            }
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
            This->StreamCountEvent.Set();
        }

        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestMigration(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN Smooth
    )
{
    PathTestContext ServerContext;
    MigrationTestClientContext ClientContext;
    
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, MigrationTestClientContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    uint16_t Count = 0;
    uint32_t Try = 0;

    do {
        if (Try != 0) {
            CxPlatSleep(100);
        }
        uint32_t Size = sizeof(Count);
        QUIC_STATUS Status =
            Connection.GetParam(
                QUIC_PARAM_CONN_LOCAL_UNUSED_DEST_CID_COUNT,
                &Size,
                &Count);
        if (QUIC_FAILED(Status)) {
            break;
        }
    } while (Count == 0 && ++Try <= 3);
    TEST_NOT_EQUAL(Count, 0);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.IncrementPort();

    ClientContext.NewAddr = SecondLocalAddr.SockAddr;

    PathProbeHelper ProbeHelper(SecondLocalAddr.GetPort());

    if (Smooth) {
        TEST_QUIC_SUCCEEDED(
            Connection.SetParam(
                QUIC_PARAM_CONN_ADD_LOCAL_ADDRESS,
                sizeof(SecondLocalAddr.SockAddr),
                &SecondLocalAddr.SockAddr));
        TEST_TRUE(ProbeHelper.ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ProbeHelper.ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        QUIC_STATISTICS_V2 Stats;
        uint32_t Size = sizeof(Stats);
        TEST_QUIC_SUCCEEDED(
            Connection.GetParam(
                QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
                &Size,
                &Stats));
        TEST_EQUAL(Stats.RecvDroppedPackets, 0);

        TEST_TRUE(ClientContext.PathValidatedEvent.WaitTimeout(TestWaitTimeout));
    }

    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(SecondLocalAddr.SockAddr),
            &SecondLocalAddr.SockAddr));

    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

    TEST_TRUE(ServerContext.PeerAddrChangedEvent.WaitTimeout(1500));
    QuicAddr ServerRemoteAddr;
    TEST_QUIC_SUCCEEDED(ServerContext.Connection->GetRemoteAddr(ServerRemoteAddr));
    TEST_TRUE(QuicAddrCompare(&SecondLocalAddr.SockAddr, &ServerRemoteAddr.SockAddr));
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
    TEST_TRUE(ClientContext.StreamCountEvent.WaitTimeout(1500));
}
