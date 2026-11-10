/*
 * Copyright (c) 2026 NITK Surathkal
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Aalima Khan <rimsha92k@gmail.com>
 *          Adurti V. L. Varshini <varshini.adurti2810@gmail.com>
 *          Ananya A. K. <ananyak29@gmail.com>
 *          Khade Vaishnavi Prashant <vaishnavik2552@gmail.com>
 *          Mohit P. Tahiliani <tahiliani@nitk.edu.in>
 */

/*
 * Tests for UDP over ILNPv6 (project #6).
 *
 *   1. Endpoint demux: same Identifier, different Locator -> same endpoint in
 *      ILNP mode, no endpoint in plain IPv6 mode.
 *   2. UDP checksum over a known I-LV pair (hand calculation below).
 *   3. Interop: an ILNP-mode node and a plain IPv6 node exchange UDP.
 *   4. Locator change mid-run (through the TEMPORARY IlnpIlccStub) keeps the
 *      same sockets working, with the Nonce Destination Option in every packet.
 */

#include "ns3/boolean.h"
#include "ns3/config.h"
#include "ns3/global-value.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/ilnp-ilcc-stub.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv6-address-helper.h"
#include "ns3/ipv6-end-point-demux.h"
#include "ns3/ipv6-end-point.h"
#include "ns3/ipv6-header.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-option-nonce.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simple-net-device-helper.h"
#include "ns3/simulator.h"
#include "ns3/socket.h"
#include "ns3/test.h"
#include "ns3/udp-header.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-socket-factory.h"

#include <map>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UdpIlnpTest");

namespace
{

const uint8_t UDP_PROTOCOL = 17; //!< UDP protocol number

/**
 * @ingroup internet-test
 * Test 1: the endpoint demux compares Identifiers only for ILNP-mode endpoints.
 */
class UdpIlnpDemuxTestCase : public TestCase
{
  public:
    UdpIlnpDemuxTestCase()
        : TestCase("UDP ILNP endpoint demux matches on Identifier")
    {
    }

  private:
    void DoRun() override
    {
        // Identifier ::1 (local) and ::2 (peer); the peer Locator changes.
        Ipv6Address local("2001:db8:0:1::1");
        Ipv6Address peerOld("2001:db8:0:1::2");
        Ipv6Address peerNew("2001:db8:0:2::2");  // same Identifier, new Locator
        Ipv6Address stranger("2001:db8:0:2::3"); // different Identifier

        for (bool ilnp : {true, false})
        {
            Ipv6EndPointDemux demux;
            Ipv6EndPoint* ep = demux.Allocate(nullptr, local, 1234, peerOld, 5000);
            NS_TEST_ASSERT_MSG_NE(ep, nullptr, "endpoint allocation failed");
            ep->SetIlnpMode(ilnp);

            // packet from the old Locator: always matches
            auto same = demux.Lookup(local, 1234, peerOld, 5000, nullptr);
            NS_TEST_EXPECT_MSG_EQ(same.size(), 1u, "exact match must be found");

            // packet from the new Locator: matches only in ILNP mode
            auto moved = demux.Lookup(local, 1234, peerNew, 5000, nullptr);
            NS_TEST_EXPECT_MSG_EQ(moved.size(),
                                  ilnp ? 1u : 0u,
                                  "new-Locator packet, ilnp=" << ilnp);
            // SimpleLookup (ICMP error path): in ILNP mode the new-Locator tuple is an
            // exact match. (In plain mode ns-3 already falls back to any endpoint on
            // the port, which is existing behaviour that we leave unchanged.)
            if (ilnp)
            {
                NS_TEST_EXPECT_MSG_EQ(demux.SimpleLookup(local, 1234, peerNew, 5000),
                                      ep,
                                      "SimpleLookup must find the ILNP endpoint");
            }

            // a different Identifier never matches
            auto other = demux.Lookup(local, 1234, stranger, 5000, nullptr);
            NS_TEST_EXPECT_MSG_EQ(other.size(), 0u, "different Identifier must not match");
        }
    }
};

/**
 * @ingroup internet-test
 * Test 2: UDP checksum over a known I-LV pair.
 *
 * Hand calculation (16-bit one's complement sum), source I-LV
 * 2001:db8:0:1::1, destination I-LV 2001:db8:0:2::2 (different Locators), UDP
 * ports 1000 -> 2000, payload 0xABCD (2 bytes), UDP length = 8 + 2 = 10:
 *
 *   source:      2001 0db8 0000 0001 0000 0000 0000 0001  -> 0x2DBB
 *   destination: 2001 0db8 0000 0002 0000 0000 0000 0002  -> 0x2DBD
 *   upper-layer length (32 bit): 0000 000A                 -> 0x000A
 *   next header (3 zero bytes + 17): 0000 0011             -> 0x0011
 *   UDP header: 03E8 + 07D0 + 000A + 0000                  -> 0x0BC2
 *   payload: ABCD
 *   total = 2DBB + 2DBD + 000A + 0011 + 0BC2 + ABCD = 0x11322
 *   fold carry: 0x1322 + 1 = 0x1323
 *   checksum = ~0x1323 = 0xECDC
 *
 * The draft draft-bhatti-ilnp-tcp-udp-checksums section 4.1 says the whole
 * source and destination I-LV are used, exactly as in IPv6.
 */
class UdpIlnpChecksumTestCase : public TestCase
{
  public:
    UdpIlnpChecksumTestCase()
        : TestCase("UDP checksum uses the full I-LV pair")
    {
    }

  private:
    uint32_t m_rx{0}; //!< datagrams delivered to the socket

    void Rx(Ptr<Socket> s)
    {
        while (s->Recv())
        {
            m_rx++;
        }
    }

    /**
     * Deliver a hand-built UDP segment to UdpL4Protocol::Receive.
     * @param udp the UDP protocol
     * @param iface the receiving interface
     * @param corrupt flip a payload bit after the checksum was computed
     * @return the receive status
     */
    IpL4Protocol::RxStatus Deliver(Ptr<UdpL4Protocol> udp, Ptr<Ipv6Interface> iface, bool corrupt)
    {
        Ipv6Address src("2001:db8:0:1::1");
        Ipv6Address dst("2001:db8:0:2::2");
        uint8_t payload[2] = {0xAB, 0xCD};
        Ptr<Packet> p = Create<Packet>(payload, 2);

        UdpHeader hdr;
        hdr.SetSourcePort(1000);
        hdr.SetDestinationPort(2000);
        hdr.InitializeChecksum(src, dst, UDP_PROTOCOL);
        hdr.EnableChecksums();
        p->AddHeader(hdr);

        // read back the checksum field computed by ns-3
        uint8_t raw[10];
        p->CopyData(raw, 10);
        uint16_t sum = (raw[6] << 8) | raw[7];
        NS_TEST_EXPECT_MSG_EQ(sum, 0xECDC, "checksum must equal the hand calculation");

        if (corrupt)
        {
            raw[9] ^= 0x01; // flip one payload bit
            p = Create<Packet>(raw, 10);
        }

        Ipv6Header ip;
        ip.SetSource(src);
        ip.SetDestination(dst);
        ip.SetNextHeader(UDP_PROTOCOL);
        ip.SetPayloadLength(10);
        return udp->Receive(p, ip, iface);
    }

    void DoRun() override
    {
        GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

        Ptr<Node> node = CreateObject<Node>();
        SimpleNetDeviceHelper dev;
        NetDeviceContainer d = dev.Install(NodeContainer(node));
        InternetStackHelper internet;
        internet.Install(node);
        Ipv6AddressHelper ipv6helper;
        ipv6helper.AssignWithoutAddress(d);
        Ptr<Ipv6> ipv6 = node->GetObject<Ipv6>();
        int32_t ifIndex = ipv6->GetInterfaceForDevice(d.Get(0));
        ipv6->AddAddress(ifIndex,
                         Ipv6InterfaceAddress(Ipv6Address("2001:db8:0:2::2"), Ipv6Prefix(64)));
        ipv6->SetUp(ifIndex);

        Ptr<Socket> sock = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
        sock->SetAttribute("IlnpMode", BooleanValue(true));
        NS_TEST_ASSERT_MSG_EQ(sock->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 2000)),
                              0,
                              "bind failed");
        sock->SetRecvCallback(MakeCallback(&UdpIlnpChecksumTestCase::Rx, this));

        Ptr<UdpL4Protocol> udp = node->GetObject<UdpL4Protocol>();
        Ptr<Ipv6Interface> iface = node->GetObject<Ipv6L3Protocol>()->GetInterface(ifIndex);

        auto good = Deliver(udp, iface, false);
        NS_TEST_EXPECT_MSG_EQ(good, IpL4Protocol::RX_OK, "valid checksum must be accepted");
        NS_TEST_EXPECT_MSG_EQ(m_rx, 1u, "valid datagram must reach the socket");

        auto bad = Deliver(udp, iface, true);
        NS_TEST_EXPECT_MSG_EQ(bad, IpL4Protocol::RX_CSUM_FAILED, "corrupted datagram dropped");
        NS_TEST_EXPECT_MSG_EQ(m_rx, 1u, "corrupted datagram must not reach the socket");

        Simulator::Destroy();
        GlobalValue::Bind("ChecksumEnabled", BooleanValue(false));
    }
};

/**
 * @ingroup internet-test
 * Two-node fixture for tests 3 and 4: one SimpleNetDevice link, nodes A (client)
 * and B (server), each with the temporary IlnpIlccStub aggregated. Identifiers:
 * A = ::1, B = ::2. Initial Locator 2001:db8:1::/64, after the change
 * 2001:db8:2::/64.
 */
class UdpIlnpTwoNodeTestCase : public TestCase
{
  public:
    /**
     * @param name test name
     * @param ilnpClient ILNP mode on the client socket
     * @param ilnpServer ILNP mode on the server socket
     * @param changeLocator move both nodes to a new Locator at t = 5 s
     */
    UdpIlnpTwoNodeTestCase(const std::string& name,
                           bool ilnpClient,
                           bool ilnpServer,
                           bool changeLocator)
        : TestCase(name),
          m_ilnpClient(ilnpClient),
          m_ilnpServer(ilnpServer),
          m_change(changeLocator)
    {
    }

  private:
    static constexpr uint64_t LOC1 = 0x20010db800010000ULL; //!< initial Locator
    static constexpr uint64_t LOC2 = 0x20010db800020000ULL; //!< Locator after the change
    static constexpr uint64_t ID_A = 1;                     //!< client Identifier
    static constexpr uint64_t ID_B = 2;                     //!< server Identifier

    bool m_ilnpClient;                                     //!< client ILNP mode
    bool m_ilnpServer;                                     //!< server ILNP mode
    bool m_change;                                         //!< change Locator mid-run
    Ptr<Node> m_a;                                         //!< client node
    Ptr<Node> m_b;                                         //!< server node
    Ptr<Socket> m_client;                                  //!< client socket
    Ptr<Socket> m_server;                                  //!< server socket
    uint32_t m_sent{0};                                    //!< datagrams sent by client
    uint32_t m_serverRx{0};                                //!< datagrams received by server
    uint32_t m_clientRx{0};                                //!< echoes received by client
    uint32_t m_serverRxNewLoc{0};                          //!< server rx from the new Locator
    uint32_t m_udpTx{0};                                   //!< UDP packets sent (both nodes)
    uint32_t m_udpTxWithNonce{0};                          //!< of which carry the nonce
    std::map<uint64_t, std::vector<uint8_t>> m_firstNonce; //!< first nonce per sender Identifier
    uint32_t m_nonceMismatch{0};                           //!< packets with another nonce value
    std::vector<uint32_t> m_ifaceA;                        //!< interface index of A
    uint32_t m_ifA{0};                                     //!< interface of A
    uint32_t m_ifB{0};                                     //!< interface of B

    static Ipv6Address Addr(uint64_t loc, uint64_t id)
    {
        return IlnpLocatorProvider::MakeAddress(loc, id);
    }

    void AddAddr(Ptr<Node> n, uint32_t ifIndex, uint64_t loc, uint64_t id)
    {
        Ptr<Ipv6> ipv6 = n->GetObject<Ipv6>();
        ipv6->AddAddress(ifIndex, Ipv6InterfaceAddress(Addr(loc, id), Ipv6Prefix(64)));
    }

    /** Trace of every IPv6 packet leaving a node: look for the nonce in UDP packets. */
    void OnSend(const Ipv6Header& hdr, Ptr<const Packet> pkt, uint32_t)
    {
        uint8_t first = hdr.GetNextHeader();
        std::vector<uint8_t> b(pkt->GetSize());
        pkt->CopyData(b.data(), b.size());
        bool isUdp = (first == UDP_PROTOCOL);
        bool nonce = false;
        std::vector<uint8_t> value;
        if (first == Ipv6Header::IPV6_EXT_DESTINATION && b.size() > 4 && b[0] == UDP_PROTOCOL &&
            b[2] == Ipv6OptionNonceHeader::NONCE_OPTION_TYPE)
        {
            isUdp = true;
            nonce = true;
            value.assign(b.begin() + 4, b.begin() + 4 + b[3]);
        }
        if (!isUdp)
        {
            return; // ND / ICMPv6 traffic
        }
        m_udpTx++;
        if (nonce)
        {
            m_udpTxWithNonce++;
            // NOTE: one nonce per direction. NC3 (same value in both directions) is NOT
            // met for UDP today because Ipv6OptionNonce::Process learns sessions under
            // protocol 58 only (project #4 code, not changed here).
            uint64_t sender = IlnpLocatorProvider::GetIdentifier(hdr.GetSource());
            auto it = m_firstNonce.find(sender);
            if (it == m_firstNonce.end())
            {
                m_firstNonce[sender] = value;
            }
            else if (value != it->second)
            {
                m_nonceMismatch++;
            }
        }
    }

    void ServerRx(Ptr<Socket> s)
    {
        Address from;
        while (Ptr<Packet> p = s->RecvFrom(from))
        {
            m_serverRx++;
            Ipv6Address src = Inet6SocketAddress::ConvertFrom(from).GetIpv6();
            if (IlnpLocatorProvider::GetLocator(src) == LOC2)
            {
                m_serverRxNewLoc++;
            }
            s->SendTo(p, 0, from); // echo
        }
    }

    void ClientRx(Ptr<Socket> s)
    {
        while (s->Recv())
        {
            m_clientRx++;
        }
    }

    void ClientSend()
    {
        m_client->Send(Create<Packet>(100));
        m_sent++;
    }

    /** Simulate the Locator Update on both nodes (stub update methods). */
    void ChangeLocator()
    {
        AddAddr(m_a, m_ifA, LOC2, ID_A);
        AddAddr(m_b, m_ifB, LOC2, ID_B);
        auto sa = m_a->GetObject<IlnpIlccStub>();
        auto sb = m_b->GetObject<IlnpIlccStub>();
        sa->SetLocalLocator(m_ifA, ID_A, LOC2);
        sa->SetPeerLocator(ID_B, LOC2);
        sb->SetLocalLocator(m_ifB, ID_B, LOC2);
        sb->SetPeerLocator(ID_A, LOC2);
    }

    void DoRun() override
    {
        m_a = CreateObject<Node>();
        m_b = CreateObject<Node>();
        NodeContainer nodes(m_a, m_b);
        SimpleNetDeviceHelper dev;
        dev.SetNetDevicePointToPointMode(true);
        NetDeviceContainer d = dev.Install(nodes);
        InternetStackHelper internet;
        internet.Install(nodes);
        Ipv6AddressHelper ipv6helper;
        ipv6helper.AssignWithoutAddress(d);
        for (auto n : {m_a, m_b})
        {
            n->GetObject<Icmpv6L4Protocol>()->SetAttribute("DAD", BooleanValue(false));
            n->AggregateObject(CreateObject<IlnpIlccStub>());
        }
        m_ifA = m_a->GetObject<Ipv6>()->GetInterfaceForDevice(d.Get(0));
        m_ifB = m_b->GetObject<Ipv6>()->GetInterfaceForDevice(d.Get(1));
        AddAddr(m_a, m_ifA, LOC1, ID_A);
        AddAddr(m_b, m_ifB, LOC1, ID_B);
        m_a->GetObject<Ipv6>()->SetUp(m_ifA);
        m_b->GetObject<Ipv6>()->SetUp(m_ifB);
        m_a->GetObject<IlnpIlccStub>()->SetLocalLocator(m_ifA, ID_A, LOC1);
        m_a->GetObject<IlnpIlccStub>()->SetPeerLocator(ID_B, LOC1);
        m_b->GetObject<IlnpIlccStub>()->SetLocalLocator(m_ifB, ID_B, LOC1);
        m_b->GetObject<IlnpIlccStub>()->SetPeerLocator(ID_A, LOC1);

        for (auto n : {m_a, m_b})
        {
            n->GetObject<Ipv6L3Protocol>()->TraceConnectWithoutContext(
                "SendOutgoing",
                MakeCallback(&UdpIlnpTwoNodeTestCase::OnSend, this));
        }

        m_server = Socket::CreateSocket(m_b, UdpSocketFactory::GetTypeId());
        m_server->SetAttribute("IlnpMode", BooleanValue(m_ilnpServer));
        NS_TEST_ASSERT_MSG_EQ(m_server->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 9)),
                              0,
                              "server bind failed");
        m_server->SetRecvCallback(MakeCallback(&UdpIlnpTwoNodeTestCase::ServerRx, this));

        m_client = Socket::CreateSocket(m_a, UdpSocketFactory::GetTypeId());
        m_client->SetAttribute("IlnpMode", BooleanValue(m_ilnpClient));
        // Connect to B's *initial* I-LV: after the Locator change the replies come
        // from another Locator, so only Identifier matching keeps the flow alive.
        m_client->Connect(Inet6SocketAddress(Addr(LOC1, ID_B), 9));
        m_client->SetRecvCallback(MakeCallback(&UdpIlnpTwoNodeTestCase::ClientRx, this));

        for (uint32_t i = 0; i < 10; i++)
        {
            Simulator::Schedule(Seconds(1 + i), &UdpIlnpTwoNodeTestCase::ClientSend, this);
        }
        if (m_change)
        {
            Simulator::Schedule(Seconds(5.5), &UdpIlnpTwoNodeTestCase::ChangeLocator, this);
        }
        Simulator::Stop(Seconds(15));
        Simulator::Run();
        Simulator::Destroy();

        NS_TEST_EXPECT_MSG_EQ(m_sent, 10u, "client sent 10 datagrams");
        NS_TEST_EXPECT_MSG_EQ(m_serverRx, 10u, "server must receive every datagram");
        NS_TEST_EXPECT_MSG_EQ(m_clientRx, 10u, "client must receive every echo");
        if (m_ilnpClient)
        {
            NS_TEST_EXPECT_MSG_EQ(m_udpTx, 20u, "10 requests + 10 echoes");
            // Both ends in ILNP mode: every request and echo has the nonce. If the server
            // is plain IPv6 only the client requests are ILNP; the plain replies are ordinary.
            NS_TEST_EXPECT_MSG_EQ(m_udpTxWithNonce,
                                  m_ilnpServer ? m_udpTx : 10u,
                                  "ILNP UDP packets must carry the Nonce option");
            NS_TEST_EXPECT_MSG_EQ(m_nonceMismatch, 0u, "nonce must stay constant within a direction across the Locator change");
        }
        if (m_change)
        {
            NS_TEST_EXPECT_MSG_GT(m_serverRxNewLoc, 0u, "traffic must move to the new Locator");
        }
    }
};

/**
 * @ingroup internet-test
 * UDP over ILNPv6 test suite.
 */
class UdpIlnpTestSuite : public TestSuite
{
  public:
    UdpIlnpTestSuite()
        : TestSuite("udp-ilnp", Type::UNIT)
    {
        AddTestCase(new UdpIlnpDemuxTestCase, TestCase::Duration::QUICK);
        AddTestCase(new UdpIlnpChecksumTestCase, TestCase::Duration::QUICK);
        AddTestCase(new UdpIlnpTwoNodeTestCase("ILNP client with plain IPv6 server (interop)",
                                               true,
                                               false,
                                               false),
                    TestCase::Duration::QUICK);
        AddTestCase(new UdpIlnpTwoNodeTestCase("Locator change mid-run keeps the UDP flow",
                                               true,
                                               true,
                                               true),
                    TestCase::Duration::QUICK);
    }
};

static UdpIlnpTestSuite g_udpIlnpTestSuite; //!< static test suite instance

} // namespace
