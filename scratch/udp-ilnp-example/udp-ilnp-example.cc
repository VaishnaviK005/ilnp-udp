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
 * UDP echo over ILNPv6 with a Locator change halfway.
 *
 * Two nodes share one link. Client A (Identifier ::1) sends one datagram per
 * second to server B (Identifier ::2); B echoes it. At t = 5.5 s both nodes
 * move from Locator 2001:db8:1::/64 to 2001:db8:2::/64. The Locator change is
 * simulated through the TEMPORARY IlnpIlccStub (not the real ILCC). The same
 * sockets keep working; every UDP packet prints the Nonce Destination Option.
 *
 * Run: ./ns3 run udp-ilnp-example
 */

#include "ns3/boolean.h"
#include "ns3/command-line.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/ilnp-ilcc-stub.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv6-address-helper.h"
#include "ns3/ipv6-header.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/ipv6-option-nonce.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simple-net-device-helper.h"
#include "ns3/simulator.h"
#include "ns3/socket.h"
#include "ns3/udp-socket-factory.h"

#include <iomanip>
#include <iostream>

using namespace ns3;

namespace
{
const uint64_t LOC1 = 0x20010db800010000ULL; //!< initial Locator 2001:db8:1::/64
const uint64_t LOC2 = 0x20010db800020000ULL; //!< new Locator 2001:db8:2::/64
const uint64_t ID_A = 1;                     //!< client Identifier
const uint64_t ID_B = 2;                     //!< server Identifier

Ptr<Node> g_a;           //!< client
Ptr<Node> g_b;           //!< server
Ptr<Socket> g_client;    //!< client socket
uint32_t g_ifA;          //!< client interface index
uint32_t g_ifB;          //!< server interface index
uint32_t g_sent = 0;     //!< datagrams sent
uint32_t g_serverRx = 0; //!< datagrams received by the server
uint32_t g_clientRx = 0; //!< echoes received by the client

/** Print every UDP packet leaving a node, with its nonce. */
void
OnSend(const Ipv6Header& hdr, Ptr<const Packet> pkt, uint32_t)
{
    std::vector<uint8_t> b(pkt->GetSize());
    pkt->CopyData(b.data(), b.size());
    if (hdr.GetNextHeader() != Ipv6Header::IPV6_EXT_DESTINATION || b.size() < 4 || b[0] != 17)
    {
        return; // not UDP (neighbour discovery etc.)
    }
    std::cout << std::fixed << std::setprecision(1) << Simulator::Now().GetSeconds() << "s  "
              << hdr.GetSource() << " -> " << hdr.GetDestination() << "  nonce=0x" << std::hex
              << std::setfill('0');
    if (b[2] == Ipv6OptionNonceHeader::NONCE_OPTION_TYPE)
    {
        for (uint32_t i = 0; i < b[3]; i++)
        {
            std::cout << std::setw(2) << static_cast<uint32_t>(b[4 + i]);
        }
    }
    else
    {
        std::cout << "NONE";
    }
    std::cout << std::dec << std::setfill(' ') << std::endl;
}

void
ServerRx(Ptr<Socket> s)
{
    Address from;
    while (Ptr<Packet> p = s->RecvFrom(from))
    {
        g_serverRx++;
        std::cout << "   server received " << p->GetSize() << " B from "
                  << Inet6SocketAddress::ConvertFrom(from).GetIpv6() << std::endl;
        s->SendTo(p, 0, from);
    }
}

void
ClientRx(Ptr<Socket> s)
{
    Address from;
    while (Ptr<Packet> p = s->RecvFrom(from))
    {
        g_clientRx++;
        std::cout << "   client received echo of " << p->GetSize() << " B from "
                  << Inet6SocketAddress::ConvertFrom(from).GetIpv6() << std::endl;
    }
}

void
ClientSend()
{
    g_sent++;
    std::cout << "client sends datagram #" << g_sent << std::endl;
    g_client->Send(Create<Packet>(100));
}

void
AddAddr(Ptr<Node> n, uint32_t ifIndex, uint64_t loc, uint64_t id)
{
    n->GetObject<Ipv6>()->AddAddress(
        ifIndex,
        Ipv6InterfaceAddress(IlnpLocatorProvider::MakeAddress(loc, id), Ipv6Prefix(64)));
}

void
ChangeLocator()
{
    std::cout << "---- Locator change: 2001:db8:1::/64 -> 2001:db8:2::/64 (via IlnpIlccStub) ----"
              << std::endl;
    AddAddr(g_a, g_ifA, LOC2, ID_A);
    AddAddr(g_b, g_ifB, LOC2, ID_B);
    auto sa = g_a->GetObject<IlnpIlccStub>();
    auto sb = g_b->GetObject<IlnpIlccStub>();
    sa->SetLocalLocator(g_ifA, ID_A, LOC2);
    sa->SetPeerLocator(ID_B, LOC2);
    sb->SetLocalLocator(g_ifB, ID_B, LOC2);
    sb->SetPeerLocator(ID_A, LOC2);
}
} // namespace

int
main(int argc, char* argv[])
{
    CommandLine cmd(__FILE__);
    cmd.Parse(argc, argv);

    g_a = CreateObject<Node>();
    g_b = CreateObject<Node>();
    NodeContainer nodes(g_a, g_b);
    SimpleNetDeviceHelper dev;
    dev.SetNetDevicePointToPointMode(true);
    NetDeviceContainer d = dev.Install(nodes);
    InternetStackHelper internet;
    internet.Install(nodes);
    Ipv6AddressHelper ipv6helper;
    ipv6helper.AssignWithoutAddress(d);
    for (auto n : {g_a, g_b})
    {
        n->GetObject<Icmpv6L4Protocol>()->SetAttribute("DAD", BooleanValue(false));
        n->AggregateObject(CreateObject<IlnpIlccStub>());
        n->GetObject<Ipv6L3Protocol>()->TraceConnectWithoutContext("SendOutgoing",
                                                                   MakeCallback(&OnSend));
    }
    g_ifA = g_a->GetObject<Ipv6>()->GetInterfaceForDevice(d.Get(0));
    g_ifB = g_b->GetObject<Ipv6>()->GetInterfaceForDevice(d.Get(1));
    AddAddr(g_a, g_ifA, LOC1, ID_A);
    AddAddr(g_b, g_ifB, LOC1, ID_B);
    g_a->GetObject<Ipv6>()->SetUp(g_ifA);
    g_b->GetObject<Ipv6>()->SetUp(g_ifB);
    g_a->GetObject<IlnpIlccStub>()->SetLocalLocator(g_ifA, ID_A, LOC1);
    g_a->GetObject<IlnpIlccStub>()->SetPeerLocator(ID_B, LOC1);
    g_b->GetObject<IlnpIlccStub>()->SetLocalLocator(g_ifB, ID_B, LOC1);
    g_b->GetObject<IlnpIlccStub>()->SetPeerLocator(ID_A, LOC1);

    Ptr<Socket> server = Socket::CreateSocket(g_b, UdpSocketFactory::GetTypeId());
    server->SetAttribute("IlnpMode", BooleanValue(true));
    server->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 9));
    server->SetRecvCallback(MakeCallback(&ServerRx));

    g_client = Socket::CreateSocket(g_a, UdpSocketFactory::GetTypeId());
    g_client->SetAttribute("IlnpMode", BooleanValue(true));
    g_client->Connect(Inet6SocketAddress(IlnpLocatorProvider::MakeAddress(LOC1, ID_B), 9));
    g_client->SetRecvCallback(MakeCallback(&ClientRx));

    for (uint32_t i = 0; i < 10; i++)
    {
        Simulator::Schedule(Seconds(1 + i), &ClientSend);
    }
    Simulator::Schedule(Seconds(5.5), &ChangeLocator);
    Simulator::Stop(Seconds(15));
    Simulator::Run();
    Simulator::Destroy();

    std::cout << "sent=" << g_sent << " serverReceived=" << g_serverRx
              << " clientReceivedEchoes=" << g_clientRx << std::endl;
    return (g_sent == g_serverRx && g_sent == g_clientRx) ? 0 : 1;
}
