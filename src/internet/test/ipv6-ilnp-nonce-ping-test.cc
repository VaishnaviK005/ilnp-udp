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
 * This test verifies the ILNP Nonce Destination Option 
 * using an end-to-end Ping test
 *
 * Topology:
 *
 *     Node 0 ---------------- Node 1
 *                 ILNP
 *
 * Node 0 sends Ping requests to Node 1.
 *
 * The test observes transmitted IPv6 packets and verifies that:
 *
 *   1. The ILNP packets contain a Destination Options extension header.
 *   2. The Destination Options header contains option type of 0x8B.
 *   3. The Nonce option length is 4 bytes or 12 bytes, depending on the configured Nonce size.
 *   4. The Nonce is not all zero.
 *   5. The nonce remains stable within a session and is consistent
 *      in both communication directions.
 *   6. The ILNP Ping exchanges complete successfully.
 *   7. A subsequent Locator change preserves the expected ILNP behavior.
 *   8. Ordinary IPv6 traffic does not contain the ILNP Nonce option.
 */

#include "ns3/address.h"
#include "ns3/application-container.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv6-address-helper.h"
#include "ns3/ipv6-extension-header.h"
#include "ns3/ipv6-header.h"
#include "ns3/ipv6-option-nonce.h"
#include "ns3/ipv6.h"
#include "ns3/node-container.h"
#include "ns3/packet.h"
#include "ns3/ping-helper.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/test.h"
#include "ns3/uinteger.h"
#include "ns3/ipv6-l3-protocol.h"

#include <array>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <iostream>

namespace ns3
{

     /**
     * \brief Test the IPv6 ILNP Nonce Destination Option using Ping.
     *
     * This test case verifies the presence and format of the ILNP Nonce
     * Destination Option in transmitted IPv6 packets. It also checks
     * nonce stability, bidirectional nonce consistency, Locator changes,
     * and the behavior of ordinary IPv6 traffic.
     */
    class Ipv6IlpNoncePingTestCase : public TestCase
    {
    public:
        /**
         * \brief Construct the IPv6 ILNP Nonce Ping test case.
         */
        Ipv6IlpNoncePingTestCase();

    private:
        /**
         * \brief Execute the test case.
         *
         * Creates the test topology, configures IPv6 and ILNP flows,
         * runs the Ping applications, and verifies the observed packets.
         */
        void DoRun() override;

        /**
         * \brief Inspect a transmitted IPv6 packet.
         *
         * Examines the IPv6 header and Destination Options extension
         * header to identify the ILNP Nonce option and validate its
         * length and value. Tracks nonce consistency for the forward
         * and reverse directions and distinguishes ILNP traffic from
         * ordinary IPv6 traffic.
         *
         * \param packet The transmitted packet.
         * \param ipv6 The IPv6 object associated with the transmission.
         * \param interface The index of the outgoing IPv6 interface.
         */
        void Ipv6TxTrace(Ptr<const Packet> packet,
                         Ptr<Ipv6> ipv6,
                         uint32_t interface);

        /**
         * \brief Record a reply from the original ILNP Ping flow.
         *
         * \param sequenceNumber The Ping sequence number.
         * \param rtt The measured round-trip time.
         */
        void PingRtt(uint16_t sequenceNumber,
             Time rtt);
        
        /**
         * \brief Record a reply from the ILNP Ping flow using the new Locator.
         *
         * \param sequenceNumber The Ping sequence number.
         * \param rtt The measured round-trip time.
         */
        void NewLocatorPingRtt(uint16_t sequenceNumber, Time rtt);
        
        /**
         * \brief Enable the ILNP flows associated with the new Locator pair.
         *
         * Registers the forward and reverse flows for the new Locator
         * addresses before the second Ping exchange.
         */
        void EnableNewLocatorFlows();

        /**
         * \brief Record a reply from the ordinary IPv6 Ping flow.
         *
         * \param sequenceNumber The Ping sequence number.
         * \param rtt The measured round-trip time.
         */
        void OrdinaryPingRtt(uint16_t sequenceNumber, Time rtt);

         /// Number of IPv6 packets observed by the transmit trace.
        uint32_t m_txPackets;           
        
        /// Number of forward-direction packets containing the Nonce option.
        uint32_t m_noncePackets;
        
        /// Number of packets with an invalid Nonce option or length.
        uint32_t m_invalidNoncePackets;
        
        /// Number of packets containing an all-zero nonce value.
        uint32_t m_zeroNoncePackets;
        
        /// Number of replies received by the original ILNP Ping flow.
        uint32_t m_pingReplies;
        
        /// Number of packets observed in the forward ILNP flow.
        uint32_t m_flowPackets;
        
        /// Number of forward-flow packets missing the Nonce option.
        uint32_t m_missingNoncePackets;

        // Reverse-direction (Node 1 -> Node 0) counters.

        /// Number of packets observed in the reverse ILNP flow.
        uint32_t m_reverseFlowPackets;

        /// Number of reverse-flow packets containing the Nonce option.
        uint32_t m_reverseNoncePackets;

        /// Number of reverse-flow packets missing the Nonce option.
        uint32_t m_reverseMissingNoncePackets;

        /*
         * Store the first observed nonce in the forward and reverse directions.
         * Subsequent packets are checked for nonce stability, and the
         * forward and reverse values are compared for consistency.
         */

        /// First nonce value observed in the forward direction.
        std::vector<uint8_t> m_sessionNonce;

        /// Whether a forward-direction nonce has been recorded.
        bool m_haveSessionNonce;

        /// Number of forward-flow packets with a different nonce value.
        uint32_t m_differentNoncePackets;

        /// First nonce value observed in the reverse direction.
        std::vector<uint8_t> m_reverseSessionNonce;
        
        /// Whether a reverse-direction nonce has been recorded.
        bool m_haveReverseSessionNonce;
        
        /// Number of reverse-flow packets with a different nonce value.
        uint32_t m_differentReverseNoncePackets;
        
        /// Number of observed mismatches between forward and reverse nonces.
        uint32_t m_bidirectionalNonceMismatches;

        /// Expected nonce length in bytes: 4 for 32 bits or 12 for 96 bits.
        uint32_t m_expectedNonceLength;

        // Addresses used by the original ILNP Ping flow.
        
        /// Source IPv6 address of the original ILNP Ping flow.
        Ipv6Address m_pingSource;
        
        /// Destination IPv6 address of the original ILNP Ping flow.
        Ipv6Address m_pingDestination;

        // Addresses used by the ILNP Ping flow after the Locator change.
        
        /// Source IPv6 address of the new Locator pair.
        Ipv6Address m_newPingSource;

        /// Destination IPv6 address of the new Locator pair.
        Ipv6Address m_newPingDestination;

        // IPv6 L3 protocols used to register new Locator flows.
        
        /// IPv6 layer-three protocol on Node 0.
        Ptr<Ipv6L3Protocol> m_senderIpv6;

        /// IPv6 layer-three protocol on Node 1.
        Ptr<Ipv6L3Protocol> m_receiverIpv6;

        // Counters for the ILNP Ping exchange using the new Locator pair.

        /// Number of replies received after the Locator change.
        uint32_t m_newLocatorPingReplies;
        
        /// Number of forward packets using the new Locator pair.
        uint32_t m_newLocatorForwardPackets;
        
        /// Number of reverse packets using the new Locator pair.
        uint32_t m_newLocatorReversePackets;

        // Addresses used by the ordinary IPv6 Ping flow.

        /// Source IPv6 address of the ordinary IPv6 Ping flow.
        Ipv6Address m_ipv6Source;

        /// Destination IPv6 address of the ordinary IPv6 Ping flow.
        Ipv6Address m_ipv6Destination;

        // Counters for the ordinary IPv6 Ping flow.
        
        /// Number of ordinary IPv6 packets observed.
        uint32_t m_ipv6FlowPackets;

        /// Number of ordinary IPv6 packets containing the Nonce option.
        uint32_t m_ipv6PacketsWithNonce;
        
        /// Number of ordinary IPv6 packets containing Destination Options.
        uint32_t m_ipv6PacketsWithDestinationOptions;
        
        /// Number of replies received by the ordinary IPv6 Ping flow.
        uint32_t m_ipv6PingReplies;
    };


    /**
     * \brief Construct the IPv6 ILNP Nonce Ping test case.
     *
     * Initializes the packet counters, nonce-tracking state, Locator
     * addresses, protocol pointers, and reply counters.
     */
    Ipv6IlpNoncePingTestCase::Ipv6IlpNoncePingTestCase()
        : TestCase("IPv6 Ping contains ILNP Nonce Destination Option"),
        m_txPackets(0),
        m_noncePackets(0),
        m_invalidNoncePackets(0),
        m_zeroNoncePackets(0),
        m_pingReplies(0),
        m_flowPackets(0),
        m_missingNoncePackets(0),
        m_reverseFlowPackets(0),
        m_reverseNoncePackets(0),
        m_reverseMissingNoncePackets(0),
        m_sessionNonce(),
        m_haveSessionNonce(false),
        m_differentNoncePackets(0),
        m_reverseSessionNonce(),
        m_haveReverseSessionNonce(false),
        m_differentReverseNoncePackets(0),
        m_bidirectionalNonceMismatches(0),
        m_expectedNonceLength(4),
        m_newPingSource(),
        m_newPingDestination(),
        m_senderIpv6(nullptr),
        m_receiverIpv6(nullptr),
        m_newLocatorPingReplies(0),
        m_newLocatorForwardPackets(0),
        m_newLocatorReversePackets(0),
        m_ipv6FlowPackets(0),
        m_ipv6PacketsWithNonce(0),
        m_ipv6PacketsWithDestinationOptions(0),
        m_ipv6PingReplies(0)
    {
    }


    /**
     * \brief Inspect a transmitted IPv6 packet.
     *
     * Examines the packet's IPv6 header and extension headers, identifies
     * the relevant test flow, and checks the Nonce Destination Option
     * when present.
     *
     * \param packet The transmitted packet.
     * \param ipv6 The IPv6 object associated with the transmission.
     * \param interface The index of the outgoing IPv6 interface.
     */
    void
    Ipv6IlpNoncePingTestCase::Ipv6TxTrace(Ptr<const Packet> packet,
                                          Ptr<Ipv6> ipv6,
                                          uint32_t interface)
    {
        m_txPackets++;

        /*
         * Work on a copy because the trace packet must not be modified.
         */
        Ptr<Packet> p = packet->Copy();

        /*
         * ------------------------------------------------------------
         * Remove the base IPv6 header.
         * ------------------------------------------------------------
         */
        Ipv6Header ipv6Header;

        if (p->RemoveHeader(ipv6Header) == 0)
        {
            return;
        }

        std::cerr << "TRACE IPv6: "
          << ipv6Header.GetSource()
          << " -> "
          << ipv6Header.GetDestination()
          << " nextHeader="
          << static_cast<uint32_t>(ipv6Header.GetNextHeader())
          << " remainingBytes="
          << p->GetSize() << '\n';

        // Diagnostic: inspect the bytes immediately after the IPv6 base header.
        std::vector<uint8_t> raw(p->GetSize());
        p->CopyData(raw.data(), static_cast<uint32_t>(raw.size()));

        std::cerr << "ILNP BYTES: "
                << ipv6Header.GetSource() << " -> "
                << ipv6Header.GetDestination()
                << " nextHeader="
                << static_cast<uint32_t>(ipv6Header.GetNextHeader())
                << " size=" << raw.size()
                << " data=";

        for (size_t j = 0; j < std::min<size_t>(raw.size(), 32); ++j)
        {
            std::cerr << std::hex
                    << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned int>(raw[j]) << ' ';
        }

        std::cerr << std::dec << std::setfill(' ') << '\n';
        
        /*
         * Identify packets belonging to the original or new ILNP flow
         * in either direction.
         */
        const bool isForward =
            (ipv6Header.GetSource() == m_pingSource &&
            ipv6Header.GetDestination() == m_pingDestination) ||
            (ipv6Header.GetSource() == m_newPingSource &&
            ipv6Header.GetDestination() == m_newPingDestination);

        const bool isReverse =
            (ipv6Header.GetSource() == m_pingDestination &&
            ipv6Header.GetDestination() == m_pingSource) ||
            (ipv6Header.GetSource() == m_newPingDestination &&
            ipv6Header.GetDestination() == m_newPingSource);

        if (ipv6Header.GetSource() == m_newPingSource &&
            ipv6Header.GetDestination() == m_newPingDestination)
        {
            m_newLocatorForwardPackets++;
        }

        if (ipv6Header.GetSource() == m_newPingDestination &&
            ipv6Header.GetDestination() == m_newPingSource)
        {
            m_newLocatorReversePackets++;
        }

        /*
         * Identify ordinary IPv6 traffic separately from ILNP traffic.
         */
        const bool isOrdinaryForward =
            ipv6Header.GetSource() == m_ipv6Source &&
            ipv6Header.GetDestination() == m_ipv6Destination;

        const bool isOrdinaryReverse =
            ipv6Header.GetSource() == m_ipv6Destination &&
            ipv6Header.GetDestination() == m_ipv6Source;

        // Ignore traffic outside the two test flows.
        if (!isForward && !isReverse &&
            !isOrdinaryForward && !isOrdinaryReverse)
        {
            return;
        }

        // Ordinary IPv6 must not carry the ILNP Nonce option.
        if (isOrdinaryForward || isOrdinaryReverse)
        {
            m_ipv6FlowPackets++;

            if (ipv6Header.GetNextHeader() ==
                Ipv6Header::IPV6_EXT_DESTINATION)
            {
                m_ipv6PacketsWithDestinationOptions++;

                Ipv6ExtensionDestinationHeader destinationHeader;
                if (p->RemoveHeader(destinationHeader) == 0)
                {
                    return;
                }

                uint32_t headerSize = destinationHeader.GetSerializedSize();
                Buffer buffer;
                buffer.AddAtEnd(headerSize);
                Buffer::Iterator i = buffer.Begin();
                destinationHeader.Serialize(i);
                i = buffer.Begin();

                // Skip the Destination Options next-header and extension-length fields.
                i.ReadU8();
                i.ReadU8();

                uint32_t optionBytes = headerSize - 2;
                uint32_t consumed = 0;

                while (consumed < optionBytes)
                {
                    uint8_t optionType = i.ReadU8();
                    consumed++;

                    // Pad1 is a single-byte option without length or data fields.
                    if (optionType == 0x00)
                    {
                        continue;
                    }

                    if (consumed >= optionBytes)
                    {
                        break;
                    }

                    uint8_t optionLength = i.ReadU8();
                    consumed++;

                    if (optionLength > optionBytes - consumed)
                    {
                        break;
                    }

                    if (optionType ==
                        Ipv6OptionNonceHeader::NONCE_OPTION_TYPE)
                    {
                        m_ipv6PacketsWithNonce++;
                    }

                    for (uint32_t j = 0; j < optionLength; ++j)
                    {
                        i.ReadU8();
                    }
                    consumed += optionLength;
                }
            }

            return;
        }

        if (isForward)
        {
            m_flowPackets++;
        }
        else
        {
            m_reverseFlowPackets++;
        }

        /*
         * Every packet in either direction of this ILNP Ping flow is
         * expected to carry the Nonce Destination Option.
         */
        if (ipv6Header.GetNextHeader() !=
            Ipv6Header::IPV6_EXT_DESTINATION)
        {
            if (isForward)
            {
                m_missingNoncePackets++;
            }
            else
            {
                m_reverseMissingNoncePackets++;
            }
            return;
        }


/* works*/
// if (ipv6Header.GetSource() !=
//         Ipv6Address("2001:1::200:ff:fe00:1") ||
//     ipv6Header.GetDestination() !=
//         Ipv6Address("2001:1::200:ff:fe00:2"))
// {
//     return;
// }

        /*
        * The packet must contain a Destination Options extension header.
        */
        // if (ipv6Header.GetNextHeader() != Ipv6Header::IPV6_EXT_DESTINATION)
        // {
        //     return;
        // }

        /*
         * ------------------------------------------------------------
         * Remove the Destination Options extension header.
         * ------------------------------------------------------------
         */
        // Ipv6ExtensionDestinationHeader destinationHeader;

        // if (p->RemoveHeader(destinationHeader) == 0)
        // {
        //     return;
        // }

        /*
         * ------------------------------------------------------------
         * Serialize the Destination Options header again.
         *
         * The serialized extension header contains the Next Header
         * and Hdr Ext Len fields, followed by the option data.
         * 
         * A normal option consists of an Option Type, an Option Data
         * Len field, and the option data. Pad1 is a single-byte option.
         * ------------------------------------------------------------
         */
        // uint32_t headerSize = destinationHeader.GetSerializedSize();

        // Buffer buffer;
        // buffer.AddAtEnd(headerSize);

        // Buffer::Iterator i = buffer.Begin();

        // destinationHeader.Serialize(i);

        // i = buffer.Begin();

        // Inspect the actual transmitted Destination Options bytes.
        // Inspect the packet bytes after removing the IPv6 base header.
        if (p->GetSize() < 2)
        {
            std::cerr << "ILNP DEBUG: packet too short: "
                    << p->GetSize() << " bytes\n";
            m_invalidNoncePackets++;
            return;
        }

        //
        // Inspect the actual bytes after removing the IPv6 base header.
        // std::vector<uint8_t> raw(p->GetSize());
        // p->CopyData(raw.data(), static_cast<uint32_t>(raw.size()));

        std::cerr << "ILNP DEBUG: "
                << ipv6Header.GetSource() << " -> "
                << ipv6Header.GetDestination()
                << " payloadSize=" << raw.size()
                << " nextHeader="
                << static_cast<uint32_t>(ipv6Header.GetNextHeader())
                << "\nILNP DEBUG bytes:";

        for (uint32_t i = 0; i < std::min<uint32_t>(raw.size(), 80); ++i)
        {
            std::cerr << " " << std::hex << std::setw(2)
                    << std::setfill('0')
                    << static_cast<unsigned int>(raw[i]);
        }
        std::cerr << std::dec << std::setfill(' ') << '\n';

        // if (raw.size() < 8)
        // {
        //     m_invalidNoncePackets++;
        //     return;
        // }

         /*
         * The Destination Options Hdr Ext Len field specifies the
         * number of 8-byte units in the extension header, excluding
         * the first 8 bytes.
         */
        const uint32_t headerSize =
            (static_cast<uint32_t>(raw[1]) + 1) * 8;

        if (headerSize < 8 || headerSize > raw.size())
        {
            std::cerr << "ILNP DEBUG: invalid Destination Options header size="
                    << headerSize << '\n';
            m_invalidNoncePackets++;
            return;
        }

        // // Log the extension header's Next Header and Hdr Ext Len fields.
        std::cerr << "ILNP DEBUG: destNextHeader="
                << static_cast<unsigned int>(raw[0])
                << " extLen=" << static_cast<unsigned int>(raw[1])
                << " headerSize=" << headerSize << '\n';

        bool nonceFoundInPacket = false;
        uint32_t offset = 2;

        /*
         * Parse the options within the Destination Options header.
         * Validate each option's length before accessing its data.
         */
        while (offset < headerSize)
        {
            const uint8_t optionType = raw[offset++];

            // Pad1 is a single-byte option.
            if (optionType == 0x00)
            {
                continue;
            }

            // Every option other than Pad1 requires a length byte.
            if (offset >= headerSize)
            {
                m_invalidNoncePackets++;
                break;
            }

            const uint8_t optionLength = raw[offset++];

            // Ensure the option data fits within the extension header.
            if (optionLength > headerSize - offset)
            {
                m_invalidNoncePackets++;
                break;
            }

            if (optionType == Ipv6OptionNonceHeader::NONCE_OPTION_TYPE)
            {
                nonceFoundInPacket = true;

                if (isForward)
                {
                    m_noncePackets++;
                }
                else
                {
                    m_reverseNoncePackets++;
                }

                // Verify that the nonce length matches the configured size.
                if (optionLength != m_expectedNonceLength)
                {
                    m_invalidNoncePackets++;
                    offset += optionLength;
                    continue;
                }

                // Extract the nonce bytes for validation and comparison.
                std::vector<uint8_t> nonceBytes(
                    raw.begin() + offset,
                    raw.begin() + offset + optionLength);

                // Reject an all-zero nonce value.
                const bool allZero = std::all_of(
                    nonceBytes.begin(),
                    nonceBytes.end(),
                    [](uint8_t byte) { return byte == 0; });

                if (allZero)
                {
                    m_zeroNoncePackets++;
                }

                /*
                 * Record the first nonce observed in each direction.
                 * Subsequent values are compared with the recorded value
                 * to verify nonce stability within each direction and
                 * consistency between the forward and reverse directions.
                 */
                if (isForward)
                {
                    if (!m_haveSessionNonce)
                    {
                        m_sessionNonce = nonceBytes;
                        m_haveSessionNonce = true;
                    }
                    else if (nonceBytes != m_sessionNonce)
                    {
                        m_differentNoncePackets++;
                    }

                    if (m_haveReverseSessionNonce &&
                        nonceBytes != m_reverseSessionNonce)
                    {
                        m_bidirectionalNonceMismatches++;
                    }
                }
                else
                {
                    if (!m_haveReverseSessionNonce)
                    {
                        m_reverseSessionNonce = nonceBytes;
                        m_haveReverseSessionNonce = true;
                    }
                    else if (nonceBytes != m_reverseSessionNonce)
                    {
                        m_differentReverseNoncePackets++;
                    }

                    if (m_haveSessionNonce &&
                        nonceBytes != m_sessionNonce)
                    {
                        m_bidirectionalNonceMismatches++;
                    }
                }

                // Print the observed nonce value for diagnostic purposes.
                std::clog << "ILNP NONCE "
                        << ipv6Header.GetSource() << " -> "
                        << ipv6Header.GetDestination()
                        << " value=0x";

                for (uint8_t byte : nonceBytes)
                {
                    std::clog << std::hex << std::setw(2)
                            << std::setfill('0')
                            << static_cast<unsigned int>(byte);
                }
                std::clog << std::dec << std::setfill(' ') << '\n';
            }

            // Advance to the next option.
            offset += optionLength;
        }

        // Record packets in which no Nonce option was found.
        if (!nonceFoundInPacket)
        {
            std::cerr << "ILNP DEBUG: no Nonce option found in this packet\n";

            if (isForward)
            {
                m_missingNoncePackets++;
            }
            else
            {
                m_reverseMissingNoncePackets++;
            }
        }

    }

    /**
     * \brief Record a reply from the original ILNP Ping flow.
     *
     * \param sequenceNumber The Ping sequence number.
     * \param rtt The measured round-trip time.
     */
    void
    Ipv6IlpNoncePingTestCase::PingRtt(uint16_t sequenceNumber,
                                    Time rtt)
    {
        m_pingReplies++;
    }


    /**
     * \brief Record a reply from the ILNP Ping flow using the new Locator.
     *
     * \param sequenceNumber The Ping sequence number.
     * \param rtt The measured round-trip time.
     */
    void
    Ipv6IlpNoncePingTestCase::NewLocatorPingRtt(
        uint16_t sequenceNumber,
        Time rtt)
    {
        m_newLocatorPingReplies++;
    }

    /**
     * \brief Enable the ILNP flows associated with the new Locator pair.
     *
     * Registers the forward flow on Node 0 and the reverse flow on
     * Node 1 for ICMPv6 traffic using the new Locator addresses.
     */
    void
    Ipv6IlpNoncePingTestCase::EnableNewLocatorFlows()
    {
        // Register the new forward path on Node 0.
        m_senderIpv6->EnableIlnpFlow(
            m_newPingSource,
            m_newPingDestination,
            58);

        // Register the new reverse path on Node 1.
        m_receiverIpv6->EnableIlnpFlow(
            m_newPingDestination,
            m_newPingSource,
            58);

        std::clog << "ILNP Locator change enabled: "
                << m_newPingSource << " -> "
                << m_newPingDestination << '\n';
    }

    /**
     * \brief Record a reply from the ordinary IPv6 Ping flow.
     *
     * \param sequenceNumber The Ping sequence number.
     * \param rtt The measured round-trip time.
     */
    void
    Ipv6IlpNoncePingTestCase::OrdinaryPingRtt(
        uint16_t sequenceNumber,
        Time rtt)
    {
        m_ipv6PingReplies++;
    }


    /**
     * \brief Execute the IPv6 ILNP Nonce Ping test.
     *
     * Creates two nodes connected by a point-to-point link, configures
     * the ILNP and ordinary IPv6 flows, starts the Ping applications,
     * and validates the transmitted packets and received replies.
     */
    void
    Ipv6IlpNoncePingTestCase::DoRun()
    {
        /*
         * ------------------------------------------------------------
         * 1. Create two nodes
         * ------------------------------------------------------------
         */
        NodeContainer nodes;
        nodes.Create(2);

        /*
         * ------------------------------------------------------------
         * 2. Install Internet stack on both nodes
         * ------------------------------------------------------------
         */
        InternetStackHelper internet;
        internet.Install(nodes);

        /*
        * Configure the sender's ILNP nonce size before transmitting packets. The selected size 
        * must match the expected option data length used by the packet validation code.
        * Choose NONCE_32 or NONCE_96.
        */
        Ptr<Ipv6L3Protocol> ipv6L3 =
            nodes.Get(0)->GetObject<Ipv6L3Protocol>();
        NS_TEST_ASSERT_MSG_NE(
            ipv6L3,
            nullptr,
            "Could not obtain Ipv6L3Protocol on sender");

        /* For 32-bit Nonce */
            // ipv6L3->SetIlnpNonceType(IlnpNonceType::NONCE_32);
        // m_expectedNonceLength = 4;

        /* For 96-bit Nonce */
        ipv6L3->SetIlnpNonceType(IlnpNonceType::NONCE_96);
        m_expectedNonceLength = 12;

        /*
         * ------------------------------------------------------------
         * 3. Create IPv6 point-to-point link
         * ------------------------------------------------------------
         */
        PointToPointHelper p2p;

        p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
        p2p.SetChannelAttribute("Delay", StringValue("2ms"));

        NetDeviceContainer devices = p2p.Install(nodes);

        /*
         * ------------------------------------------------------------
         * 4. Assign IPv6 addresses
         * 
         * The nodes receive addresses from multiple prefixes to
         * distinguish the ILNP flow, ordinary IPv6 flow, and the
         * ILNP flow using the new Locator pair.
         * ------------------------------------------------------------
         */
        Ipv6AddressHelper address;

        address.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));

        Ipv6InterfaceContainer interfaces = address.Assign(devices);

        // Assign a second global IPv6 address pair for ordinary IPv6 traffic.
        Ipv6AddressHelper ordinaryAddress;
        ordinaryAddress.SetBase(
            Ipv6Address("2001:2::"),
            Ipv6Prefix(64));

        Ipv6InterfaceContainer ordinaryInterfaces =
            ordinaryAddress.Assign(devices);
        
        // Assign a third global address pair for the new ILNP Locator : same endpoint Identifiers,but a different Locator prefix 
        Ipv6AddressHelper newLocatorAddress;
        newLocatorAddress.SetBase(
            Ipv6Address("2001:3::"),
            Ipv6Prefix(64));

        Ipv6InterfaceContainer newLocatorInterfaces =
            newLocatorAddress.Assign(devices);

        /*
         * No explicit SetUp() call is required here for this ns-3
         * configuration. Ipv6AddressHelper::Assign() configures
         * the assigned addresses on the interfaces.
         */

        /*
         * Store the assigned IPv6 addresses for each test flow.
         * Interface index 0 corresponds to Node 0, and interface
         * index 1 corresponds to Node 1.
        */
        // First global address on each interface: ILNP flow.
        m_pingSource = interfaces.GetAddress(0, 1);
        m_pingDestination = interfaces.GetAddress(1, 1);

        /*
         * Second global address on each interface: ordinary IPv6 flow.
         * Address index 0 is normally link-local, index 1 is the first
         * global address, and index 2 is the second global address.
         */
        m_ipv6Source = ordinaryInterfaces.GetAddress(0, 2);
        m_ipv6Destination = ordinaryInterfaces.GetAddress(1, 2);

        /*
         * New Locator pair. Address index 3 selects the third global
         * address after the link-local address and the first two
         * global addresses.
         */
        m_newPingSource = newLocatorInterfaces.GetAddress(0, 3);
        m_newPingDestination = newLocatorInterfaces.GetAddress(1, 3);

        std::clog << "New ILNP Locator flow: "
                << m_newPingSource << " -> "
                << m_newPingDestination << '\n';

        // Print the configured addresses to verify the two flows are distinct and aid test diagnostics.
        std::clog << "ILNP flow: "
                << m_pingSource << " -> " << m_pingDestination << '\n';

        std::clog << "Ordinary IPv6 flow: "
                << m_ipv6Source << " -> " << m_ipv6Destination << '\n'; 

        /*
         * Obtain the IPv6 layer-three protocol objects used to register
         * the ILNP flows on the sender and receiver.
         */
        m_senderIpv6 =
            nodes.Get(0)->GetObject<Ipv6L3Protocol>();

        m_receiverIpv6 =
            nodes.Get(1)->GetObject<Ipv6L3Protocol>();

        NS_TEST_ASSERT_MSG_NE(
            m_senderIpv6,
            nullptr,
            "Could not obtain sender Ipv6L3Protocol");

        NS_TEST_ASSERT_MSG_NE(
            m_receiverIpv6,
            nullptr,
            "Could not obtain receiver Ipv6L3Protocol");

        /*
         * Register the original forward ILNP flow on the sender.
         * The protocol number 58 identifies ICMPv6.
         */
        m_senderIpv6->EnableIlnpFlow(
            m_pingSource,
            m_pingDestination,
            58);

        /*
         * ------------------------------------------------------------
         * 5. Connect to IPv6 Tx trace
         * ------------------------------------------------------------
         */
        Ptr<Ipv6> ipv6 = nodes.Get(0)->GetObject<Ipv6>();

        bool connected =
        ipv6->TraceConnectWithoutContext(
            "Tx",
            MakeCallback(&Ipv6IlpNoncePingTestCase::Ipv6TxTrace, this));

        NS_TEST_ASSERT_MSG_EQ(connected,
                              true,
                              "Failed to connect to IPv6 Tx trace");
        
        Ptr<Ipv6> ipv6Node1 = nodes.Get(1)->GetObject<Ipv6>();

        bool connectedNode1 =
            ipv6Node1->TraceConnectWithoutContext(
                "Tx",
                MakeCallback(
                    &Ipv6IlpNoncePingTestCase::Ipv6TxTrace,
                    this));

        NS_TEST_ASSERT_MSG_EQ(
            connectedNode1,
            true,
            "Failed to connect to Node 1 IPv6 Tx trace");
        
        /*
         * ------------------------------------------------------------
         * 6. Create the Ping application
         * ------------------------------------------------------------
         */

        // Configure the original ILNP Ping flow. 
        // Ipv6Address destination = interfaces.GetAddress(1, 1);
        Ipv6Address destination = m_pingDestination;

        PingHelper ping(destination);

        const uint32_t expectedPingCount = 3;
        ping.SetAttribute("Count", UintegerValue(expectedPingCount));
        ping.SetAttribute("Interval", TimeValue(Seconds(1)));
        ping.SetAttribute("Size", UintegerValue(64));

        ApplicationContainer pingApps = ping.Install(nodes.Get(0));
        
        bool rttConnected =
            pingApps.Get(0)->TraceConnectWithoutContext(
                "Rtt",
                MakeCallback(&Ipv6IlpNoncePingTestCase::PingRtt, this));

        
        NS_TEST_ASSERT_MSG_EQ(
            rttConnected,
            true,
            "Failed to connect to Ping Rtt trace");

        // Create a separate Ping flow using ordinary IPv6 addresses.
        PingHelper ordinaryPing(m_ipv6Destination);

        const uint32_t expectedOrdinaryPingCount = 5;
        ordinaryPing.SetAttribute(
            "Count",
            UintegerValue(expectedOrdinaryPingCount));
        ordinaryPing.SetAttribute(
            "Interval",
            TimeValue(Seconds(1)));
        ordinaryPing.SetAttribute(
            "Size",
            UintegerValue(64));

        ApplicationContainer ordinaryPingApps =
            ordinaryPing.Install(nodes.Get(0));

        bool ordinaryRttConnected =
            ordinaryPingApps.Get(0)->TraceConnectWithoutContext(
                "Rtt",
                MakeCallback(
                    &Ipv6IlpNoncePingTestCase::OrdinaryPingRtt,
                    this));

        NS_TEST_ASSERT_MSG_EQ(
            ordinaryRttConnected,
            true,
            "Failed to connect to ordinary IPv6 Ping Rtt trace");

        // Create a second ILNP Ping flow using the new Locator pair.
        PingHelper newLocatorPing(m_newPingDestination);

        const uint32_t expectedNewLocatorPingCount = 2;

        newLocatorPing.SetAttribute(
            "Count",
            UintegerValue(expectedNewLocatorPingCount));

        newLocatorPing.SetAttribute(
            "Interval",
            TimeValue(MilliSeconds(500)));

        newLocatorPing.SetAttribute(
            "Size",
            UintegerValue(64));

        ApplicationContainer newLocatorPingApps =
            newLocatorPing.Install(nodes.Get(0));

        bool newLocatorRttConnected =
            newLocatorPingApps.Get(0)->TraceConnectWithoutContext(
                "Rtt",
                MakeCallback(
                    &Ipv6IlpNoncePingTestCase::NewLocatorPingRtt,
                    this));

        NS_TEST_ASSERT_MSG_EQ(
            newLocatorRttConnected,
            true,
            "Failed to connect to new-Locator Ping Rtt trace");
        
        /*
         * ------------------------------------------------------------
         * 7. Schedule the Ping applications.
         * ------------------------------------------------------------
         */

        // Phase 1: run ping test with the original ILNP Locator.
        pingApps.Start(Seconds(1.0));
        pingApps.Stop(Seconds(4.0));

        // Keep ordinary IPv6 traffic running across both phases.
        ordinaryPingApps.Start(Seconds(1.0));
        ordinaryPingApps.Stop(Seconds(6.5));

        /*
        * Phase 2: switch to the new ILNP Locator after the original
        * ping exchange has started and the original session has
        * had the time to establish its nonce state.
        */
        Simulator::Schedule(
            Seconds(3.5),
            &Ipv6IlpNoncePingTestCase::EnableNewLocatorFlows,
            this);

        newLocatorPingApps.Start(Seconds(4.0));
        newLocatorPingApps.Stop(Seconds(5.5));

        /*
         * ------------------------------------------------------------
         * 8. Run the simulation
         * ------------------------------------------------------------
         */
        Simulator::Stop(Seconds(7.0));

        Simulator::Run();

        /*
         * ------------------------------------------------------------
         * 9. Verify that IPv6 traffic exists.
         * ------------------------------------------------------------
         */
        NS_TEST_ASSERT_MSG_GT(m_txPackets,
                              0u,
                              "No IPv6 packets were transmitted");

        /*
         * ------------------------------------------------------------
         * 10. Verify at least one packet contains the ILNP Nonce.
         * ------------------------------------------------------------
         */
        NS_TEST_ASSERT_MSG_GT(m_noncePackets,
                              0u,
                              "No ILNP Nonce Destination Option was found");
        
        NS_TEST_ASSERT_MSG_EQ(m_haveSessionNonce,
                              true,
                              "No session Nonce was captured");
        
        /*
         * ------------------------------------------------------------
         * 11. Verify the nonce option format and length.
         *
         * The expected length is selected by the configured nonce type:
         * 4 bytes for a 32-bit nonce or 12 bytes for a 96-bit nonce.
         * ------------------------------------------------------------
         */
        NS_TEST_ASSERT_MSG_EQ(
            m_invalidNoncePackets,
            0u,
            "ILNP Nonce option has an invalid type/length/format");

        /*
         * ------------------------------------------------------------
         * 12. Verify that the Nonce is not all zero.
         * ------------------------------------------------------------
         */
        NS_TEST_ASSERT_MSG_EQ(
            m_zeroNoncePackets,
            0u,
            "ILNP Nonce contains an all-zero value");

        /*
         * ------------------------------------------------------------
         * 13. Verify that every packet in the session reuses the same Nonce.
         * ------------------------------------------------------------
         */
        NS_TEST_ASSERT_MSG_EQ(
            m_differentNoncePackets,
            0u,
            "The ILNP Nonce changed between packets in the same session");
        
        /*
        * Verify that the original Ping exchange completed successfully.
        */
        NS_TEST_ASSERT_MSG_GT(
            m_pingReplies,
            0u,
            "Ping failed: no Echo Reply was received by Node 0");
        
        NS_TEST_ASSERT_MSG_EQ(
            m_pingReplies,
            expectedPingCount,
            "Expected three Ping Echo Replies");

         /*
         * Verify that the Ping exchange using the new Locator completed.
         */
        NS_TEST_ASSERT_MSG_EQ(
            m_newLocatorPingReplies,
            2u,
            "Expected two Ping Echo Replies after Locator change");
        
        NS_TEST_ASSERT_MSG_GT(
            m_newLocatorForwardPackets,
            0u,
            "No forward packets used the new Locator pair");

        NS_TEST_ASSERT_MSG_GT(
            m_newLocatorReversePackets,
            0u,
            "No reverse packets used the new Locator pair");

        /*
         * Verify that all observed forward-flow packets contain
         * the Nonce Destination Option.
         */
        NS_TEST_ASSERT_MSG_GT(
            m_flowPackets,
            0u,
            "No packets were observed in the forward ping flow");

        NS_TEST_ASSERT_MSG_EQ(
            m_missingNoncePackets,
            0u,
            "A packet in the forward ping flow was missing "
            "the Nonce Destination Option");

        NS_TEST_ASSERT_MSG_EQ(
            m_noncePackets,
            m_flowPackets,
            "Not every forward ping packet contained a Nonce option");

        /*
         * Verify that all observed reverse-flow packets contain
         * the Nonce Destination Option and use a stable nonce.
         */
        NS_TEST_ASSERT_MSG_GT(
            m_reverseFlowPackets,
            0u,
            "No packets were observed in the reverse ping flow");

        NS_TEST_ASSERT_MSG_EQ(
            m_haveReverseSessionNonce,
            true,
            "No reverse-direction session Nonce was captured");

        NS_TEST_ASSERT_MSG_EQ(
            m_reverseMissingNoncePackets,
            0u,
            "A reverse-flow packet was missing the Nonce option");

        NS_TEST_ASSERT_MSG_EQ(
            m_reverseNoncePackets,
            m_reverseFlowPackets,
            "Not every reverse-flow packet contained exactly one Nonce option");

        NS_TEST_ASSERT_MSG_EQ(
            m_differentReverseNoncePackets,
            0u,
            "The reverse-direction Nonce changed between packets");

        /*
         * Verify that the nonce observed in the forward direction
         * matches the nonce observed in the reverse direction.
         */
        NS_TEST_ASSERT_MSG_EQ(
            m_bidirectionalNonceMismatches,
            0u,
            "Forward and reverse packets used different Nonces");

        /*
         * Verify that ordinary IPv6 traffic is observed and does not
         * contain the ILNP Nonce option.
         */
        NS_TEST_ASSERT_MSG_GT(
            m_ipv6FlowPackets,
            0u,
            "No ordinary IPv6 packets were observed");

        NS_TEST_ASSERT_MSG_EQ(
            m_ipv6PacketsWithNonce,
            0u,
            "Ordinary IPv6 traffic unexpectedly contained an ILNP Nonce option");

        NS_TEST_ASSERT_MSG_GT(
            m_ipv6PingReplies,
            0u,
            "Ordinary IPv6 Ping received no replies");

        NS_TEST_ASSERT_MSG_EQ(
            m_ipv6PingReplies,
            expectedOrdinaryPingCount,
            "Expected five ordinary IPv6 Ping replies");
        
        // Print flow counters to assist with test diagnostics.
        std::cout << "ILNP forward packets: " << m_flowPackets << '\n';
        std::cout << "ILNP reverse packets: " << m_reverseFlowPackets << '\n';
        std::cout << "Ordinary IPv6 packets: " << m_ipv6FlowPackets << '\n';
        std::cout << "Ordinary IPv6 packets with Nonce: "
                << m_ipv6PacketsWithNonce << '\n';

        Simulator::Destroy();
    }


    /*
     * ================================================================
     * Test Suite registration
     * ================================================================
     */

    /**
     * \brief Test suite for the IPv6 ILNP Nonce Ping test.
     */
    class Ipv6IlpNoncePingTestSuite : public TestSuite
    {
    public:
        /**
         * \brief Construct the IPv6 ILNP Nonce Ping test suite.
         */
        Ipv6IlpNoncePingTestSuite();
    };


    /**
     * \brief Register the IPv6 ILNP Nonce Ping test case.
     */
    Ipv6IlpNoncePingTestSuite::Ipv6IlpNoncePingTestSuite()
    : TestSuite("ipv6-ilnp-nonce-ping", Type::UNIT)
    {
        AddTestCase(new Ipv6IlpNoncePingTestCase(),
                    TestCase::Duration::QUICK);
    }


    /// Static instance that registers the test suite with the ns-3 test framework.
    static Ipv6IlpNoncePingTestSuite g_ipv6IlpNoncePingTestSuite;

} // namespace ns3
