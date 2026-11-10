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
#include "ipv6-option-nonce.h"

#include "ns3/abort.h"
#include "ns3/log.h"

#include <openssl/rand.h>

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("Ipv6OptionNonceHeader");

NS_OBJECT_ENSURE_REGISTERED(Ipv6OptionNonceHeader);

/**
 * @brief Get the TypeId for the IPv6 Nonce Destination Option header.
 *
 * @return The TypeId for this header.
 */
TypeId
Ipv6OptionNonceHeader::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::Ipv6OptionNonceHeader")
            .SetParent<Ipv6OptionHeader>()
            .SetGroupName("Internet")
            .AddConstructor<Ipv6OptionNonceHeader>();

    return tid;
}

/**
 * @brief Construct an IPv6 Nonce Destination Option header.
 *
 * Initializes the option type and sets the initial nonce length to zero.
 */
Ipv6OptionNonceHeader::Ipv6OptionNonceHeader()
{
    SetType(NONCE_OPTION_TYPE);
    SetLength(0);
}

/**
 * @brief Destroy the IPv6 Nonce Destination Option header.
 */
Ipv6OptionNonceHeader::~Ipv6OptionNonceHeader()
{
}

/**
 * @brief Generate a cryptographically secure 32-bit nonce.
 *
 * Generates a random nonce using the OpenSSL cryptographic random
 * number generator and updates the option length and stored nonce.
 *
 * @return true if the nonce was generated successfully; false otherwise.
 */
bool
Ipv6OptionNonceHeader::GenerateNonce32()
{
    std::array<uint8_t, NONCE_LENGTH_32> nonce{};
    /*
     * Generate a 32-bit nonce using OpenSSL's cryptographically secure
     * random number generator.
     * 
     * RFC 6744 requires the Nonce Value to be an unpredictable and cryptographically random value.
     *
     * RAND_bytes() obtains cryptographically secure random bytes from OpenSSL's CSPRNG.
     */
    if (RAND_bytes(nonce.data(), NONCE_LENGTH_32) != 1)
    {
        NS_LOG_ERROR("OpenSSL RAND_bytes() failed while generating a 32-bit ILNP nonce");
        return false;
    }

    // Store the generated nonce and update the option metadata.
    m_nonce.assign(nonce.begin(), nonce.end());

    SetType(NONCE_OPTION_TYPE);
    SetLength(NONCE_LENGTH_32);

    return true;
}

/**
 * @brief Generate a cryptographically secure 96-bit nonce.
 *
 * Generates a random nonce using the OpenSSL cryptographic random
 * number generator and updates the option length and stored nonce.
 *
 * @return true if the nonce was generated successfully; false otherwise.
 */
bool
Ipv6OptionNonceHeader::GenerateNonce96()
{
    std::array<uint8_t, NONCE_LENGTH_96> nonce{};

    /*
     * Generate 96 bits of cryptographically secure random data.
     */
    if (RAND_bytes(nonce.data(), NONCE_LENGTH_96) != 1)
    {
        NS_LOG_ERROR("OpenSSL RAND_bytes() failed while generating a 96-bit ILNP nonce");
        return false;
    }

    // Store the generated nonce and update the option metadata.
    m_nonce.assign(nonce.begin(), nonce.end());

    SetType(NONCE_OPTION_TYPE);
    SetLength(NONCE_LENGTH_96);

    return true;
}

/**
 * @brief Set the nonce value from a 32-bit integer.
 *
 * The integer is stored in network byte order.
 *
 * @param nonce The 32-bit nonce value.
 */
void
Ipv6OptionNonceHeader::SetNonce32(uint32_t nonce)
{
    m_nonce.resize(NONCE_LENGTH_32);

    /*
     * Store the integer in network byte order.
     */
    m_nonce[0] = static_cast<uint8_t>((nonce >> 24) & 0xff);
    m_nonce[1] = static_cast<uint8_t>((nonce >> 16) & 0xff);
    m_nonce[2] = static_cast<uint8_t>((nonce >> 8) & 0xff);
    m_nonce[3] = static_cast<uint8_t>(nonce & 0xff);

    SetType(NONCE_OPTION_TYPE);
    SetLength(NONCE_LENGTH_32);
}

/**
 * @brief Set the nonce value from a 96-bit byte array.
 *
 * @param nonce The 96-bit nonce value.
 */
void
Ipv6OptionNonceHeader::SetNonce96(const std::array<uint8_t, 12>& nonce)
{
    m_nonce.assign(nonce.begin(), nonce.end());

    SetType(NONCE_OPTION_TYPE);
    SetLength(NONCE_LENGTH_96);
}

/**
 * @brief Set the nonce value from a byte vector.
 *
 * The vector must contain either 4 bytes (32 bits) or 12 bytes
 * (96 bits). An invalid length triggers an assertion.
 *
 * @param nonce The nonce value to store.
 */
void
Ipv6OptionNonceHeader::SetNonce(const std::vector<uint8_t>& nonce)
{
    NS_ABORT_MSG_IF(nonce.size() != NONCE_LENGTH_32 &&
                        nonce.size() != NONCE_LENGTH_96,
                    "RFC 6744 Nonce Option requires a 32-bit or 96-bit nonce");

    m_nonce = nonce;

    SetType(NONCE_OPTION_TYPE);
    SetLength(static_cast<uint8_t>(m_nonce.size()));
}

/**
 * @brief Get the stored nonce value.
 *
 * @return A copy of the nonce value as a byte vector or a sequence of bytes.
 */
std::vector<uint8_t>
Ipv6OptionNonceHeader::GetNonce() const
{
    return m_nonce;
}

/**
 * @brief Get the stored nonce as a 32-bit integer.
 *
 * The nonce must contain exactly 4 bytes.
 *
 * @return The 32-bit nonce value in host byte order.
 */
uint32_t
Ipv6OptionNonceHeader::GetNonce32() const
{
    NS_ABORT_MSG_IF(m_nonce.size() != NONCE_LENGTH_32,
                    "GetNonce32() called when nonce is not 32 bits");

    // Reconstruct the integer from bytes stored in network byte order.
    return (static_cast<uint32_t>(m_nonce[0]) << 24) |
           (static_cast<uint32_t>(m_nonce[1]) << 16) |
           (static_cast<uint32_t>(m_nonce[2]) << 8) |
           static_cast<uint32_t>(m_nonce[3]);
}

/**
 * @brief Get the stored nonce as a 96-bit byte array.
 *
 * The nonce must contain exactly 12 bytes.
 *
 * @return The 96-bit nonce value.
 */
std::array<uint8_t, 12>
Ipv6OptionNonceHeader::GetNonce96() const
{
    NS_ABORT_MSG_IF(m_nonce.size() != NONCE_LENGTH_96,
                    "GetNonce96() called when nonce is not 96 bits");

    std::array<uint8_t, 12> nonce{};

    std::copy(m_nonce.begin(), m_nonce.end(), nonce.begin());

    return nonce;
}

/**
 * @brief Check whether the stored nonce has a supported length.
 *
 * @return true if the nonce contains 4 or 12 bytes; false otherwise.
 */
bool
Ipv6OptionNonceHeader::IsValidNonceLength() const
{
    return m_nonce.size() == NONCE_LENGTH_32 ||
           m_nonce.size() == NONCE_LENGTH_96;
}

/**
 * @brief Get the serialized size of the IPv6 Nonce Option.
 *
 * The serialized option consists of the Option Type field, the
 * Option Data Len field, and the Nonce Value.
 *
 * @return The serialized size in bytes.
 */
uint32_t
Ipv6OptionNonceHeader::GetSerializedSize() const
{
    /*
     * Option Type + Option Length + Nonce Value.
     */
    return 2 + m_nonce.size();
}

/**
 * @brief Serialize the IPv6 Nonce Option into a buffer.
 *
 * Writes the option type, option data length, and nonce value.
 * The nonce must have a supported length before serialization.
 *
 * @param start The buffer iterator at which serialization begins.
 */
void
Ipv6OptionNonceHeader::Serialize(Buffer::Iterator start) const
{
    NS_ABORT_MSG_IF(!IsValidNonceLength(),
                    "Cannot serialize an IPv6 Nonce Option with an invalid nonce length");

    // Write the option type and the number of bytes in the nonce value.
    start.WriteU8(NONCE_OPTION_TYPE);
    start.WriteU8(static_cast<uint8_t>(m_nonce.size()));

    // Write the nonce value byte by byte.
    for (const auto byte : m_nonce)
    {
        start.WriteU8(byte);
    }
}

/**
 * @brief Deserialize an IPv6 Nonce Option from a buffer.
 *
 * Reads the option type, option data length, and nonce value.
 * Only 32-bit and 96-bit nonce values are accepted.
 *
 * @param start The buffer iterator at which deserialization begins.
 * @return The number of bytes consumed.
 */
uint32_t
Ipv6OptionNonceHeader::Deserialize(Buffer::Iterator start)
{
    uint32_t bytesRead = 0;

    // Read and validate the option type.
    const uint8_t type = start.ReadU8();
    bytesRead++;

    NS_ABORT_MSG_IF(type != NONCE_OPTION_TYPE,
                    "Invalid IPv6 Nonce Option Type");

    // Read and validate the length of the nonce value.
    const uint8_t length = start.ReadU8();
    bytesRead++;

    NS_ABORT_MSG_IF(length != NONCE_LENGTH_32 &&
                        length != NONCE_LENGTH_96,
                    "Invalid IPv6 Nonce Option length; RFC 6744 requires "
                    "support for 32-bit and 96-bit nonce values");

     // Read the nonce value and update the option metadata.
    m_nonce.resize(length);

    for (uint32_t i = 0; i < length; ++i)
    {
        m_nonce[i] = start.ReadU8();
        bytesRead++;
    }

    SetType(NONCE_OPTION_TYPE);
    SetLength(length);

    return bytesRead;
}

/**
 * @brief Print the IPv6 Nonce Option header.
 *
 * Outputs the option type, nonce length, and nonce value in hexadecimal.
 *
 * @param os The output stream to which the header is printed.
 */
void
Ipv6OptionNonceHeader::Print(std::ostream& os) const
{
    os << "Type=0x" << std::hex << static_cast<uint32_t>(NONCE_OPTION_TYPE)
       << std::dec << ", Length=" << m_nonce.size() << ", Nonce=0x";

    // Print each nonce byte as two hexadecimal digits.
    for (const auto byte : m_nonce)
    {
        os << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<uint32_t>(byte);
    }

    // Restore decimal formatting for subsequent stream output.
    os << std::dec;
}

/**
 * @brief Get the alignment requirement for the IPv6 Nonce Option.
 *
 * The option does not require alignment beyond a single byte.
 *
 * @return The alignment requirement as a factor and offset pair.
 */
Ipv6OptionNonceHeader::Alignment
Ipv6OptionNonceHeader::GetAlignment() const
{
    /*
     * No special alignment requirement.
     */
    return {1, 0};
}

} // namespace ns3