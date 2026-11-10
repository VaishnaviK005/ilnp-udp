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

#ifndef IPV6_OPTION_NONCE_H
#define IPV6_OPTION_NONCE_H

#include "ipv6-option-header.h"

#include <array>
#include <cstdint>
#include <vector>

namespace ns3
{

/**
 * \brief IPv6 Nonce Destination Option Header.
 *
 * This class implements the Nonce Destination Option for Identifier-Locator Network Protocol(ILNP) as specified by RFC 6744.
 * 
 * The option carries a nonce value used by ILNP to support the
 * identification of ILNP sessions and help distinguish ILNP packets
 * from packets belonging to ordinary IPv6 communication.
 * 
 * The Option Type is 0x8B
 * This implementation provides support for:
 *   - 32-bit nonce
 *   - 96-bit nonce
 *
 * The nonce is generated using OpenSSL RAND_bytes(), which provides
 * cryptographically secure random bytes.
 * The class provides methods to generate, set, retrieve, serialize,
 * deserialize, and print the nonce value.
 *
 * \see Ipv6OptionHeader
 * \see RFC 6744
 */
class Ipv6OptionNonceHeader : public Ipv6OptionHeader
{
  public:
    /**
     * \brief Nonce Destination Option Type defined by RFC 6744.
     */
    static constexpr uint8_t NONCE_OPTION_TYPE = 0x8B;

    /**
     * \brief 32-bit nonce length.
     */
    static constexpr uint8_t NONCE_LENGTH_32 = 4;

    /**
     * \brief 96-bit nonce length.
     */
    static constexpr uint8_t NONCE_LENGTH_96 = 12;

    /**
     * \brief Get the TypeId associated with this class.
     * 
     * \return The TypeId for this IPv6 Nonce Destination Option header.
     */
    static TypeId GetTypeId();

    /**
     * \brief Constructor : Construct an IPv6 Nonce Destination Option header.
     *
     * Initializes the option type and length.
     */
    Ipv6OptionNonceHeader();

    /**
     * \brief Destructor : Destroy an IPv6 Nonce Destination Option header.
     */
    ~Ipv6OptionNonceHeader() override;

    /**
     * \brief Generate a new cryptographically random 32-bit nonce.
     *
     * Generates the nonce using the OpenSSL RAND_bytes() function.
     *
     * \return true if nonce generation succeeds; false otherwise.
     */
    bool GenerateNonce32();

    /**
     * \brief Generate a new cryptographically random 96-bit nonce.
     *
     * Generates the nonce using the OpenSSL RAND_bytes() function.
     *
     * \return true if nonce generation succeeds; false otherwise.
     */
    bool GenerateNonce96();

    /**
     * \brief Set a 32-bit nonce explicitly.
     * 
     * The integer is stored as four bytes in network byte order.
     *
     * \param nonce nonce The 32-bit nonce value.
     */
    void SetNonce32(uint32_t nonce);

    /**
     * \brief Set a 96-bit nonce explicitly.
     * 
     * \param nonce nonce The 96-bit nonce value.
     */
    void SetNonce96(const std::array<uint8_t, 12>& nonce);

    /**
     * \brief Set the nonce from a byte vector.
     *
     * The vector must contain either 4 bytes or 12 bytes.
     *
     * \param nonce The nonce bytes.
     */
    void SetNonce(const std::vector<uint8_t>& nonce);

    /**
     * \brief Get the stored nonce value.
     *
     * \return The nonce as a byte vector.
     */
    std::vector<uint8_t> GetNonce() const;

    /**
     * \brief Get the stored nonce as a 32-bit integer.
     * 
     * The stored nonce must contain exactly 4 bytes.
     *
     * \return The 32-bit nonce.
     */
    uint32_t GetNonce32() const;

    /**
     * \brief Get the stored nonce as a 96-bit byte array.
     * 
     * The stored nonce must contain exactly 12 bytes.
     *
     * \return The 96-bit nonce.
     */
    std::array<uint8_t, 12> GetNonce96() const;

    /**
     * \brief Check whether the stored nonce has a supported length.
     * 
     * A valid nonce contains either 4 bytes or 12 bytes.
     *
     * \return true if the nonce length is valid; false otherwise.
     */
    bool IsValidNonceLength() const;

    /**
     * \brief Get the serialized size of the option.
     *
     * The size includes the option type, the option data length,
     * and the nonce value.
     * 
     * \return Size of option in bytes.
     */
    uint32_t GetSerializedSize() const override;

    /**
     * \brief Serialize the Nonce Destination Option.
     *
     * Writes the option type, option data length, and nonce value
     * to the specified buffer iterator.
     *
     * \param start The buffer iterator at which serialization begins.
     */
    void Serialize(Buffer::Iterator start) const override;

    /**
     * \brief Deserialize the Nonce Destination option.
     * 
     * Reads the option type, option data length, and nonce value
     * from the specified buffer iterator.
     *
     * \param start The buffer iterator at which deserialization begins.
     * \return Th number of bytes consumed.
     */
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * \brief Print the Nonce Destination Option.
     * 
     * Writes the option type, nonce length, and nonce value
     * to the specified output stream.
     * 
     * \param os The output stream to which the option is printed.
     */
    void Print(std::ostream& os) const override;

    /**
     * \brief Get the alignment requirement for the option.
     *
     * \return The alignment requirement as a factor and offset pair.
     */
    Alignment GetAlignment() const override;

  private:
    /**
     * \brief Store the nonce value.
     * 
     * Contains the nonce bytes used by this option.
     */
    std::vector<uint8_t> m_nonce;
};

} // namespace ns3

#endif /* IPV6_OPTION_NONCE_H */