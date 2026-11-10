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
#ifndef ILNP_LOCATOR_PROVIDER_H
#define ILNP_LOCATOR_PROVIDER_H

#include "ns3/callback.h"
#include "ns3/ipv6-address.h"
#include "ns3/object.h"

#include <stdint.h>

namespace ns3
{

/**
 * \ingroup internet
 *
 * \brief Abstract source of Locator information for ILNPv6 transport protocols.
 *
 * An ILNPv6 address is a 128-bit I-LV: the upper 64 bits are the Locator (L64)
 * and the lower 64 bits are the Identifier (NID). The transport layer only
 * needs three things from the Identifier-Locator Communication Cache (ILCC,
 * RFC 6741): the peer's current Locator, this node's current Locator on an
 * interface, and a notification when a Locator changes. This interface
 * exposes exactly that, so UDP never depends on a concrete ILCC.
 *
 * An implementation is aggregated to the Node and found with
 * Node::GetObject<IlnpLocatorProvider>().
 */
class IlnpLocatorProvider : public Object
{
  public:
    /**
     * \brief Callback fired when a Locator changes.
     *
     * Arguments: Identifier whose Locator changed, old Locator, new Locator.
     * For a local change the Identifier is that of the changed interface address.
     */
    typedef Callback<void, uint64_t, uint64_t, uint64_t> LocatorChangeCallback;

    /**
     * \brief Get the TypeId.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    ~IlnpLocatorProvider() override;

    /**
     * \brief Get the current Locator of a remote node.
     * \param identifier the remote 64-bit Identifier
     * \param [out] locator the peer's current 64-bit Locator prefix
     * \return true if the Identifier is known
     */
    virtual bool GetPeerLocator(uint64_t identifier, uint64_t& locator) const = 0;

    /**
     * \brief Get this node's current Locator on an interface.
     * \param interface the Ipv6 interface index
     * \param [out] locator this node's current 64-bit Locator prefix
     * \return true if a Locator is known for the interface
     */
    virtual bool GetLocalLocator(uint32_t interface, uint64_t& locator) const = 0;

    /**
     * \brief Register a callback fired when any Locator (local or peer) changes.
     * \param cb the callback
     */
    virtual void SetLocatorChangeCallback(LocatorChangeCallback cb) = 0;

    /**
     * \brief Extract the Locator (upper 64 bits) of an IPv6 address.
     * \param address the address
     * \return the Locator
     */
    static uint64_t GetLocator(const Ipv6Address& address);

    /**
     * \brief Extract the Identifier (lower 64 bits) of an IPv6 address.
     * \param address the address
     * \return the Identifier
     */
    static uint64_t GetIdentifier(const Ipv6Address& address);

    /**
     * \brief Build an I-LV address from a Locator and an Identifier.
     * \param locator the 64-bit Locator
     * \param identifier the 64-bit Identifier
     * \return the 128-bit address
     */
    static Ipv6Address MakeAddress(uint64_t locator, uint64_t identifier);
};

} // namespace ns3

#endif /* ILNP_LOCATOR_PROVIDER_H */
