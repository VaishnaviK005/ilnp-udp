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
// TEMPORARY STUB. Replace with an adapter to the project #5 ILCC when available.
#ifndef ILNP_ILCC_STUB_H
#define ILNP_ILCC_STUB_H

#include "ilnp-locator-provider.h"

#include <map>

namespace ns3
{

/**
 * \ingroup internet
 *
 * \brief TEMPORARY stand-in for the ILCC, implementing IlnpLocatorProvider.
 *
 * Holds a map from remote Identifier to Locator, and a map from interface
 * index to local Locator. Tests call SetPeerLocator() and SetLocalLocator()
 * to simulate a received or locally triggered Locator Update.
 */
class IlnpIlccStub : public IlnpLocatorProvider
{
  public:
    /**
     * \brief Get the TypeId.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    IlnpIlccStub();
    ~IlnpIlccStub() override;

    bool GetPeerLocator(uint64_t identifier, uint64_t& locator) const override;
    bool GetLocalLocator(uint32_t interface, uint64_t& locator) const override;
    void SetLocatorChangeCallback(LocatorChangeCallback cb) override;

    /**
     * \brief Set (or update) the Locator of a peer; fires the change callback.
     * \param identifier the peer Identifier
     * \param locator the new peer Locator
     */
    void SetPeerLocator(uint64_t identifier, uint64_t locator);

    /**
     * \brief Set (or update) this node's Locator on an interface; fires the callback.
     * \param interface the Ipv6 interface index
     * \param identifier the Identifier of the interface address
     * \param locator the new Locator
     */
    void SetLocalLocator(uint32_t interface, uint64_t identifier, uint64_t locator);

  private:
    std::map<uint64_t, uint64_t> m_peers;    //!< Identifier -> peer Locator
    std::map<uint32_t, uint64_t> m_local;    //!< interface -> local Locator
    LocatorChangeCallback m_changeCallback;  //!< locator change callback
};

} // namespace ns3

#endif /* ILNP_ILCC_STUB_H */
