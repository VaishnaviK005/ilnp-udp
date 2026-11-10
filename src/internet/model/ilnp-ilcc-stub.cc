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
#include "ilnp-ilcc-stub.h"

#include "ns3/log.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("IlnpIlccStub");

NS_OBJECT_ENSURE_REGISTERED(IlnpIlccStub);

TypeId
IlnpIlccStub::GetTypeId()
{
    static TypeId tid = TypeId("ns3::IlnpIlccStub")
                            .SetParent<IlnpLocatorProvider>()
                            .SetGroupName("Internet")
                            .AddConstructor<IlnpIlccStub>();
    return tid;
}

IlnpIlccStub::IlnpIlccStub()
{
    NS_LOG_FUNCTION(this);
}

IlnpIlccStub::~IlnpIlccStub()
{
    NS_LOG_FUNCTION(this);
}

bool
IlnpIlccStub::GetPeerLocator(uint64_t identifier, uint64_t& locator) const
{
    auto it = m_peers.find(identifier);
    if (it == m_peers.end())
    {
        return false;
    }
    locator = it->second;
    return true;
}

bool
IlnpIlccStub::GetLocalLocator(uint32_t interface, uint64_t& locator) const
{
    auto it = m_local.find(interface);
    if (it == m_local.end())
    {
        return false;
    }
    locator = it->second;
    return true;
}

void
IlnpIlccStub::SetLocatorChangeCallback(LocatorChangeCallback cb)
{
    m_changeCallback = cb;
}

void
IlnpIlccStub::SetPeerLocator(uint64_t identifier, uint64_t locator)
{
    NS_LOG_FUNCTION(this << identifier << locator);
    uint64_t old = 0;
    GetPeerLocator(identifier, old);
    m_peers[identifier] = locator;
    if (!m_changeCallback.IsNull())
    {
        m_changeCallback(identifier, old, locator);
    }
}

void
IlnpIlccStub::SetLocalLocator(uint32_t interface, uint64_t identifier, uint64_t locator)
{
    NS_LOG_FUNCTION(this << interface << identifier << locator);
    uint64_t old = 0;
    GetLocalLocator(interface, old);
    m_local[interface] = locator;
    if (!m_changeCallback.IsNull())
    {
        m_changeCallback(identifier, old, locator);
    }
}

} // namespace ns3
