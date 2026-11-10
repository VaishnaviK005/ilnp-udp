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
#include "ilnp-locator-provider.h"

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(IlnpLocatorProvider);

TypeId
IlnpLocatorProvider::GetTypeId()
{
    static TypeId tid = TypeId("ns3::IlnpLocatorProvider")
                            .SetParent<Object>()
                            .SetGroupName("Internet");
    return tid;
}

IlnpLocatorProvider::~IlnpLocatorProvider()
{
}

uint64_t
IlnpLocatorProvider::GetLocator(const Ipv6Address& address)
{
    uint8_t b[16];
    address.GetBytes(b);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
    {
        v = (v << 8) | b[i];
    }
    return v;
}

uint64_t
IlnpLocatorProvider::GetIdentifier(const Ipv6Address& address)
{
    uint8_t b[16];
    address.GetBytes(b);
    uint64_t v = 0;
    for (int i = 8; i < 16; i++)
    {
        v = (v << 8) | b[i];
    }
    return v;
}

Ipv6Address
IlnpLocatorProvider::MakeAddress(uint64_t locator, uint64_t identifier)
{
    uint8_t b[16];
    for (int i = 0; i < 8; i++)
    {
        b[i] = (locator >> (56 - 8 * i)) & 0xff;
        b[8 + i] = (identifier >> (56 - 8 * i)) & 0xff;
    }
    return Ipv6Address(b);
}

} // namespace ns3
