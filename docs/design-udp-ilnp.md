# Design: UDP support for ILNPv6 in ns-3 (project #6)

## Scope
RFC 6741 section 4 and draft-bhatti-ilnp-tcp-udp-checksums for UDP over IPv6 only.
Out of scope: ILNPv4, TCP, QUIC, NAT, DNS (name resolution is assumed done).

## 1. How ILNP mode is selected
Each UDP socket has an ns-3 attribute `IlnpMode` (default `false` = plain IPv6).
`UdpSocketImpl::FinishBind` copies it to the IPv6 endpoint (`Ipv6EndPoint::SetIlnpMode`),
so the endpoint carries the per-session mode flag mentioned in RFC 6744. No packet tag
is added and nothing in L3 changes: nonce insertion and validation stay in
`Ipv6L3Protocol` (project #4, unchanged).
**Open point for Mohit sir:** whether the mode should be chosen per socket (current)
or by a node-wide switch.

## 2. How endpoints are matched
RFC 6741 section 4.1: a transport session is identified by (local port, remote port,
local Identifier, remote Identifier). `Ipv6EndPointDemux::Lookup` and `SimpleLookup`
(the latter also used for ICMP errors) now compare addresses with `AddressMatches()`:
- plain endpoint: full 128-bit equality, exactly as before;
- ILNP-mode endpoint: equality of the low 64 bits (Identifier) only.
Wildcard (`::`) and multicast addresses always use the full comparison. Specificity
ranking (exact / wildcard) is unchanged.

## 3. Send path: choosing Locators
`UdpSocketImpl::DoSendTo(Ipv6Address...)` in ILNP mode asks the node's
`IlnpLocatorProvider` (found with `Node::GetObject`):
- destination: Identifier of the application's destination -> provider's current peer
  Locator -> new destination I-LV (unknown Identifier, link-local or multicast: unchanged);
- source: if the endpoint is bound to a specific address, the node address with the same
  Identifier and the provider's current local Locator is used; if bound to `::`, normal
  route-based source selection applies.
UDP depends only on the abstract `IlnpLocatorProvider`, never on the stub.

## 4. Checksum
`UdpHeader::InitializeChecksum(Ipv6Address, Ipv6Address, uint8_t)` and
`CalculateHeaderChecksum` already write the full 128-bit source and destination into
the pseudo-header (verified in `udp-header.cc`). The draft (section 4.1) says: "the
algorithm and pseudo-header used in the checksum computation with TCP and UDP for ILNP
are now exactly the same as for IPv6". It replaces RFC 6741's zeroing of the Locator
bits, so **no algorithm change**; we only add tests. Checksums are computed only when
`Node::ChecksumEnabled` is true. The draft's incremental-checksum section is not implemented.
Draft typos noticed: the abstract still says "zero value L64" while section 4.1 says the
whole I-LV is used (the later sections win); some sections write "s_L64 and s_L64" where
"s_L64 and d_L64" is meant.

## 5. ICMPv6 errors
`UdpL4Protocol::ReceiveIcmp(Ipv6Address...)` calls `SimpleLookup(payloadSource, sport,
payloadDestination, dport)` using the addresses inside the quoted packet. With the change
in section 2 an ILNP-mode endpoint still matches after a Locator change.

## 6. Nonce
Every ILNP packet carries the Nonce Destination Option (draft-nonce NC1-NC3). That is done
in L3 by project #4 (session key = Identifiers only). UDP reuses it unchanged.

## 7. Files
New: `ilnp-locator-provider.{h,cc}`, `ilnp-ilcc-stub.{h,cc}` (temporary),
`test/udp-ilnp-test.cc`, example, this note.
Changed (additive only): `ipv6-end-point.{h,cc}` (mode flag),
`ipv6-end-point-demux.cc` (`AddressMatches`), `udp-socket-impl.{h,cc}` (attribute,
Locator resolution), `src/internet/CMakeLists.txt` (new files added to existing lists).

## 8. ILCC integration
`ilnp-ilcc-stub` is a TEMPORARY stand-in. The real ILCC (project #5) needs an adapter
deriving from `IlnpLocatorProvider`, aggregated to each `Node`, that provides:
1. `GetPeerLocator(uint64_t identifier, uint64_t& locator)`: current Locator for a remote
   Identifier (true if known), reflecting Locator Updates received via ICMPv6;
2. `GetLocalLocator(uint32_t interface, uint64_t& locator)`: this node's current Locator
   on an Ipv6 interface;
3. `SetLocatorChangeCallback(cb)`: invoke `cb(identifier, oldLocator, newLocator)` whenever
   a local or peer Locator changes.
Locator-change behaviour has been verified only against the stub, not the real ILCC.
