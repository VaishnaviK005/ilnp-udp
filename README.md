# UDP support for ILNPv6 in ns-3 (project #6)

UDP over ILNPv6 (RFC 6741 section 4 and draft-bhatti-ilnp-tcp-udp-checksums) for ns-3.
This repository holds **only the files we add or change**, in ns-3 layout. It is not a copy of ns-3.

## What it does
- A UDP socket has an `IlnpMode` attribute (default `false` = plain IPv6, unchanged).
- In ILNP mode the IPv6 endpoint is matched on the 64-bit Identifier only, so a Locator change
  does not break the flow (`Ipv6EndPointDemux::Lookup` / `SimpleLookup`).
- The send path takes the peer Locator and own Locator from an abstract `IlnpLocatorProvider`.
  Until the project #5 ILCC is available, `IlnpIlccStub` (TEMPORARY) implements it.
- The UDP checksum already uses the full 128-bit I-LV in the pseudo-header, as the draft requires. No change, tests added.
- The nonce (project #4) is reused unchanged; an ILNP-mode socket enables the ILNP flow for UDP in L3.

Design note: `docs/design-udp-ilnp.md`. Baseline test results: `docs/baseline-results.txt`.

## Baseline
ns-3-dev commit `e94155b5d7eecfbe8ed558adc00c915275a71f17` (branch `ilnp-udp` was created from it).
The nonce baseline (project #4, Ananya) is included and was 3-way merged onto this commit.

## Apply onto a fresh ns-3-dev checkout
```bash
git clone https://gitlab.com/nsnam/ns-3-dev.git && cd ns-3-dev
git checkout e94155b5d7eecfbe8ed558adc00c915275a71f17
rsync -a --exclude .git --exclude README.md --exclude LICENSE.md /path/to/this/repo/ ./
```
`scratch/udp-ilnp-example` is ignored by ns-3's `.gitignore`; it is still copied by rsync.
OpenSSL development files are required (the nonce code uses `RAND_bytes`): `sudo apt install libssl-dev`.

## Build, test, run
```bash
./ns3 configure --enable-tests --enable-examples
./ns3 build -j4
./test.py -s udp-ilnp                   # new tests
./test.py -s udp ; ./test.py -s ipv6-protocol   # existing suites
./ns3 run udp-ilnp-example 2>&1 | grep -v '^ILNP'   # example (the nonce code prints "ILNP ..." debug lines)
```

## Files
New:
- `src/internet/model/ilnp-locator-provider.{h,cc}` - abstract Locator source used by UDP
- `src/internet/model/ilnp-ilcc-stub.{h,cc}` - TEMPORARY stub, replace with an adapter to the project #5 ILCC
- `src/internet/test/udp-ilnp-test.cc` - suite `udp-ilnp` (demux, checksum, interop, Locator change)
- `scratch/udp-ilnp-example/{CMakeLists.txt,udp-ilnp-example.cc}` - echo example
- `docs/design-udp-ilnp.md`, `docs/baseline-results.txt`

Changed (additive only):
- `src/internet/model/ipv6-end-point.{h,cc}` - ILNP mode flag
- `src/internet/model/ipv6-end-point-demux.cc` - `AddressMatches()`, Identifier comparison
- `src/internet/model/udp-socket-impl.{h,cc}` - `IlnpMode` attribute, Locator resolution, flow enabling
- `src/internet/model/ipv6-option.{h,cc}`, `ipv6-extension.cc` - `Process()` gets the upper-layer protocol so the nonce session is learned under the right protocol (same nonce both ways for UDP)
- `src/internet/CMakeLists.txt` - new files added to existing lists (plus project #4's nonce files and OpenSSL)

From project #4 (Ananya, merged; `ipv6-option.{h,cc}` has one small change by us, listed above):
`src/internet/model/ipv6-option-nonce.{h,cc}`, `ipv6-option.{h,cc}`, `ipv6-l3-protocol.{h,cc}`,
`src/internet/test/ipv6-ilnp-nonce-ping-test.cc`.

## Known issues (not caused by project #6)
- `ipv6-ilnp-nonce-ping` fails at baseline: the "ordinary IPv6" flow reuses the ILNP flow's Identifiers on another prefix and gets a nonce.

## Final results (clean rebuild, -j4)
See docs/final-results.txt: udp-ilnp, udp, ipv6-protocol, ipv6-extension-header, ipv6-raw, ipv6-dual-stack,
ipv6-forwarding, ipv6-fragmentation, ipv6-list-routing, ipv4-raw, ipv6-address-helper PASS.
ipv6-ilnp-nonce-ping FAILS exactly as at baseline (see Known issues). Locator-change behaviour was verified
only against the temporary IlnpIlccStub, not the real ILCC.
