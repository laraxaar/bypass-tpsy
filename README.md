# Bypass TSPY v4.0 — Wintun & WinDivert Hybrid Engine

A highly-efficient, packet-level TCP/UDP DPI evasion utility for Windows. It implements a hybrid **Wintun (packet capture)** and **WinDivert (packet injection)** architecture to bypass modern deep packet inspection (DPI) boxes (such as TSPU / RKN) without heavy CPU load.

---

## Why Wintun + WinDivert Hybrid?

1. **Selective Interception via Route Table**:
   - Instead of matching all system traffic, we load targeted IP blocks or dynamically resolved hosts directly into the Windows Route Table, sending them to a virtual **Wintun TUN adapter**.
   - Normal traffic goes directly to the physical interface without any CPU routing overhead or inspection.

2. **Loop Evasion with WinDivert**:
   - Because Wintun is a virtual TUN interface, writing modified packets back into it causes Windows to loop them right back into Wintun.
   - We use a send-only **WinDivert** handle to inject the modified packets directly to the physical network card (`IfIdx` set to the real gateway interface index), bypassing the routing lookup completely.

3. **Modern TCP Desync Evasion**:
   - **DesyncSplit**: Splitting the TLS ClientHello packet into separate TCP segments (often right in the middle of the SNI hostname string). The DPI box fails to parse the fragmented handshake, while the destination server reassembles it cleanly.
   - **DesyncJunk**: Injecting an out-of-window packet with `TTL = 1`. This packet travels only to the ISP's local DPI box, throwing its state machine off, and dies before reaching the server.

4. **Transparent DNS Proxying with DoH**:
   - We route the system's DNS queries through Wintun by intercepting UDP port 53 packets.
   - Target hostnames are resolved securely via **DNS-over-HTTPS (DoH)** to fetch real IPs and dynamically insert them into the route table. This defeats DNS hijacking/poisoning transparently without changing system files or `netsh`.

5. **QUIC (HTTP/3) Evasion**:
   - UDP 443 Initial packets to target IP addresses are dropped, forcing the browser to fall back to standard TCP where our desync strategies are applied.

---

## Project Structure

```
bypass-tpsy/
├── CMakeLists.txt         # CMake compilation settings
├── config.ini             # Application configuration
├── include/
│   ├── logger.h           # Thread-safe logger
│   ├── config.h           # INI configuration parser
│   ├── packet.h           # IP/TCP/UDP parsing and checksums
│   ├── tls_parser.h       # TLS ClientHello / SNI parser
│   ├── quic_parser.h      # QUIC Initial packet detector
│   ├── dns_proxy.h        # Transparent DNS proxy and DoH client
│   ├── tunnel_io.h        # Wintun TUN adapter interface
│   ├── inject_io.h        # WinDivert packet injector
│   ├── route_table.h      # Windows Route Table manager
│   ├── route_refresher.h  # Dynamic hostname IP rotation scheduler
│   ├── seq_tracker.h      # TCP connection flow state tracker
│   ├── bypass_strategy.h  # DPI bypass strategies (Split, Junk, HTTP)
│   └── stats.h            # Metrics reporting engine
```

---

## Build Requirements

1. **Windows 10/11 x64**
2. **Visual Studio 2022** (supporting C++20 standard library)
3. **CMake** (v3.20+)
4. **Wintun SDK** (contains `wintun.h` and x64/x86 `wintun.dll`)
5. **WinDivert SDK** (contains `windivert.h`, `WinDivert.dll`, and `WinDivert64.sys`)

---

## Build Instructions

1. Install the SDKs to the default paths:
   - Wintun SDK to `C:/SDKs/wintun`
   - WinDivert SDK to `C:/SDKs/windivert`
   *(Alternatively, pass `-DWINTUN_SDK_ROOT="path/to/wintun"` and `-DWINDIVERT_SDK_ROOT="path/to/windivert"` when generating with CMake)*.

2. Run CMake from a developer console:
   ```bash
   cmake -B build -G "Visual Studio 17 2022" -A x64
   cmake --build build --config Release
   ```
   This compiles `bypass_tpsy.exe` and automatically copies `wintun.dll`, `WinDivert.dll`, and `WinDivert64.sys` into the build directory.

---

## Running the Engine

1. Run the command prompt as **Administrator**.
2. Start the engine:
   ```bash
   bypass_tpsy.exe
   ```
3. Set the system's preferred DNS server to `8.8.8.8` (or any dummy server). The engine transparently intercepts queries to this address, resolving target domains through DoH.

---

## System Configuration Settings (`config.ini`)

- `[tunnel]`: Setup local TUN adapter IP (default `10.127.0.1`).
- `[routes]`: Declare static subnets and dynamic hostnames to route through the adapter.
- `[dns]`: Config DoH upstream URL (default Cloudflare).
- `[quic]`: Block UDP 443 initial packets to enforce TCP fallback.
- `[desync]`: Evasion strategies customization (Junk size, TTL, SEQ offset, Split offset, Split delay).
- `[host_filter]`: Whitelist/blacklist domain filters.
- `[stats]`: Metrics print interval (seconds).

---

## Key Limitations & Workarounds

| Failure Scenario | Explanation | Workaround |
|---|---|---|
| DPI at Hop 4+ | Junk packet with `TTL=1` dies at hop 1. If DPI resides further down the route, the junk packet won't reach it. | Increase `junk_ttl` to 2 or 3 in `config.ini` (may reach the target server and trigger TCP warnings if sequence offset is incorrect). |
| TCP Reassembly | DPI reassembles split segments before analysis. | Combine strategies using `desync.mode = chain` to desynchronize DPI state first. |
| CDN IP Pooling | Blocked host shares CDN IP with unblocked domains. | Routing unblocked domains through Wintun is minor overhead. Adjust wildcard filters or route subnets. |
| Active Probing | Server returns a block page or blocks connection in response to DPI probe connection verification. | Out of scope for packet-level tools. Utilize encrypted VPN or VPS proxy. |
