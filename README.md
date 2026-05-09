# Packet Analyzer & DPI Engine

A **Deep Packet Inspection (DPI)** tool built in C++17 that reads network traffic from `.pcap` files, classifies packets by application (YouTube, Facebook, TikTok, etc.) using TLS SNI extraction, and filters/blocks traffic based on configurable rules. Supports both single-threaded and multi-threaded processing pipelines.

---

## Demo Output

<img width="1023" height="1537" alt="image" src="https://github.com/user-attachments/assets/411f5f7e-5cb9-428a-be8d-421d5e9d7568" />

---

## What It Does

- Reads `.pcap` files (Wireshark captures)
- Parses Ethernet → IP → TCP/UDP headers from raw bytes
- Extracts **TLS SNI** from HTTPS Client Hello packets to identify the destination domain without decrypting traffic
- Extracts **HTTP Host** header for plain HTTP traffic
- Tracks connections using the **5-tuple** (src IP, dst IP, src port, dst port, protocol)
- Classifies traffic by app — YouTube, Facebook, TikTok, Discord, Spotify, etc.
- Blocks/drops packets based on rules (by app, domain, or source IP)
- Writes filtered traffic to a new `.pcap` file
- Generates a report with per-app packet counts and detected domains

---

## Project Structure

```
packet_analyzer/
├── include/
│   ├── pcap_reader.h          # PCAP file I/O
│   ├── packet_parser.h        # Ethernet / IP / TCP / UDP parsing
│   ├── sni_extractor.h        # TLS SNI + HTTP Host extraction
│   ├── types.h                # FiveTuple, AppType, Flow structs
│   ├── connection_tracker.h   # Flow state tracking
│   ├── rule_manager.h         # Block/allow rule engine
│   ├── load_balancer.h        # Multi-threaded load distributor
│   ├── fast_path.h            # Worker thread DPI logic
│   ├── thread_safe_queue.h    # Mutex + condvar queue
│   └── dpi_engine.h           # Top-level orchestrator
│
├── src/
│   ├── main_working.cpp       # ★ Single-threaded version
│   ├── dpi_mt.cpp             # ★ Multi-threaded version
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── connection_tracker.cpp
│   ├── rule_manager.cpp
│   ├── load_balancer.cpp
│   ├── fast_path.cpp
│   └── types.cpp
│
├── generate_test_pcap.py      # Generates test_dpi.pcap using Scapy
├── test_dpi.pcap              # Sample capture file
└── CMakeLists.txt
```

---

## How It Works

### Packet Flow (Single-threaded)

```
PCAP File
   │
   ▼
PcapReader       — reads raw bytes + timestamps
   │
   ▼
PacketParser     — decodes Ethernet / IP / TCP / UDP headers
   │
   ▼
SNIExtractor     — inspects TLS Client Hello for domain name
   │
   ▼
ConnectionTracker — groups packets into flows by 5-tuple
   │
   ▼
RuleManager      — checks block rules (IP / app / domain)
   │
   ├── BLOCKED → drop, increment counter
   └── ALLOWED → write to output.pcap
```

### Multi-threaded Pipeline

```
Reader Thread
      │
      ├── hash(5-tuple) % N ──► LB Thread 0 ──► FP Thread 0
      │                                      └─► FP Thread 1
      └──────────────────────► LB Thread 1 ──► FP Thread 2
                                            └─► FP Thread 3
                                                    │
                                             Output Queue
                                                    │
                                            Writer Thread → output.pcap
```

Consistent hashing ensures all packets from the same connection always go to the same Fast Path thread — so flow state is safe without extra locking.

### TLS SNI Extraction

Even though HTTPS traffic is encrypted, the destination domain appears in **plaintext** in the first packet (TLS Client Hello). The engine reads this field — called SNI — to identify the app without touching the encrypted payload.

```
TLS Client Hello (first packet of every HTTPS connection):
└── Extensions
    └── SNI (type 0x0000)
        └── server_name: "www.youtube.com"  ← extracted here
```

### Blocking Logic

```
Incoming packet
   │
   ├── Source IP in blocklist?     → DROP
   ├── App type in blocklist?      → DROP
   ├── SNI matches blocked domain? → DROP
   └── None of the above           → FORWARD
```

Blocking is **flow-based**: once a connection is identified and blocked (on the Client Hello), all remaining packets of that connection are dropped automatically.

---

## Build & Run

### Prerequisites

- C++17 compiler (GCC 9+, Clang 10+, or MSVC 2019+)
- CMake 3.16+
- No external libraries needed

### Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Or manually:

```bash
# Single-threaded
g++ -std=c++17 -O2 -I include -o dpi_working \
    src/main_working.cpp src/pcap_reader.cpp \
    src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

# Multi-threaded
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp
```

### Run

```bash
# Basic
./dpi_working test_dpi.pcap output.pcap

# With blocking rules
./dpi_working test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-domain facebook.com \
    --block-ip 192.168.1.50

# Multi-threaded with custom thread count
./dpi_engine input.pcap output.pcap --lbs 2 --fps 4
```

### Generate Test Traffic

```bash
python3 generate_test_pcap.py    # outputs test_dpi.pcap
```

---

## Tech Stack

| | |
|---|---|
| Language | C++17 |
| Build | CMake 3.16+ |
| Concurrency | pthreads, `std::mutex`, `std::condition_variable` |
| Packet format | libpcap PCAP |
| Protocols parsed | Ethernet, IPv4, TCP, UDP, TLS 1.2/1.3, HTTP |
| Test data | Python + Scapy |
