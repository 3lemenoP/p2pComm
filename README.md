Here is the `README.md` with all emojis removed and formatted for clean readability.

-----

# p2pComm

**Decentralized P2P Messaging with Kaspa Blockchain Integration**

A secure, end-to-end encrypted messaging application using WebRTC for direct peer-to-peer communication and the Kaspa blockchain for decentralized signaling and offline message delivery.

## Features

### Core Messaging

  * **End-to-End Encryption** - ChaCha20-Poly1305 with X25519 key exchange
  * **Message Signing** - Ed25519 digital signatures for authenticity
  * **Direct P2P** - WebRTC data channels for instant messaging (\<100ms latency)
  * **Responsive UI** - Terminal-aesthetic design optimized for mobile and desktop

### Kaspa Blockchain Integration

  * **Decentralized Signaling** - WebRTC offer/answer exchange via blockchain transactions
  * **Offline Delivery** - Messages delivered via blockchain when peers are offline
  * **Peer Discovery** - Automatic discovery via blockchain announcements
  * **Wallet Integration** - HD wallet derivation from password

## Quick Start

### Prerequisites

  * Node.js 18+
  * Rust + wasm-pack (for building WASM core)
  * Kaspa testnet coins (for blockchain features)

### Setup

```bash
# Clone the repository
git clone https://github.com/3lemenoP/p2pComm.git
cd p2pComm

# Build WASM core
cd wasm-core
wasm-pack build --target web
cd ..

# Install frontend dependencies
cd frontend
npm install
npm run copy-wasm

# Start development server
npm run dev
```

Open `http://localhost:3000` in your browser.

### Multi-Device Testing

Test with two browser profiles:

  * Chrome: `http://localhost:3000?user=alice`
  * Firefox: `http://localhost:3000?user=bob`

## Documentation

| Document | Description |
| :--- | :--- |
| PROJECT\_STATUS.md | Current development status and progress |
| PROJECT\_SPECIFICATION.md | Complete architecture and specification |
| docs/KASPA\_INTEGRATION\_PLAN.md | Kaspa blockchain integration guide |
| frontend/README.md | Frontend build and development guide |
| wasm-core/WASM\_API.md | WASM module API reference |

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Vite + JS)                     │
├─────────────────────────────────────────────────────────────┤
│  App Logic  │  WebRTC Bridge  │  Kaspa Service             │
├─────────────────────────────────────────────────────────────┤
│                WASM Core (Rust → WebAssembly)                │
├─────────────────────────────────────────────────────────────┤
│ Identity │ Crypto │ Messages │ Network │ Kaspa │ Storage   │
├─────────────────────────────────────────────────────────────┤
│  WebRTC Data Channels  │  Kaspa Blockchain (Testnet/Mainnet) │
└─────────────────────────────────────────────────────────────┘
```

### Key Modules

| Module | Location | Purpose |
| :--- | :--- | :--- |
| Identity | `wasm-core/src/identity/` | Ed25519/X25519 keypairs, PeerId derivation |
| Crypto | `wasm-core/src/crypto/` | Encryption, signing, hashing, KDF |
| Messages | `wasm-core/src/message/` | Message creation, signing, encryption |
| Kaspa | `wasm-core/src/kaspa/` | Blockchain RPC, wallet, transaction building |
| Network | `wasm-core/src/network/` | Protocol, connection management |

## Development

### Build Commands

```bash
# WASM Core
cd wasm-core
wasm-pack build --target web

# Frontend
cd frontend
npm run build          # Production build
npm run dev            # Development server
npm run full-build     # WASM + Frontend combined
```

### Testing

```bash
# Rust unit tests
cd wasm-core
cargo test

# Type checking
cd frontend
npm run type-check
```

## Current Status

**Version:** Week 10 - Kaspa Message Delivery Fixes

| Component | Status | Progress |
| :--- | :--- | :--- |
| Core Foundation | Production | 100% |
| WASM Rust Backend | Production | 100% |
| Frontend UI | Production | 100% |
| WebRTC P2P | Production | 100% |
| Kaspa Integration | Production | 95% |
| Offline Delivery | Testing | 85% |
| Message Reception | Fixed | 100% |

### Recent Fixes (December 2025)

  * Fixed Kaspa address not saved during contact import
  * Fixed `onResolveRecipientAddress` callback in wallet auto-connect
  * Fixed DUST\_THRESHOLD mismatch (1K → 25M sompis)
  * Improved transaction payload retrieval with BFS DAG traversal
  * Fixed payload serialization (Vec → hex string)
  * Fixed JavaScript Map access for WASM returns
  * Fixed recipient check to allow broadcast messages

## Security Model

  * **Identity:** Ed25519 signing + X25519 encryption keypairs
  * **Key Derivation:** Argon2id from password (m=65536, t=3, p=4)
  * **PeerId:** BLAKE3 hash of signing public key
  * **Encryption:** X25519-ChaCha20-Poly1305 with ephemeral keys
  * **Signatures:** Ed25519 on all messages

## Network Requirements

  * **P2P Messaging:** STUN servers for NAT traversal (\~80% success rate)
  * **Blockchain:** Kaspa testnet RPC endpoint (`wss://testnet.kaspa.ws`)
  * **Headers:** COOP/COEP for WASM SharedArrayBuffer support

## License

[License information]

## Contributing

Contributions welcome\! Please read the project specification first.

Built with using Rust, WebAssembly, and Kaspa

-----

Would you like me to refine the formatting further or generate a project structure tree for this README?