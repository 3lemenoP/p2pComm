# p2pComm - Complete Project Specification

**Version:** 1.1 (Kaspa-Enhanced)
**Last Updated:** 2025-11-17
**Status:** Comprehensive Specification - Offline Delivery & Decentralized Signaling

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Core Architecture](#core-architecture)
3. [Kaspa Blockchain Integration](#kaspa-blockchain-integration)
4. [Technical Components](#technical-components)
5. [Complete User Workflow](#complete-user-workflow)
6. [Security & Privacy](#security--privacy)
7. [Deployment Architecture](#deployment-architecture)
8. [Advanced Features](#advanced-features)

---

## Project Overview

### Vision

**p2pComm** is a fully decentralized, asynchronous messaging platform that uses **Kaspa L1 blockchain** for peer discovery, offline message delivery, and decentralized signaling. It eliminates all centralized infrastructure while providing WhatsApp-like user experience with guaranteed delivery, even when recipients are offline.

### Core Principles

- **No Central Servers**: Discovery, signaling, and offline delivery via Kaspa blockchain
- **Asynchronous by Default**: Messages deliver regardless of online status
- **End-to-End Encryption**: Messages encrypted before leaving browser
- **Censorship Resistant**: Cannot be shut down or blocked
- **Privacy First**: Optional anonymity via Tor/relays
- **Invisible Blockchain**: Users see "verified delivery" - no crypto jargon exposed
- **Browser-First**: Pure client-side application (WASM + HTML)
- **Open Source**: Fully auditable code

### Key Differentiators

| Feature | Traditional P2P | Centralized Apps | p2pComm |
|---------|----------------|-----------------|---------|
| **Offline Delivery** | ❌ No | ✅ Yes (server) | ✅ Yes (blockchain) |
| **Signaling** | ❌ Central server | ✅ Central server | ✅ Kaspa payloads |
| **Speed (Online)** | ✅ Instant | ✅ Instant | ✅ Instant (WebRTC) |
| **Speed (Offline)** | ❌ N/A | ✅ Instant | ⚠️ ~1 second (BlockDAG) |
| **Censorship** | ⚠️ Can block signaling | ❌ Can be blocked | ✅ Resistant |
| **Trust** | ❌ Trust server | ❌ Trust company | ✅ Cryptographic only |
| **Cost/User/Month** | $0.10 (infra) | $0.30-0.50 | $0.005 (blockchain) |
| **Metadata Privacy** | ❌ Server sees all | ❌ Server logs | ⚠️ Public (encrypted) |

### How It Works (User Perspective)

**Alice sends message to Bob:**

1. **Both Online (Direct P2P):**
   - WebRTC connection established directly
   - Message delivered instantly
   - Single checkmark (sent) → Double checkmark (delivered)

2. **Bob Offline (Kaspa Fallback):**
   - Message queued for Kaspa delivery
   - Encrypted message embedded in Kaspa transaction payload
   - Tiny dust output (0.00001 KAS) sent to Bob's address as notification
   - Bob's app monitors blockchain, detects incoming transaction
   - Message decrypted and displayed when Bob comes online
   - Single checkmark (sent) → "Verified delivery" badge
   - Double checkmark when Bob reads

**User sees:** "Message delivered securely" - no mention of blockchain

---

## Core Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    p2pComm Enhanced Architecture                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐                           ┌──────────────┐   │
│  │   Browser    │                           │   Browser    │   │
│  │   (Alice)    │                           │    (Bob)     │   │
│  └──────┬───────┘                           └───────┬──────┘   │
│         │                                            │           │
│         │ ┌─────────────────────────────────────┐  │           │
│         │ │   PRIMARY: Direct P2P (WebRTC)      │  │           │
│         │ │   When both online                  │  │           │
│         ├─┼────────────────────────────────────►├──┤           │
│         │ └─────────────────────────────────────┘  │           │
│         │                                            │           │
│         │ ┌─────────────────────────────────────┐  │           │
│         │ │   FALLBACK: Kaspa Blockchain        │  │           │
│         │ │   • Offline message delivery        │  │           │
│         │ │   • WebRTC signaling (SDP/ICE)      │  │           │
│         │ │   • Verified delivery proofs        │  │           │
│         ├─┼────────────────────────────────────►├──┤           │
│         │ └─────────────────────────────────────┘  │           │
│         ▼                                            ▼           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Kaspa L1 Blockchain                        │   │
│  │  ┌─────────────────────────────────────────────────┐   │   │
│  │  │  Transaction Payload (up to ~98 KB)             │   │   │
│  │  │  • Encrypted messages                           │   │   │
│  │  │  │  • WebRTC SDP offers/answers/ICE              │   │   │
│  │  │  • Batched for efficiency                       │   │   │
│  │  └─────────────────────────────────────────────────┘   │   │
│  │  ┌─────────────────────────────────────────────────┐   │   │
│  │  │  Dust Output (0.00001 KAS to recipient)         │   │   │
│  │  │  • Triggers UTXO notification                   │   │   │
│  │  │  • No content revealed                          │   │   │
│  │  └─────────────────────────────────────────────────┘   │   │
│  │  ~1 second confirmations (BlockDAG)                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           │ Monitor UTXOs                        │
│                           ▼                                      │
│                 ┌──────────────────┐                            │
│  │               │  UTXO Monitor    │                            │
│                 │  (Per-User Wasm) │                            │
│                 └──────────────────┘                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack

**Frontend:**
- HTML5 + CSS3 (Terminal aesthetic)
- Vanilla JavaScript (No frameworks)
- WASM Module (Rust-compiled)
- Service Worker (Background UTXO monitoring)

**Backend (WASM Core):**
- Rust (Performance + Security)
- **Kaspa Integration (Rusty-Kaspa WASM32 SDK):**
  - Full non-custodial wallet
  - Transaction payload embedding
  - UTXO monitoring via WebSocket RPC
  - Mnemonic derivation (deterministic from password)
  - Bundle size: +1.2–1.6 MB (gzipped)
- Ed25519 (Signing)
- X25519 (Encryption)
- BLAKE3 (Hashing)
- IndexedDB (Storage)

**Blockchain:**
- Kaspa L1 (Discovery + Delivery + Signaling)
- Transaction payloads (not P2SH scripts)
- Dust outputs (0.00001 KAS notifications)
- ~1 second block times
- Ultra-low fees (~$0.00005 per message)

**Networking:**
- **WebRTC (Primary):** Direct peer-to-peer when both online
- **Kaspa Payloads (Fallback):** Offline delivery and signaling
- **No STUN/TURN Needed:** Kaspa handles signaling exchange

---

## Kaspa Blockchain Integration

### Why Kaspa for Offline Delivery?

**Technical Advantages:**

1. **Transaction Payloads**
   - Dedicated payload field (not stored in UTXO set)
   - Up to ~98 KB per transaction
   - Perfect for encrypted messages and WebRTC signaling data
   - More efficient than OP_RETURN or P2SH patterns

2. **Ultra-Fast Confirmations**
   - ~1 second block times (BlockDAG)
   - Messages delivered as fast as email
   - 10x faster than Bitcoin

3. **Negligible Costs**
   - ~$0.00005 per offline message
   - $5 funds ~100,000 messages
   - 100x cheaper than centralized push notification services

4. **Dust Outputs as Notifications**
   - 0.00001 KAS ($0.000001) sent to recipient
   - Triggers UTXO watch without revealing content
   - Minimal blockchain footprint

5. **Decentralized RPC Nodes**
   - Multiple public nodes (e.g., api.kaspa.org)
   - No single point of failure
   - WebSocket subscriptions for real-time UTXO updates

### Transaction Payload Structure

**Kaspa Envelope (Wire Format):**

```json
{
  "version": 1,
  "app_id": "p2pcomm/v1",
  "envelope_type": "Message|SignalingOffer|SignalingAnswer|SignalingIce",
  "sender_peer_id": "a1b2c3d4...",
  "recipient_peer_id": "b7c8d9e0...",
  "timestamp": 1234567890,
  "data": "<encrypted_bytes>",
  "signature": "<ed25519_signature>"
}
```

**Data Field Contains:**
- **For Messages:** Encrypted message content (X25519 encryption)
- **For Signaling:** WebRTC SDP or ICE candidates (encrypted)

**Transaction Structure:**
```
Inputs:
  [User's UTXO for fees]

Outputs:
  [0.00001 KAS to recipient address]  ← Dust notification
  [Change back to sender]

Payload:
  [Serialized KaspaEnvelope(s)]       ← Up to ~98 KB
```

### Batching for Efficiency

**Multiple messages in one transaction:**

```json
{
  "batch_version": 1,
  "envelopes": [
    { "recipient": "peer1", "data": "..." },
    { "recipient": "peer2", "data": "..." },
    { "recipient": "peer3", "data": "..." }
  ]
}
```

**Benefits:**
- Send to 20+ recipients for one transaction fee
- Amortizes cost to ~$0.0000025 per message
- Queues batch when app is open, submits every 30 seconds

### Wallet Management (Invisible to User)

**Deterministic Wallet:**
```
User Password + Identity Key → PBKDF2 → Entropy → Mnemonic → Kaspa Wallet
```

**Advantages:**
- No separate backup needed (same password restores everything)
- Fully non-custodial (keys never leave device)
- HD wallet (multiple addresses for privacy)
- Derived addresses shared during handshake

**User Experience:**
- Wallet created automatically during identity setup
- Pre-funded with small amount (optional onboarding gift)
- Auto top-up widgets when balance low (Topper.to integration)
- Never see "mnemonic" or "blockchain" - just "Verified Delivery balance"

---

## Technical Components

### 1. WASM Core Module

**Location:** `wasm-core/`

**Enhanced Modules:**

```rust
wasm-core/src/
├── identity/           # Keypair generation, peer IDs
├── crypto/             # Ed25519, X25519, BLAKE3
├── storage/            # IndexedDB abstraction
│   ├── identity_store.rs
│   ├── message_store.rs
│   ├── peer_addresses.rs
│   └── kaspa_wallet_store.rs    // NEW: Encrypted wallet
├── network/            # Protocol implementation
│   ├── protocol.rs     # Message types
│   ├── connection.rs   # WebRTC connections
│   ├── manager.rs      # Network orchestration
│   └── delivery.rs     // NEW: Delivery strategy (P2P vs Kaspa)
├── kaspa/              # Kaspa blockchain integration
│   ├── wallet.rs       # HD wallet, deterministic mnemonic
│   ├── payload.rs      // NEW: Payload manager
│   ├── utxo_monitor.rs // NEW: UTXO watch + notifications
│   ├── transaction.rs  // NEW: Tx building with payloads
│   └── rpc_client.rs   // NEW: WebSocket RPC connection
└── wasm_bindings/      # JavaScript API
    ├── kaspa_api.rs    // NEW: Kaspa functions
    └── delivery_api.rs // NEW: Verified delivery toggle
```

### 2. Payload Manager (New Component)

**Purpose:** Handle message/signaling embedding in Kaspa transaction payloads

**Responsibilities:**
- Queue pending messages/signals for Kaspa delivery
- Batch multiple envelopes for efficiency
- Build transactions with payload field
- Sign and submit to Kaspa RPC
- Track transaction confirmations

**API:**
```rust
pub struct PayloadManager {
    pending_queue: Vec<PendingItem>,
    batch_interval: Duration,
}

impl PayloadManager {
    pub fn queue_for_kaspa(&mut self, recipient: PeerId, envelope: KaspaEnvelope)

    pub async fn flush_batch(&mut self) -> Result<TxId> {
        // Build transaction with all pending envelopes
        // Submit to Kaspa network
        // Return transaction ID for tracking
    }

    pub fn auto_batch_background(&self) {
        // Batch every 30s when app is active
    }
}
```

### 3. UTXO Monitor (New Component)

**Purpose:** Watch for incoming dust outputs + extract payloads

**Responsibilities:**
- Subscribe to user's addresses via WebSocket RPC
- Detect new UTXOs in real-time
- Fetch transaction data and extract payload
- Verify signature and decrypt data
- Process as message or signaling data
- Background polling when app is inactive

**API:**
```rust
pub struct UtxoMonitor {
    rpc_client: KaspaRpcClient,
    watched_addresses: Vec<Address>,
}

impl UtxoMonitor {
    pub async fn subscribe(&mut self, addresses: Vec<Address>) {
        // WebSocket subscription to address UTXOs
    }

    pub async fn on_new_utxo(&self, utxo: Utxo) -> Result<Vec<KaspaEnvelope>> {
        // Fetch full transaction
        // Extract payload
        // Deserialize envelopes
        // Verify signatures
        // Return valid envelopes
    }

    pub async fn poll_background(&self) {
        // Periodic polling (every 30s) when WebSocket unavailable
    }
}
```

### 4. Network Manager (Enhanced)

**Delivery Strategy:**

```rust
pub enum DeliveryMethod {
    DirectP2P,
    KaspaPayload { tx_id: String },
}

impl NetworkManager {
    pub async fn send_message(&mut self, recipient: PeerId, content: String) -> Result<MessageId> {
        // 1. Try direct WebRTC connection (15s timeout)
        if let Ok(conn) = self.get_connection(&recipient).await {
            // Send via P2P, mark delivered
            return Ok(message_id);
        }

        // 2. Fallback to Kaspa payload
        let envelope = create_envelope(MessageType::Message, content);
        self.payload_manager.queue_for_kaspa(recipient, envelope);
        // Returns immediately, batches in background
        Ok(message_id)
    }

    pub async fn initiate_webrtc(&mut self, peer: PeerId) -> Result<()> {
        // 1. Create SDP offer
        let offer = create_offer();

        // 2. Send via Kaspa payload (signaling)
        let envelope = create_envelope(SignalingType::Offer, offer);
        self.payload_manager.queue_for_kaspa(peer, envelope);

        // 3. Wait for answer (from UTXO monitor callback)
        // 4. Complete WebRTC connection
    }
}
```

---

## Complete User Workflow

### Scenario 1: Both Users Online (Direct P2P)

**Alice sends "Hey Bob!" while both are online:**

1. **Connection Exists:**
   - Alice and Bob previously exchanged Kaspa addresses via handshake
   - WebRTC data channel already established
   - Low-latency direct connection

2. **Message Send:**
   - Alice types message in UI
   - WASM encrypts with Bob's public key (X25519)
   - Signs with Alice's private key (Ed25519)
   - Sends via WebRTC data channel
   - **Latency: < 100ms**

3. **Delivery Confirmation:**
   - Bob receives encrypted bytes
   - Verifies Alice's signature
   - Decrypts message
   - Sends ACK back via P2P
   - Alice sees double checkmark
   - **Total time: < 200ms**

**User sees:** Instant delivery (like WhatsApp)

---

### Scenario 2: Recipient Offline (Kaspa Fallback)

**Alice sends "Call me back" but Bob is offline:**

1. **Connection Attempt:**
   - Alice's app tries to establish WebRTC to Bob
   - Timeout after 15 seconds
   - Detects Bob is offline

2. **Kaspa Delivery:**
   - Message queued for Kaspa delivery
   - App batches with other pending messages (waits up to 30s)
   - Creates KaspaEnvelope:
     ```json
     {
       "envelope_type": "Message",
       "sender": "alice_peer_id",
       "recipient": "bob_peer_id",
       "data": "<encrypted_message>",
       "signature": "<alice_signature>"
     }
     ```
   - Builds Kaspa transaction:
     - Dust output (0.00001 KAS) to Bob's address
     - Payload with encrypted envelope
   - Submits to Kaspa network
   - **Confirmation: ~1 second**

3. **Delivery Status:**
   - Alice sees "Sent via verified delivery"
   - Optional: Link to Kaspa explorer (for advanced users)
   - UI shows blockchain confirmation icon

4. **Bob Comes Online:**
   - Bob's app starts UTXO monitor
   - Detects new dust UTXO to his address
   - Fetches transaction from Kaspa RPC
   - Extracts payload, deserializes envelope
   - Verifies Alice's signature
   - Decrypts message with his private key
   - Message appears in conversation
   - Sends read receipt (via P2P or Kaspa)

5. **Alice Notified:**
   - Alice sees double checkmark (delivered + read)
   - **Total offline delivery time: 1-5 seconds after Bob opens app**

**User sees:** "Message delivered securely" (no blockchain jargon)

---

### Scenario 3: First Connection (Decentralized Signaling)

**Alice wants to call Bob for the first time:**

1. **No Existing Connection:**
   - Alice and Bob are contacts but never connected before
   - No WebRTC data channel exists
   - Need to exchange SDP offers/answers

2. **WebRTC Signaling via Kaspa:**

   **Step 1: Alice creates offer**
   - Generates WebRTC offer (SDP)
   - Wraps in KaspaEnvelope (type: SignalingOffer)
   - Sends via Kaspa payload to Bob's address

   **Step 2: Bob receives offer**
   - UTXO monitor detects dust + payload
   - Extracts SDP offer
   - Creates SDP answer
   - Sends answer via Kaspa payload to Alice's address

   **Step 3: Alice receives answer**
   - Completes WebRTC connection
   - Direct P2P channel established

   **Step 4: ICE candidates**
   - Exchange ICE candidates via Kaspa if needed
   - NAT traversal completes

3. **Connection Established:**
   - **Total signaling time: 3-6 seconds** (3-6 Kaspa transactions)
   - Once established, connection persists
   - Future messages go via WebRTC directly

**User sees:** "Establishing secure connection..." then "Connected"

**Note:** After first connection, WebRTC reconnects instantly using cached ICE

---

## Security & Privacy

### Cryptographic Guarantees

**Identity:**
- Ed25519 signing (authentication)
- X25519 encryption (confidentiality)
- Peer ID = BLAKE3(public_key) (unforgeable)

**Messages:**
- Signed by sender (non-repudiation)
- Encrypted to recipient (confidentiality)
- Timestamped (replay protection)
- Kaspa provides tamper-proof delivery proof

**Kaspa Payloads:**
- Encrypted identically to P2P messages
- Signatures verified before processing
- Dust spam prevented by sender verification

### Privacy Considerations

**Public on Blockchain:**
- Transaction IDs
- Dust amounts (0.00001 KAS)
- Payload sizes (but content encrypted)
- Timestamps
- Sender/recipient addresses (Kaspa addresses, not Peer IDs)

**Private (Encrypted):**
- Message contents
- Sender/recipient Peer IDs (inside encrypted payload)
- WebRTC signaling data

**Mitigation Strategies:**

1. **Address Rotation:**
   - HD wallet generates new addresses for each contact
   - Prevents linking multiple conversations

2. **Batching:**
   - Multiple recipients in one transaction
   - Obscures who is communicating with whom

3. **Tor Integration:**
   - Connect to Kaspa RPC via Tor
   - Hide IP address

4. **Optional Paid Relays:**
   - Submit transactions through third-party relays
   - Further obscure origin

### Security Best Practices

**Wallet Security:**
- Deterministic from password (no separate backup)
- Encrypted at rest in IndexedDB
- Never transmitted over network

**Dust Spam Prevention:**
- Only process payloads with valid signatures
- Ignore unsigned dust outputs
- Rate limit per-sender

**Replay Attack Prevention:**
- Timestamp validation (reject >24h old)
- Message ID deduplication
- Nonce tracking

---

## Deployment Architecture

### Hosting (Zero Infrastructure)

**Static Files Only:**
```
yoursite.com/
├── index.html           # PWA shell
├── chat.html            # Main app
├── sw.js                # Service Worker (UTXO background polling)
└── pkg/
    ├── wasm_core.js
    └── wasm_core_bg.wasm  (~1.8 MB with Kaspa integration)
```

**Deployment Options:**
- GitHub Pages (free)
- Netlify (free)
- Vercel (free)
- IPFS (decentralized)
- Self-hosted (Nginx)

**No Backend Required:**
- No signaling server
- No message relay
- No database
- No authentication service

### Infrastructure Requirements

**For Users:**
- Web browser (Chrome, Firefox, Safari)
- ~2 MB WASM download (one-time, cached)
- Small amount of KAS for offline messages (~$5 = 100,000 messages)

**For Developers:**
- **None** - uses public Kaspa RPC nodes

**Optional (Community):**
- Run Kaspa full node (for censorship resistance)
- IPFS pinning service (decentralized hosting)

### Cost Analysis

**Per User Per Month:**

```
Scenarios:
  100 messages/month:
    - 80% sent while online (direct P2P): Free
    - 20% sent while offline (Kaspa):
      20 messages × $0.00005 = $0.001

  1,000 messages/month:
    - 80% sent while online: Free
    - 20% sent while offline:
      200 messages × $0.00005 = $0.01

  10,000 messages/month (heavy user):
    - 80% sent while online: Free
    - 20% sent while offline:
      2,000 messages × $0.00005 = $0.10

Wallet Top-Up:
  $5 one-time = 100,000 offline messages
  (Lasts 5-8 months for average user)
```

**Comparison:**

| Service | Cost/User/Month | Centralized? |
|---------|----------------|--------------|
| p2pComm | $0.01-0.10 | ❌ No |
| WhatsApp | $0.30 (est) | ✅ Yes |
| Signal | $0.50 (donated) | ✅ Yes |
| Telegram | $0.40 (est) | ✅ Yes |

**Infrastructure Costs:**
- Hosting: $0 (static files)
- Signaling: $0 (Kaspa blockchain)
- Relay: $0 (Kaspa blockchain)
- Database: $0 (IndexedDB)
- **Total: $0**

---

## Advanced Features

### 1. Verified Delivery Proofs

**Blockchain-Anchored Receipts:**

```json
{
  "message_id": "msg_12345",
  "delivered_via": "kaspa",
  "tx_id": "abc123def456...",
  "block_height": 1234567,
  "confirmations": 10,
  "proof_url": "https://explorer.kaspa.org/tx/abc123..."
}
```

**User Experience:**
- Long-press message → "View delivery proof"
- Shows blockchain confirmation (for disputes)
- Cryptographically verifiable receipt

### 2. Group Messaging

**Batch Delivery:**
- One Kaspa transaction to all group members
- Encrypted with shared group key
- Amortized cost: $0.00005 ÷ 10 members = $0.000005/message

**Group Key Management:**
- Rotate keys via encrypted payload
- Admin-controlled member list

### 3. File Transfer

**Large Files (>98 KB):**
- Chunk into multiple transactions
- Send manifest in first transaction
- Reassemble on recipient side
- Progress tracking via blockchain confirmations

**Cost Example:**
- 10 MB file = ~100 chunks
- 100 transactions × $0.00005 = $0.005
- Still cheaper than S3 transfer costs

### 4. Offline Voice Messages

**Audio Attachments:**
- Encode to Opus (efficient)
- Typical 1-minute voice message: ~50 KB
- Fits in single Kaspa payload
- Cost: $0.00005

### 5. Auto-Retry with Backoff

**Delivery Guarantees:**
- Try P2P (15s timeout)
- Queue for Kaspa (30s batch)
- Retry if tx fails (exponential backoff)
- Mark "failed" after 3 attempts
- User can manually retry

### 6. Multi-Device Sync

**Same Identity, Multiple Devices:**
- Shared mnemonic → same Kaspa wallet
- All devices monitor same addresses
- Messages delivered to all devices
- Last-read state synced via Kaspa payload

### 7. Disappearing Messages

**Self-Destructing:**
- Set TTL in payload metadata
- Recipient app honors TTL (or deletes)
- Blockchain record remains (encrypted)
- User trust model: recipient can screenshot

---

## User Experience & Seamlessness

### No Blockchain Exposure

**User-Facing Terms:**

| Technical Term | User Sees |
|---------------|-----------|
| Kaspa transaction | "Verified delivery" |
| Blockchain confirmation | "Delivered securely" |
| UTXO | (invisible) |
| Wallet balance | "Secure delivery balance" |
| Mnemonic | (never shown - deterministic) |
| Transaction fee | (absorbed into "delivery") |

### Onboarding Flow

1. **Create Identity:**
   - Username + password
   - Generates Peer ID + Kaspa wallet automatically
   - No mention of blockchain

2. **Optional Pre-Funding:**
   - "Enable verified delivery? $5 unlocks 100,000 messages"
   - Integration with Topper.to (credit card → KAS)
   - Or "Skip for now" (can enable later)

3. **Add Contacts:**
   - Scan QR code or enter Peer ID
   - App exchanges Kaspa addresses during first handshake
   - User never sees Kaspa addresses

4. **Send Message:**
   - Works immediately (P2P if both online)
   - Falls back to Kaspa seamlessly
   - UI shows delivery status without blockchain jargon

### Low Balance Handling

**When balance < 20 messages:**
- Non-intrusive banner: "Secure delivery running low"
- One-click top-up widget
- Option to disable verified delivery (P2P only mode)

**Never Disruptive:**
- Messages still send via P2P when possible
- Offline messages queue until topped up
- No "payment failed" errors

---

## Success Metrics

### Technical Metrics

- **P2P Success Rate:** > 80% (when both online)
- **Kaspa Delivery Time:** < 2 seconds (average)
- **UTXO Detection Latency:** < 5 seconds
- **Message Delivery Rate:** > 99.9%
- **WASM Load Time:** < 3 seconds

### User Metrics

- **Monthly Active Users:** 10,000+
- **Messages Sent:** 500,000+/month
- **Offline Delivery Usage:** ~20% of messages
- **User Retention:** > 60% (30 day)
- **NPS Score:** > 50

### Cost Metrics

- **Avg Cost/User/Month:** < $0.10
- **Infrastructure Costs:** $0
- **Kaspa Network Fees:** ~$50/month (for 1M messages)

---

## Migration from Phase 1/2

### For Existing Users

1. **Wallet Creation:**
   - Prompt: "Enable offline delivery?"
   - Generate wallet from existing password
   - Pre-fund option presented

2. **Contact Address Exchange:**
   - Next handshake includes Kaspa address
   - Backfill for existing contacts via P2P message

3. **Gradual Rollout:**
   - Feature flag: `enable_kaspa_delivery`
   - Start with beta users
   - Monitor costs and performance
   - Expand to all users

### For Developers

1. **Add Kaspa Dependencies:**
   ```toml
   kaspa-wasm = "0.15"
   kaspa-rpc-core = "0.15"
   kaspa-wallet-core = "0.15"
   ```

2. **Implement Components:**
   - PayloadManager
   - UtxoMonitor
   - Delivery strategy logic

3. **Testing:**
   - Unit tests for payload serialization
   - Integration tests with local Kaspa node
   - E2E tests with testnet

4. **Deployment:**
   - Deploy to staging (testnet KAS)
   - Beta test with 100 users
   - Production rollout (mainnet KAS)

---

## Future Vision

### Phase 1: MVP (Current - v1.1)
- Basic messaging (P2P + Kaspa fallback)
- Verified delivery
- Decentralized signaling
- 1,000 beta users

### Phase 2: Enhanced Delivery
- File transfer via chunked payloads
- Voice messages
- Group messaging optimization
- 10,000 users

### Phase 3: Advanced Features
- Multi-device sync
- Disappearing messages
- Read receipts via Kaspa
- 50,000 users

### Phase 4: Ecosystem
- Mobile apps (iOS/Android)
- Desktop apps (Electron)
- Public API
- Third-party integrations
- 100,000+ users

### Phase 5: Decentralized Infrastructure
- Community-run RPC nodes
- IPFS hosting
- Tor hidden service option
- Zero-knowledge proofs for metadata privacy
- 1,000,000+ users

---

**This specification represents the complete vision for p2pComm with Kaspa-enhanced offline delivery and decentralized signaling. Implementation details and current status are documented separately in PROJECT_STATUS.md**

**Key Innovation:** Asynchronous messaging without servers, using blockchain as a decentralized message queue with cryptographic delivery proofs.
