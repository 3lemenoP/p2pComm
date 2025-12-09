/**
 * Kaspa Blockchain Service for p2pComm
 *
 * Provides decentralized peer discovery and signaling through the Kaspa blockchain.
 * This module integrates with the WASM Kaspa API to enable:
 * 1. Automatic WebRTC signaling via blockchain transactions
 * 2. Peer discovery through blockchain announcements
 * 3. Fallback message delivery when WebRTC is unavailable
 *
 * Modes:
 * - 'simulation': Uses localStorage for testing (default)
 * - 'testnet': Connects to real Kaspa testnet
 */

// Default testnet RPC endpoint
const DEFAULT_TESTNET_RPC = 'wss://testnet.kaspad.net:443';

// Alternative testnet endpoints to try
const TESTNET_ENDPOINTS = [
    'ws://127.0.0.1:17110',           // Local kaspad (Borsh)
    'ws://127.0.0.1:18110',           // Local kaspad (JSON)
    'wss://testnet.kaspad.net:443',
    'wss://seeder1.kaspad.net:443',
    'wss://seeder2.kaspad.net:443',
];

// Connection timeout in milliseconds
const RPC_CONNECT_TIMEOUT = 10000; // 10 seconds

export class KaspaService {
    constructor(wasmModule) {
        this.wasmModule = wasmModule;
        this.localPeerId = null;
        this.kaspaAddress = null;

        // Managers from WASM
        this.signalingManager = null;
        this.discoveryManager = null;
        this.messageQueue = null;

        // RPC connection state
        this.rpcEndpoint = null;
        this.isConnected = false;
        this.pollingInterval = null;

        // Mode: 'simulation' (localStorage) or 'testnet' (real blockchain)
        this.mode = 'simulation';

        // Wallet state (for testnet mode)
        this.walletInfo = null;
        this.isWalletInitialized = false;

        // Callbacks
        this.onPeerDiscovered = null;
        this.onSignalingMessage = null;
        this.onMessageReceived = null;
        this.onConnectionStatusChanged = null;
        this.onWalletInitialized = null;
        this.onBalanceChanged = null;
        this.onDeliveryConfirmation = null;  // Callback for delivery confirmations

        // Offline message queue for batching
        this.offlineQueue = [];
        this.maxBatchSize = 5;  // Max messages per batch
        this.batchFlushInterval = 30000;  // Flush every 30 seconds
        this.flushTimer = null;

        // Delivery tracking
        this.pendingDeliveries = new Map();  // message_id -> {status, timestamp, attempts}

        // Stats
        this.stats = null;
    }

    /**
     * Initialize the Kaspa service
     * @param {string} localPeerId - The local peer ID
     * @param {string} kaspaAddress - The Kaspa wallet address for receiving messages (ignored in testnet mode)
     * @param {Object} options - Configuration options
     * @param {string} options.mode - 'simulation' (localStorage) or 'testnet' (real blockchain)
     * @param {string} options.rpcEndpoint - Kaspa RPC endpoint URL (for testnet mode)
     * @param {string} options.password - Wallet password (for testnet mode)
     */
    async initialize(localPeerId, kaspaAddress, options = {}) {
        this.localPeerId = localPeerId;
        this.mode = options.mode || 'simulation';
        this.rpcEndpoint = options.rpcEndpoint || DEFAULT_TESTNET_RPC;

        try {
            // Initialize WASM managers
            this.signalingManager = this.wasmModule.create_signaling_manager(localPeerId);
            this.discoveryManager = this.wasmModule.create_discovery_manager(localPeerId);
            this.messageQueue = this.wasmModule.create_message_queue(localPeerId);
            this.stats = this.wasmModule.create_kaspa_stats();

            console.log('[KaspaService] Initialized with peer ID:', localPeerId);
            console.log('[KaspaService] Mode:', this.mode);

            if (this.mode === 'testnet') {
                // Testnet mode: Connect to real Kaspa network
                await this.initializeTestnetMode(options.password);
            } else {
                // Simulation mode: Use provided address
                this.kaspaAddress = kaspaAddress;
                console.log('[KaspaService] Kaspa address (simulated):', kaspaAddress);
            }

            // Start polling for blockchain messages
            await this.startBlockchainPolling();

            this.isConnected = true;
            this.notifyStatusChange('connected');

            return true;
        } catch (error) {
            console.error('[KaspaService] Initialization failed:', error);
            this.notifyStatusChange('error');
            throw error;
        }
    }

    /**
     * Initialize testnet mode with real wallet and RPC connection
     * @private
     */
    async initializeTestnetMode(password) {
        if (!password) {
            throw new Error('Password required for testnet mode');
        }

        console.log('[KaspaService] Initializing testnet mode...');

        // Create deterministic wallet from password
        try {
            this.walletInfo = this.wasmModule.kaspa_create_wallet(password, true); // true = testnet
            this.kaspaAddress = this.walletInfo.primary_address;
            this.isWalletInitialized = true;

            console.log('[KaspaService] Wallet initialized');
            console.log('[KaspaService] Primary address:', this.kaspaAddress);
            console.log('[KaspaService] Receive addresses:', this.walletInfo.receive_addresses?.length || 0);

            if (this.onWalletInitialized) {
                this.onWalletInitialized(this.walletInfo);
            }
        } catch (error) {
            console.error('[KaspaService] Wallet creation failed:', error);
            throw new Error('Failed to create wallet: ' + error);
        }

        // Connect to Kaspa testnet RPC with timeout and fallback
        const endpointsToTry = this.rpcEndpoint
            ? [this.rpcEndpoint, ...TESTNET_ENDPOINTS.filter(e => e !== this.rpcEndpoint)]
            : TESTNET_ENDPOINTS;

        let connected = false;

        for (const endpoint of endpointsToTry) {
            console.log('[KaspaService] Trying RPC endpoint:', endpoint);

            try {
                // Create a timeout promise
                const timeoutPromise = new Promise((_, reject) => {
                    setTimeout(() => reject(new Error('Connection timeout')), RPC_CONNECT_TIMEOUT);
                });

                // Race between connection and timeout
                await Promise.race([
                    this.wasmModule.kaspa_connect(endpoint),
                    timeoutPromise
                ]);

                console.log('[KaspaService] Connected to RPC:', endpoint);
                this.rpcEndpoint = endpoint;
                connected = true;

                // Get initial balance
                await this.refreshBalance();
                break;
            } catch (error) {
                console.warn('[KaspaService] RPC endpoint failed:', endpoint, '-', error.message || error);
                // Try next endpoint
            }
        }

        if (!connected) {
            console.warn('[KaspaService] All RPC endpoints failed, falling back to simulation mode');
            console.log('[KaspaService] Wallet features available, blockchain features simulated');
        }
    }

    /**
     * Refresh wallet balance
     */
    async refreshBalance() {
        if (!this.isWalletInitialized || this.mode !== 'testnet') {
            return null;
        }

        try {
            const balance = await this.wasmModule.kaspa_get_balance(this.kaspaAddress);
            console.log('[KaspaService] Balance:', balance);

            if (this.onBalanceChanged) {
                this.onBalanceChanged(balance);
            }

            return balance;
        } catch (error) {
            console.warn('[KaspaService] Failed to get balance:', error);
            return null;
        }
    }

    /**
     * Get wallet information
     */
    getWalletInfo() {
        return this.walletInfo;
    }

    /**
     * Check if wallet is initialized
     */
    hasWallet() {
        return this.isWalletInitialized;
    }

    /**
     * Announce presence on the blockchain for peer discovery
     */
    async announcePresence(publicKey) {
        if (!this.isConnected) {
            throw new Error('Kaspa service not connected');
        }

        try {
            // Create peer announcement
            const announcement = this.wasmModule.create_peer_announcement(
                this.localPeerId,
                this.kaspaAddress,
                publicKey
            );

            // Serialize to JSON for transmission
            const announcementJson = this.wasmModule.serialize_announcement(announcement);

            // Create blockchain envelope
            const envelope = this.wasmModule.create_announcement_envelope(
                this.localPeerId,
                announcementJson
            );

            // Announcements are time-sensitive, send immediately (bypass queue)
            await this.submitToBlockchain(envelope);

            console.log('[KaspaService] Presence announced on blockchain');
            this.stats.messages_sent++;

            return true;
        } catch (error) {
            console.error('[KaspaService] Failed to announce presence:', error);
            throw error;
        }
    }

    /**
     * Send WebRTC signaling offer via blockchain
     */
    async sendOffer(remotePeerId, sdp, sessionId) {
        if (!this.isConnected) {
            throw new Error('Kaspa service not connected');
        }

        try {
            // Create SDP offer data
            const sdpData = this.wasmModule.create_sdp_offer(sdp, sessionId);
            const sdpJson = JSON.stringify({
                type: 'offer',
                sdp: sdp,
                session_id: sessionId
            });

            // Create signaling envelope
            const envelope = this.wasmModule.create_signaling_envelope(
                this.localPeerId,
                remotePeerId,
                3, // EnvelopeType::SignalingOffer
                sdpJson
            );

            // Submit to blockchain
            await this.submitToBlockchain(envelope);

            console.log('[KaspaService] Offer sent via blockchain to:', remotePeerId);
            this.stats.messages_sent++;

            return sessionId;
        } catch (error) {
            console.error('[KaspaService] Failed to send offer:', error);
            throw error;
        }
    }

    /**
     * Send WebRTC signaling answer via blockchain
     */
    async sendAnswer(remotePeerId, sdp, sessionId) {
        if (!this.isConnected) {
            throw new Error('Kaspa service not connected');
        }

        try {
            const sdpJson = JSON.stringify({
                type: 'answer',
                sdp: sdp,
                session_id: sessionId
            });

            // Create signaling envelope
            const envelope = this.wasmModule.create_signaling_envelope(
                this.localPeerId,
                remotePeerId,
                4, // EnvelopeType::SignalingAnswer
                sdpJson
            );

            // Submit to blockchain
            await this.submitToBlockchain(envelope);

            console.log('[KaspaService] Answer sent via blockchain to:', remotePeerId);
            this.stats.messages_sent++;

            return true;
        } catch (error) {
            console.error('[KaspaService] Failed to send answer:', error);
            throw error;
        }
    }

    /**
     * Send ICE candidates via blockchain
     */
    async sendIceCandidates(remotePeerId, candidates, sessionId) {
        if (!this.isConnected) {
            throw new Error('Kaspa service not connected');
        }

        try {
            const iceJson = JSON.stringify({
                candidates: candidates,
                session_id: sessionId
            });

            // Create signaling envelope
            const envelope = this.wasmModule.create_signaling_envelope(
                this.localPeerId,
                remotePeerId,
                5, // EnvelopeType::SignalingIce
                iceJson
            );

            // Submit to blockchain
            await this.submitToBlockchain(envelope);

            console.log('[KaspaService] ICE candidates sent via blockchain to:', remotePeerId);
            this.stats.messages_sent++;

            return true;
        } catch (error) {
            console.error('[KaspaService] Failed to send ICE candidates:', error);
            throw error;
        }
    }

    /**
     * Send a direct message via blockchain (fallback when WebRTC unavailable)
     * Messages are queued and batched for cost optimization
     */
    async sendMessage(remotePeerId, messagePayload, options = {}) {
        if (!this.isConnected) {
            throw new Error('Kaspa service not connected');
        }

        try {
            // Create direct message envelope
            const envelope = this.wasmModule.create_direct_message_envelope(
                this.localPeerId,
                remotePeerId,
                JSON.stringify(messagePayload)
            );

            // Queue for offline delivery (with batching)
            // Use immediate=true for urgent messages
            const immediate = options.immediate || false;
            await this.queueOfflineMessage(envelope, immediate);

            console.log('[KaspaService] Message queued for blockchain delivery to:', remotePeerId);
            this.stats.messages_sent++;

            return true;
        } catch (error) {
            console.error('[KaspaService] Failed to send message:', error);
            throw error;
        }
    }

    /**
     * Queue a message for offline delivery (with batching)
     * Used for non-urgent messages to reduce blockchain costs
     * @param {Object} envelope - The message envelope to queue
     * @param {boolean} immediate - If true, bypass queue and send immediately
     * @returns {string} message_id - Unique identifier for tracking delivery status
     */
    async queueOfflineMessage(envelope, immediate = false) {
        // Generate message ID for tracking
        const messageId = envelope.message_id || `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Track delivery status
        this.pendingDeliveries.set(messageId, {
            status: 'queued',
            timestamp: Date.now(),
            attempts: 0
        });

        if (immediate) {
            // Priority messages (signaling, announcements) bypass the queue
            this.pendingDeliveries.get(messageId).status = 'sending';
            await this.submitToBlockchain(envelope);
            this.confirmDelivery(messageId, 'submitted');
            return messageId;
        }

        // Add to offline queue
        this.offlineQueue.push({
            envelope: envelope,
            messageId: messageId,
            timestamp: Date.now()
        });

        console.log(`[KaspaService] Message queued for offline delivery (${this.offlineQueue.length}/${this.maxBatchSize})`);

        // Auto-flush if queue reaches max size
        if (this.offlineQueue.length >= this.maxBatchSize) {
            await this.flushOfflineQueue();
        } else {
            // Start flush timer if not already running
            this.startFlushTimer();
        }

        return messageId;
    }

    /**
     * Start the batch flush timer
     * @private
     */
    startFlushTimer() {
        if (this.flushTimer) {
            return; // Timer already running
        }

        this.flushTimer = setInterval(async () => {
            if (this.offlineQueue.length > 0) {
                await this.flushOfflineQueue();
            }
        }, this.batchFlushInterval);
    }

    /**
     * Flush the offline queue - submit all queued messages
     */
    async flushOfflineQueue() {
        if (this.offlineQueue.length === 0) {
            return;
        }

        console.log(`[KaspaService] Flushing offline queue: ${this.offlineQueue.length} messages`);

        // In simulation mode or when batching is enabled, we can submit them individually
        // In real blockchain mode with batching support, we'd combine payloads
        const queuedMessages = [...this.offlineQueue];
        this.offlineQueue = [];

        // Submit each message
        for (const queuedMsg of queuedMessages) {
            try {
                // Update status to sending
                if (this.pendingDeliveries.has(queuedMsg.messageId)) {
                    this.pendingDeliveries.get(queuedMsg.messageId).status = 'sending';
                    this.pendingDeliveries.get(queuedMsg.messageId).attempts++;
                }

                await this.submitToBlockchain(queuedMsg.envelope);

                // Confirm delivery
                this.confirmDelivery(queuedMsg.messageId, 'submitted');
            } catch (error) {
                console.error('[KaspaService] Failed to submit queued message:', error);

                // Update status to failed
                if (this.pendingDeliveries.has(queuedMsg.messageId)) {
                    this.pendingDeliveries.get(queuedMsg.messageId).status = 'failed';
                    this.confirmDelivery(queuedMsg.messageId, 'failed');
                }

                // Re-queue failed message (up to 3 attempts)
                const attempts = this.pendingDeliveries.get(queuedMsg.messageId)?.attempts || 0;
                if (attempts < 3) {
                    this.offlineQueue.push(queuedMsg);
                }
            }
        }

        console.log(`[KaspaService] Queue flushed. Remaining: ${this.offlineQueue.length}`);
    }

    /**
     * Confirm delivery of a message and notify callback
     * @param {string} messageId - The message ID
     * @param {string} status - The delivery status (submitted, delivered, failed)
     * @private
     */
    confirmDelivery(messageId, status) {
        if (!this.pendingDeliveries.has(messageId)) {
            return;
        }

        const delivery = this.pendingDeliveries.get(messageId);
        delivery.status = status;
        delivery.confirmedAt = Date.now();

        console.log(`[KaspaService] Delivery confirmation: ${messageId} -> ${status}`);

        // Notify callback
        if (this.onDeliveryConfirmation) {
            this.onDeliveryConfirmation({
                messageId: messageId,
                status: status,
                timestamp: delivery.timestamp,
                confirmedAt: delivery.confirmedAt,
                attempts: delivery.attempts
            });
        }

        // Clean up old delivery records (keep for 5 minutes for status queries)
        setTimeout(() => {
            this.pendingDeliveries.delete(messageId);
        }, 5 * 60 * 1000);
    }

    /**
     * Get discovered peers from the blockchain
     */
    getDiscoveredPeers() {
        if (!this.discoveredPeers) {
            return [];
        }
        return Array.from(this.discoveredPeers.values());
    }

    /**
     * Get connection candidates (peers suitable for auto-connect)
     */
    getConnectionCandidates(maxCandidates = 5) {
        if (!this.discoveryManager) {
            return [];
        }

        try {
            return this.discoveryManager.get_connection_candidates(maxCandidates);
        } catch (error) {
            console.error('[KaspaService] Failed to get candidates:', error);
            return [];
        }
    }

    /**
     * Submit envelope to blockchain via RPC
     * @private
     */
    async submitToBlockchain(envelope) {
        try {
            // Serialize envelope to bytes
            const bytes = this.wasmModule.serialize_envelope(envelope);

            if (this.mode === 'testnet' && this.isWalletInitialized) {
                // Testnet mode: Submit real transaction
                const submitted = await this.submitRealTransaction(envelope, bytes);

                if (!submitted) {
                    // Fallback to simulation if real submission fails
                    console.warn('[KaspaService] Real submission failed, using simulation fallback');
                    await this.simulateBlockchainSubmit(envelope, bytes);
                }
            } else {
                // Simulation mode: Use localStorage for cross-tab communication
                await this.simulateBlockchainSubmit(envelope, bytes);
            }

            this.stats.transactions_submitted++;

            return true;
        } catch (error) {
            console.error('[KaspaService] Blockchain submit failed:', error);
            throw error;
        }
    }

    /**
     * Submit a real transaction to Kaspa testnet
     * @private
     */
    async submitRealTransaction(envelope, payloadBytes) {
        try {
            // Get recipient address from envelope
            let recipientAddress = this.kaspaAddress; // Default to self (for announcements)

            // Try to resolve recipient peer's Kaspa address
            if (envelope.recipient_peer_id && this.discoveredPeers) {
                const recipientPeer = this.discoveredPeers.get(envelope.recipient_peer_id);
                if (recipientPeer?.kaspaAddress) {
                    recipientAddress = recipientPeer.kaspaAddress;
                }
            }

            // Get UTXOs for our address
            const utxosResult = await this.wasmModule.kaspa_get_utxos(this.kaspaAddress);
            if (!utxosResult || utxosResult.length === 0) {
                console.warn('[KaspaService] No UTXOs available for transaction');
                return false;
            }

            // Get change address
            const changeAddress = this.walletInfo.change_addresses?.[0] || this.kaspaAddress;

            // Build transaction with payload
            const builtTx = this.wasmModule.kaspa_build_payload_transaction(
                JSON.stringify(utxosResult),
                recipientAddress,
                changeAddress,
                Array.from(payloadBytes)
            );

            console.log('[KaspaService] Built transaction:', {
                fee: builtTx.fee,
                payload_size: builtTx.payload_size,
                total_input: builtTx.total_input,
                total_output: builtTx.total_output
            });

            // Submit transaction
            const txId = await this.wasmModule.kaspa_submit_transaction(builtTx.transaction_json);

            console.log('[KaspaService] Transaction submitted:', txId);

            // Also submit to simulation layer for immediate cross-tab communication
            // (Real blockchain takes a few seconds to propagate)
            await this.simulateBlockchainSubmit(envelope, payloadBytes);

            return true;
        } catch (error) {
            console.error('[KaspaService] Real transaction submission failed:', error);
            return false;
        }
    }

    /**
     * Simulate blockchain submission using localStorage
     * This allows testing without actual Kaspa network
     * @private
     */
    async simulateBlockchainSubmit(envelope, bytes) {
        const pendingMessages = JSON.parse(
            localStorage.getItem('kaspa_pending_messages') || '[]'
        );

        // Deserialize bytes to get proper JSON structure
        // The bytes are the JSON-serialized envelope
        let envelopeData;
        try {
            const decoder = new TextDecoder();
            const jsonString = decoder.decode(new Uint8Array(bytes));
            envelopeData = JSON.parse(jsonString);
        } catch (e) {
            console.error('[KaspaService] Failed to deserialize envelope:', e);
            // Fallback: try to access WASM getters
            envelopeData = {
                envelope_type: typeof envelope.envelope_type === 'function'
                    ? envelope.envelope_type()
                    : envelope.envelope_type,
                sender_peer_id: typeof envelope.sender_peer_id === 'function'
                    ? envelope.sender_peer_id()
                    : envelope.sender_peer_id,
                recipient_peer_id: envelope.recipient_peer_id || null,
                payload: typeof envelope.payload === 'function'
                    ? envelope.payload()
                    : envelope.payload,
                timestamp: envelope.timestamp,
                message_id: envelope.message_id,
                signature: envelope.signature || null
            };
        }

        pendingMessages.push({
            envelope: envelopeData,
            bytes: Array.from(bytes),
            timestamp: Date.now(),
            txId: 'sim_' + Date.now().toString(36)
        });

        // Keep only last 100 messages
        while (pendingMessages.length > 100) {
            pendingMessages.shift();
        }

        localStorage.setItem('kaspa_pending_messages', JSON.stringify(pendingMessages));

        // Dispatch event for cross-tab communication
        window.dispatchEvent(new StorageEvent('storage', {
            key: 'kaspa_pending_messages',
            newValue: JSON.stringify(pendingMessages)
        }));
    }

    /**
     * Start polling for blockchain messages
     * @private
     */
    async startBlockchainPolling() {
        // Set up storage event listener for cross-tab communication
        window.addEventListener('storage', (event) => {
            if (event.key === 'kaspa_pending_messages') {
                this.processBlockchainMessages();
            }
        });

        // Also poll periodically
        this.pollingInterval = setInterval(() => {
            this.processBlockchainMessages();
        }, 3000); // Poll every 3 seconds

        // Process any existing messages
        await this.processBlockchainMessages();

        console.log('[KaspaService] Blockchain polling started');
    }

    /**
     * Process incoming blockchain messages
     * @private
     */
    async processBlockchainMessages() {
        try {
            const pendingMessages = JSON.parse(
                localStorage.getItem('kaspa_pending_messages') || '[]'
            );

            const processedIds = JSON.parse(
                localStorage.getItem('kaspa_processed_ids') || '[]'
            );

            // Debug logging
            if (pendingMessages.length > 0) {
                console.log('[KaspaService] Processing', pendingMessages.length, 'pending messages, my ID:', this.localPeerId);
            }

            for (const msg of pendingMessages) {
                // Skip already processed
                if (processedIds.includes(msg.txId)) {
                    continue;
                }

                // Skip messages from self
                if (msg.envelope.sender_peer_id === this.localPeerId) {
                    processedIds.push(msg.txId);
                    continue;
                }

                // Skip messages not for us (unless broadcast)
                const isForUs = !msg.envelope.recipient_peer_id ||
                               msg.envelope.recipient_peer_id === this.localPeerId;

                console.log('[KaspaService] Message from:', msg.envelope.sender_peer_id?.substring(0, 8),
                           'to:', msg.envelope.recipient_peer_id?.substring(0, 8) || 'broadcast',
                           'isForUs:', isForUs,
                           'type:', msg.envelope.envelope_type);

                if (!isForUs) {
                    continue;
                }

                // Process based on envelope type
                await this.handleBlockchainEnvelope(msg.envelope);

                // Mark as processed
                processedIds.push(msg.txId);
                this.stats.messages_received++;
            }

            // Save processed IDs (keep last 200)
            while (processedIds.length > 200) {
                processedIds.shift();
            }
            localStorage.setItem('kaspa_processed_ids', JSON.stringify(processedIds));

        } catch (error) {
            console.error('[KaspaService] Error processing blockchain messages:', error);
        }
    }

    /**
     * Handle an envelope received from the blockchain
     * @private
     */
    async handleBlockchainEnvelope(envelope) {
        console.log('[KaspaService] Received envelope type:', envelope.envelope_type);

        switch (envelope.envelope_type) {
            case 'PeerAnnouncement':
            case 2: // EnvelopeType::PeerAnnouncement
                await this.handlePeerAnnouncement(envelope);
                break;

            case 'SignalingOffer':
            case 3: // EnvelopeType::SignalingOffer
                await this.handleSignalingOffer(envelope);
                break;

            case 'SignalingAnswer':
            case 4: // EnvelopeType::SignalingAnswer
                await this.handleSignalingAnswer(envelope);
                break;

            case 'SignalingIce':
            case 5: // EnvelopeType::SignalingIce
                await this.handleSignalingIce(envelope);
                break;

            case 'DirectMessage':
            case 0: // EnvelopeType::DirectMessage
                await this.handleDirectMessage(envelope);
                break;

            default:
                console.warn('[KaspaService] Unknown envelope type:', envelope.envelope_type);
        }
    }

    /**
     * Handle peer announcement
     * @private
     */
    async handlePeerAnnouncement(envelope) {
        try {
            const announcement = JSON.parse(envelope.payload);

            console.log('[KaspaService] Peer discovered:', announcement.peer_id);

            // Track discovered peers locally (simple JS tracking for MVP)
            if (!this.discoveredPeers) {
                this.discoveredPeers = new Map();
            }
            this.discoveredPeers.set(announcement.peer_id, {
                peerId: announcement.peer_id,
                kaspaAddress: announcement.kaspa_address,
                publicKey: announcement.public_key,
                timestamp: envelope.timestamp,
                lastSeen: Date.now()
            });

            // Notify callback
            if (this.onPeerDiscovered) {
                this.onPeerDiscovered({
                    peerId: announcement.peer_id,
                    kaspaAddress: announcement.kaspa_address,
                    publicKey: announcement.public_key,
                    timestamp: envelope.timestamp
                });
            }
        } catch (error) {
            console.error('[KaspaService] Failed to handle peer announcement:', error);
        }
    }

    /**
     * Handle signaling offer
     * @private
     */
    async handleSignalingOffer(envelope) {
        try {
            const sdpData = JSON.parse(envelope.payload);

            console.log('[KaspaService] Received offer from:', envelope.sender_peer_id);

            // Notify callback
            if (this.onSignalingMessage) {
                this.onSignalingMessage({
                    type: 'offer',
                    fromPeerId: envelope.sender_peer_id,
                    sdp: sdpData.sdp,
                    sessionId: sdpData.session_id
                });
            }
        } catch (error) {
            console.error('[KaspaService] Failed to handle signaling offer:', error);
        }
    }

    /**
     * Handle signaling answer
     * @private
     */
    async handleSignalingAnswer(envelope) {
        try {
            const sdpData = JSON.parse(envelope.payload);

            console.log('[KaspaService] Received answer from:', envelope.sender_peer_id);

            // Notify callback
            if (this.onSignalingMessage) {
                this.onSignalingMessage({
                    type: 'answer',
                    fromPeerId: envelope.sender_peer_id,
                    sdp: sdpData.sdp,
                    sessionId: sdpData.session_id
                });
            }
        } catch (error) {
            console.error('[KaspaService] Failed to handle signaling answer:', error);
        }
    }

    /**
     * Handle ICE candidates
     * @private
     */
    async handleSignalingIce(envelope) {
        try {
            const iceData = JSON.parse(envelope.payload);

            console.log('[KaspaService] Received ICE from:', envelope.sender_peer_id);

            // Notify callback
            if (this.onSignalingMessage) {
                this.onSignalingMessage({
                    type: 'ice',
                    fromPeerId: envelope.sender_peer_id,
                    candidates: iceData.candidates,
                    sessionId: iceData.session_id
                });
            }
        } catch (error) {
            console.error('[KaspaService] Failed to handle ICE candidates:', error);
        }
    }

    /**
     * Handle direct message (fallback delivery)
     * @private
     */
    async handleDirectMessage(envelope) {
        try {
            const messagePayload = JSON.parse(envelope.payload);

            console.log('[KaspaService] Received message from:', envelope.sender_peer_id);

            // Notify callback
            if (this.onMessageReceived) {
                this.onMessageReceived({
                    fromPeerId: envelope.sender_peer_id,
                    payload: messagePayload,
                    timestamp: envelope.timestamp,
                    deliveryMethod: 'blockchain'
                });
            }
        } catch (error) {
            console.error('[KaspaService] Failed to handle direct message:', error);
        }
    }

    /**
     * Notify connection status change
     * @private
     */
    notifyStatusChange(status) {
        if (this.onConnectionStatusChanged) {
            this.onConnectionStatusChanged(status);
        }
    }

    /**
     * Get service statistics
     */
    getStats() {
        return {
            messagesSent: this.stats?.messages_sent || 0,
            messagesReceived: this.stats?.messages_received || 0,
            transactionsSubmitted: this.stats?.transactions_submitted || 0,
            isConnected: this.isConnected,
            peersDiscovered: this.getDiscoveredPeers().length,
            mode: this.mode,
            hasWallet: this.isWalletInitialized,
            walletAddress: this.kaspaAddress,
            offlineQueueSize: this.offlineQueue.length  // Number of messages waiting to be sent
        };
    }

    /**
     * Disconnect and cleanup
     */
    async disconnect() {
        // Flush any pending messages before disconnecting
        if (this.offlineQueue.length > 0) {
            console.log('[KaspaService] Flushing pending messages before disconnect...');
            await this.flushOfflineQueue();
        }

        // Clear intervals
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }

        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }

        // Disconnect from RPC if in testnet mode
        if (this.mode === 'testnet') {
            try {
                await this.wasmModule.kaspa_disconnect();
            } catch (error) {
                console.warn('[KaspaService] RPC disconnect error:', error);
            }
        }

        this.isConnected = false;
        this.notifyStatusChange('disconnected');

        console.log('[KaspaService] Disconnected');
    }

    /**
     * Convert KAS to sompis
     */
    kasToSompis(kas) {
        return this.wasmModule.kaspa_kas_to_sompis(kas);
    }

    /**
     * Convert sompis to KAS
     */
    sompisToKas(sompis) {
        return this.wasmModule.kaspa_sompis_to_kas(sompis);
    }

    /**
     * Get dust amount constant
     */
    getDustAmount() {
        return this.wasmModule.kaspa_get_dust_amount();
    }

    /**
     * Get max payload size constant
     */
    getMaxPayloadSize() {
        return this.wasmModule.kaspa_get_max_payload_size();
    }

    /**
     * Get current operating mode
     */
    getMode() {
        return this.mode;
    }
}

/**
 * Create a new Kaspa service instance
 */
export function createKaspaService(wasmModule) {
    return new KaspaService(wasmModule);
}
