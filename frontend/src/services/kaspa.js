/**
 * Kaspa Blockchain Service for p2pComm
 *
 * Provides decentralized peer discovery and signaling through the Kaspa blockchain.
 * This is a thin wrapper around the WASM unified service layer (p2pcomm_*).
 *
 * Key capabilities:
 * 1. Automatic WebRTC signaling via blockchain transactions
 * 2. Peer discovery through blockchain announcements
 * 3. Fallback message delivery when WebRTC is unavailable
 */

// Default testnet RPC endpoint
const DEFAULT_TESTNET_RPC = 'ws://135.181.102.1:17110';

export class KaspaService {
    constructor(wasmModule) {
        this.wasmModule = wasmModule;
        this.localPeerId = null;
        this.kaspaAddress = null;

        // Service state
        this.isConnected = false;
        this.isWalletInitialized = false;
        this.pollingInterval = null;

        // Callbacks
        this.onPeerDiscovered = null;
        this.onSignalingMessage = null;
        this.onMessageReceived = null;
        this.onConnectionStatusChanged = null;
        this.onWalletInitialized = null;
        this.onBalanceChanged = null;
        this.onDeliveryConfirmation = null;
        this.onResolveRecipientAddress = null;

        // Prevent double announcement
        this.hasAnnounced = false;
    }

    /**
     * Initialize the Kaspa service using the unified WASM service layer
     * @param {string} localPeerId - The local peer ID
     * @param {string} kaspaAddress - Ignored (derived from password)
     * @param {Object} options - Configuration options
     * @param {string} options.password - Wallet password (required)
     * @param {string} options.rpcEndpoint - Optional RPC endpoint override
     */
    async initialize(localPeerId, kaspaAddress, options = {}) {
        this.localPeerId = localPeerId;
        const password = options.password;

        if (!password) {
            throw new Error('Password required for Kaspa wallet');
        }

        try {
            console.log('[KaspaService] Initializing via unified service...');

            // Use the unified WASM service initialization
            const config = {
                peer_id: localPeerId,
                password: password,
                is_testnet: true,
                auto_connect_rpc: true,
                auto_start_utxo_monitor: true,
                utxo_poll_interval_ms: 3000
            };

            await this.wasmModule.p2pcomm_init(config);

            // Get wallet info from the initialized service
            const stats = await this.wasmModule.p2pcomm_get_stats();
            if (stats) {
                this.kaspaAddress = this.wasmModule.kaspa_wallet_get_primary_address?.() || null;
                this.isWalletInitialized = true;

                console.log('[KaspaService] Wallet initialized');
                console.log('[KaspaService] Primary address:', this.kaspaAddress);

                if (this.onWalletInitialized) {
                    this.onWalletInitialized({
                        primary_address: this.kaspaAddress
                    });
                }
            }

            // Start polling for blockchain messages
            this.startBlockchainPolling();

            this.isConnected = true;
            this.notifyStatusChange('connected');

            console.log('[KaspaService] Initialization complete');
            return true;
        } catch (error) {
            console.error('[KaspaService] Initialization failed:', error);
            this.notifyStatusChange('error');
            throw error;
        }
    }

    /**
     * Refresh wallet balance
     */
    async refreshBalance() {
        if (!this.isWalletInitialized || !this.kaspaAddress) {
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

        if (this.hasAnnounced) {
            console.log('[KaspaService] Already announced presence, skipping');
            return true;
        }

        try {
            // Create announcement payload
            const announcementJson = JSON.stringify({
                peer_id: this.localPeerId,
                kaspa_address: this.kaspaAddress,
                public_key: publicKey
            });

            // Queue announcement via delivery coordinator
            await this.wasmModule.delivery_coordinator_queue_announcement(
                this.localPeerId,
                announcementJson
            );

            // Process immediately
            await this.wasmModule.delivery_coordinator_flush_all();
            const batches = await this.wasmModule.delivery_coordinator_get_ready_batches();

            // Submit batches
            for (const batch of batches || []) {
                await this.submitBatch(batch);
            }

            this.hasAnnounced = true;
            console.log('[KaspaService] Presence announced on blockchain');
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
            const sdpJson = JSON.stringify({
                type: 'offer',
                sdp: sdp,
                session_id: sessionId
            });

            await this.wasmModule.delivery_coordinator_queue_signaling(
                this.localPeerId,
                remotePeerId,
                3, // SignalingOffer
                sdpJson
            );

            // Flush and submit immediately (signaling is time-sensitive)
            await this.flushAndSubmitPending();

            console.log('[KaspaService] Offer sent via blockchain to:', remotePeerId);
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

            await this.wasmModule.delivery_coordinator_queue_signaling(
                this.localPeerId,
                remotePeerId,
                4, // SignalingAnswer
                sdpJson
            );

            await this.flushAndSubmitPending();

            console.log('[KaspaService] Answer sent via blockchain to:', remotePeerId);
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

            await this.wasmModule.delivery_coordinator_queue_signaling(
                this.localPeerId,
                remotePeerId,
                5, // SignalingIce
                iceJson
            );

            await this.flushAndSubmitPending();

            console.log('[KaspaService] ICE candidates sent via blockchain to:', remotePeerId);
            return true;
        } catch (error) {
            console.error('[KaspaService] Failed to send ICE candidates:', error);
            throw error;
        }
    }

    /**
     * Send a direct message via blockchain (fallback when WebRTC unavailable)
     */
    async sendMessage(remotePeerId, messagePayload, options = {}) {
        if (!this.isConnected) {
            throw new Error('Kaspa service not connected');
        }

        try {
            const immediate = options.immediate || false;

            const messageId = await this.wasmModule.delivery_coordinator_queue_direct_message(
                this.localPeerId,
                remotePeerId,
                JSON.stringify(messagePayload),
                immediate
            );

            console.log('[KaspaService] Message queued for blockchain delivery:', messageId);

            // If immediate, flush now
            if (immediate) {
                await this.flushAndSubmitPending();
            }

            return messageId;
        } catch (error) {
            console.error('[KaspaService] Failed to send message:', error);
            throw error;
        }
    }

    /**
     * Flush pending batches and submit to blockchain
     * @private
     */
    async flushAndSubmitPending() {
        await this.wasmModule.delivery_coordinator_flush_all();
        const batches = await this.wasmModule.delivery_coordinator_get_ready_batches();

        for (const batch of batches || []) {
            await this.submitBatch(batch);
        }
    }

    /**
     * Submit a batch to the blockchain
     * @private
     */
    async submitBatch(batch) {
        try {
            // Combine messages into payload
            const payloads = batch.messages.map(msg => {
                const bytes = this.wasmModule.serialize_envelope(msg.envelope);
                return Array.from(bytes);
            });

            // Get recipient address
            let recipientAddress = this.kaspaAddress;
            if (batch.recipient && this.onResolveRecipientAddress) {
                const resolved = this.onResolveRecipientAddress(batch.recipient);
                if (resolved) recipientAddress = resolved;
            }

            // Get UTXOs
            this.wasmModule.kaspa_wallet_clear_utxos?.();
            const utxos = await this.wasmModule.kaspa_get_utxos(this.kaspaAddress);

            if (!utxos || utxos.length === 0) {
                console.warn('[KaspaService] No UTXOs available');
                return false;
            }

            // Store UTXOs for signing
            const utxosWithAddress = utxos.map(utxo => ({
                ...utxo,
                address: utxo.address || this.kaspaAddress
            }));
            this.wasmModule.kaspa_wallet_add_utxos_batch?.(JSON.stringify(utxosWithAddress));

            // Combine all payloads for the batch
            const combinedPayload = payloads.flat();

            // Build transaction
            const builtTx = this.wasmModule.kaspa_build_payload_transaction(
                JSON.stringify(utxos),
                recipientAddress,
                this.kaspaAddress,
                combinedPayload
            );

            // Sign and submit
            const signedTxJson = await this.wasmModule.kaspa_sign_transaction(builtTx.transaction_json);
            const txId = await this.wasmModule.kaspa_submit_transaction(signedTxJson);

            console.log('[KaspaService] Batch submitted, txId:', txId);

            // Record success
            await this.wasmModule.delivery_coordinator_record_success(batch.batch_id, builtTx.fee || 0);

            // Notify delivery confirmations
            for (const msg of batch.messages) {
                if (this.onDeliveryConfirmation) {
                    this.onDeliveryConfirmation({
                        messageId: msg.id,
                        status: 'submitted',
                        txId: txId
                    });
                }
            }

            return true;
        } catch (error) {
            console.error('[KaspaService] Batch submission failed:', error);
            await this.wasmModule.delivery_coordinator_record_failure?.();
            return false;
        }
    }

    /**
     * Start polling for blockchain messages
     * @private
     */
    startBlockchainPolling() {
        this.pollingInterval = setInterval(() => {
            this.processBlockchainMessages();
        }, 3000);

        // Initial poll
        this.processBlockchainMessages();
        console.log('[KaspaService] Blockchain polling started');
    }

    /**
     * Process incoming blockchain messages using unified service
     * @private
     */
    async processBlockchainMessages() {
        if (!this.kaspaAddress) return;

        try {
            // Use unified process cycle
            const result = await this.wasmModule.p2pcomm_process_cycle();

            // Get received messages
            const receivedMessages = await this.wasmModule.message_handler_pop_received?.();
            const signalingMessages = await this.wasmModule.message_handler_pop_signaling?.();

            // Route received messages to callback
            if (receivedMessages && receivedMessages.length > 0) {
                console.log(`[KaspaService] Processing ${receivedMessages.length} received messages`);
                for (const msg of receivedMessages) {
                    if (this.onMessageReceived) {
                        this.onMessageReceived(msg);
                    }
                }
            }

            // Route signaling messages to callback
            if (signalingMessages && signalingMessages.length > 0) {
                console.log(`[KaspaService] Processing ${signalingMessages.length} signaling messages`);
                for (const sig of signalingMessages) {
                    if (this.onSignalingMessage) {
                        this.onSignalingMessage(sig);
                    }
                }
            }

            // Process any pending batches
            await this.wasmModule.delivery_coordinator_process_waiting_batches?.();
            const readyBatches = await this.wasmModule.delivery_coordinator_get_ready_batches?.();

            if (readyBatches && readyBatches.length > 0) {
                for (const batch of readyBatches) {
                    await this.submitBatch(batch);
                }
            }

        } catch (error) {
            console.error('[KaspaService] Error processing blockchain messages:', error);
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
     * Get discovered peers from blockchain
     */
    getDiscoveredPeers() {
        try {
            const peers = this.wasmModule.kaspa_discovery_get_peers?.();
            return peers || [];
        } catch {
            return [];
        }
    }

    /**
     * Get service statistics
     */
    async getStats() {
        try {
            const stats = await this.wasmModule.p2pcomm_get_stats();
            return {
                ...stats,
                isConnected: this.isConnected,
                hasWallet: this.isWalletInitialized,
                walletAddress: this.kaspaAddress
            };
        } catch {
            return {
                isConnected: this.isConnected,
                hasWallet: this.isWalletInitialized,
                walletAddress: this.kaspaAddress
            };
        }
    }

    /**
     * Disconnect and cleanup
     */
    async disconnect() {
        // Flush pending messages
        try {
            await this.flushAndSubmitPending();
        } catch (e) {
            console.warn('[KaspaService] Error flushing pending:', e);
        }

        // Stop polling
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }

        // Stop WASM service
        try {
            await this.wasmModule.p2pcomm_stop?.();
            await this.wasmModule.kaspa_disconnect?.();
        } catch (e) {
            console.warn('[KaspaService] Error stopping service:', e);
        }

        this.isConnected = false;
        this.notifyStatusChange('disconnected');
        console.log('[KaspaService] Disconnected');
    }

    // Utility methods delegated to WASM
    kasToSompis(kas) {
        return this.wasmModule.kaspa_kas_to_sompis?.(kas) || BigInt(kas * 100000000);
    }

    sompisToKas(sompis) {
        return this.wasmModule.kaspa_sompis_to_kas?.(sompis) || Number(sompis) / 100000000;
    }

    getDustAmount() {
        return this.wasmModule.kaspa_get_dust_amount?.() || 25000000n;
    }

    getMaxPayloadSize() {
        return this.wasmModule.kaspa_get_max_payload_size?.() || 98000;
    }
}

/**
 * Create a new Kaspa service instance
 */
export function createKaspaService(wasmModule) {
    return new KaspaService(wasmModule);
}
