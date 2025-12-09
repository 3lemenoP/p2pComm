/**
 * WebRTC Bridge for p2pComm
 *
 * Manages WebRTC peer-to-peer connections with manual signaling.
 * Integrates with WASM network module for message handling.
 */

export class WebRTCBridge {
    constructor(wasmModule) {
        this.wasmModule = wasmModule;
        this.connections = new Map(); // peerId -> WebRTCConnection
        this.localPeerId = null;
    }

    /**
     * Initialize the bridge with local peer ID
     */
    setLocalPeerId(peerId) {
        this.localPeerId = peerId;
    }

    /**
     * Create a new WebRTC offer for manual signaling
     * Returns: { peerId, sdp, type: 'offer' }
     */
    async createOffer(remotePeerId) {
        console.log(`Creating offer for remote peer: ${remotePeerId}`);
        console.log(`My local peer ID: ${this.localPeerId}`);

        if (this.connections.has(remotePeerId)) {
            throw new Error(`Already have connection to ${remotePeerId}`);
        }

        const connection = new WebRTCConnection(
            this.localPeerId,
            remotePeerId,
            this.wasmModule,
            () => this.handleConnectionClosed(remotePeerId)
        );

        this.connections.set(remotePeerId, connection);
        console.log(`Stored connection with key: ${remotePeerId}`);

        const offer = await connection.createOffer();
        return {
            peerId: this.localPeerId,
            remotePeerId: remotePeerId,
            sdp: offer.sdp,
            type: 'offer'
        };
    }

    /**
     * Handle incoming offer and create answer for manual signaling
     * Returns: { peerId, sdp, type: 'answer' }
     */
    async handleOffer(offerData) {
        const remotePeerId = offerData.peerId;

        if (this.connections.has(remotePeerId)) {
            console.warn(`Already have connection to ${remotePeerId}, replacing`);
            await this.disconnect(remotePeerId);
        }

        const connection = new WebRTCConnection(
            this.localPeerId,
            remotePeerId,
            this.wasmModule,
            () => this.handleConnectionClosed(remotePeerId)
        );

        this.connections.set(remotePeerId, connection);

        const answer = await connection.handleOffer({
            type: 'offer',
            sdp: offerData.sdp
        });

        return {
            peerId: this.localPeerId,
            remotePeerId: remotePeerId,
            sdp: answer.sdp,
            type: 'answer'
        };
    }

    /**
     * Handle incoming answer to complete connection
     */
    async handleAnswer(answerData) {
        // The answer includes:
        // - peerId: the answerer's (remote peer's) local peer ID
        // - remotePeerId: who the answer is for (should be us)
        // We need to look up the connection by the remote peer's ID
        const remotePeerId = answerData.peerId;  // The peer who generated the answer

        console.log(`Looking for connection to ${remotePeerId}`);
        console.log(`Active connections:`, Array.from(this.connections.keys()));

        const connection = this.connections.get(remotePeerId);

        if (!connection) {
            throw new Error(`No pending connection for ${remotePeerId}`);
        }

        await connection.handleAnswer({
            type: 'answer',
            sdp: answerData.sdp
        });
    }

    /**
     * Send message to a peer
     */
    send(peerId, bytes) {
        const connection = this.connections.get(peerId);
        if (!connection) {
            throw new Error(`No connection to ${peerId}`);
        }
        connection.send(bytes);
    }

    /**
     * Get connection status for a peer
     */
    getConnectionStatus(peerId) {
        const connection = this.connections.get(peerId);
        return connection ? connection.getStatus() : 'disconnected';
    }

    /**
     * Disconnect from a peer
     */
    async disconnect(peerId) {
        const connection = this.connections.get(peerId);
        if (connection) {
            await connection.close();
            this.connections.delete(peerId);
        }
    }

    /**
     * Handle connection closed event
     */
    handleConnectionClosed(peerId) {
        console.log(`Connection to ${peerId} closed`);
        this.connections.delete(peerId);

        // Notify WASM network manager
        try {
            this.wasmModule.network_disconnect_peer(peerId);
        } catch (error) {
            console.error('Error notifying WASM of disconnect:', error);
        }
    }

    /**
     * Get all active connections
     */
    getActiveConnections() {
        return Array.from(this.connections.keys());
    }
}

/**
 * WebRTCConnection manages a single peer-to-peer connection
 */
class WebRTCConnection {
    constructor(localPeerId, remotePeerId, wasmModule, onClose) {
        this.localPeerId = localPeerId;
        this.remotePeerId = remotePeerId;
        this.wasmModule = wasmModule;
        this.onCloseCallback = onClose;

        this.peerConnection = null;
        this.dataChannel = null;
        this.status = 'disconnected';
        this.messageQueue = [];
        this.iceCandidates = [];

        this.initPeerConnection();
    }

    /**
     * Initialize RTCPeerConnection
     */
    initPeerConnection() {
        // WebRTC configuration with free STUN server
        const config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };

        this.peerConnection = new RTCPeerConnection(config);
        this.status = 'connecting';

        // ICE candidate handling (for manual signaling, we gather all candidates first)
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.iceCandidates.push(event.candidate);
            }
        };

        // Connection state monitoring
        this.peerConnection.onconnectionstatechange = () => {
            console.log(`Connection state: ${this.peerConnection.connectionState}`);

            switch (this.peerConnection.connectionState) {
                case 'connected':
                    this.status = 'connected';
                    this.flushMessageQueue();
                    // Notify WASM that connection is established
                    try {
                        this.wasmModule.network_mark_connected(this.remotePeerId);
                    } catch (error) {
                        console.error('Error marking connection as connected:', error);
                    }
                    break;
                case 'disconnected':
                case 'failed':
                case 'closed':
                    this.status = 'disconnected';
                    if (this.onCloseCallback) {
                        this.onCloseCallback();
                    }
                    break;
            }
        };

        // Handle incoming data channels (for answer side)
        this.peerConnection.ondatachannel = (event) => {
            console.log('Received data channel from remote peer');
            this.dataChannel = event.channel;
            this.setupDataChannel();
        };
    }

    /**
     * Create WebRTC offer
     */
    async createOffer() {
        // Create data channel (offer side creates the channel)
        this.dataChannel = this.peerConnection.createDataChannel('p2pcomm-data', {
            ordered: true,
            maxRetransmits: 3
        });
        this.setupDataChannel();

        // Create and set local description
        const offer = await this.peerConnection.createOffer();
        await this.peerConnection.setLocalDescription(offer);

        // Wait for ICE gathering to complete
        await this.waitForICEGathering();

        return this.peerConnection.localDescription;
    }

    /**
     * Handle incoming offer and create answer
     */
    async handleOffer(offer) {
        await this.peerConnection.setRemoteDescription(offer);

        const answer = await this.peerConnection.createAnswer();
        await this.peerConnection.setLocalDescription(answer);

        // Wait for ICE gathering to complete
        await this.waitForICEGathering();

        return this.peerConnection.localDescription;
    }

    /**
     * Handle incoming answer
     */
    async handleAnswer(answer) {
        await this.peerConnection.setRemoteDescription(answer);
    }

    /**
     * Wait for ICE gathering to complete
     * For manual signaling, we want all ICE candidates included in the SDP
     */
    waitForICEGathering() {
        return new Promise((resolve) => {
            if (this.peerConnection.iceGatheringState === 'complete') {
                resolve();
                return;
            }

            const checkState = () => {
                if (this.peerConnection.iceGatheringState === 'complete') {
                    this.peerConnection.removeEventListener('icegatheringstatechange', checkState);
                    resolve();
                }
            };

            this.peerConnection.addEventListener('icegatheringstatechange', checkState);

            // Timeout after 5 seconds
            setTimeout(() => {
                this.peerConnection.removeEventListener('icegatheringstatechange', checkState);
                resolve();
            }, 5000);
        });
    }

    /**
     * Setup data channel event handlers
     */
    setupDataChannel() {
        if (!this.dataChannel) return;

        // Set binary type to arraybuffer for better performance
        this.dataChannel.binaryType = 'arraybuffer';

        this.dataChannel.onopen = () => {
            console.log(`Data channel opened to ${this.remotePeerId}`);
            this.status = 'connected';

            // Register peer with network manager
            try {
                this.wasmModule.network_connect_peer(this.remotePeerId);
                this.wasmModule.network_mark_connected(this.remotePeerId);
                console.log(`Registered peer ${this.remotePeerId} with network manager`);
            } catch (error) {
                console.error('Error registering peer with network manager:', error);
            }

            this.flushMessageQueue();
        };

        this.dataChannel.onclose = () => {
            console.log(`Data channel closed to ${this.remotePeerId}`);
            this.status = 'disconnected';
        };

        this.dataChannel.onerror = (error) => {
            console.error(`Data channel error:`, error);
        };

        this.dataChannel.onmessage = (event) => {
            this.handleIncomingMessage(event.data);
        };
    }

    /**
     * Handle incoming message from data channel
     */
    async handleIncomingMessage(data) {
        try {
            // Convert to Uint8Array - handle both ArrayBuffer and Blob
            let bytes;
            if (data instanceof ArrayBuffer) {
                bytes = new Uint8Array(data);
            } else if (data instanceof Blob) {
                const arrayBuffer = await data.arrayBuffer();
                bytes = new Uint8Array(arrayBuffer);
            } else {
                console.error('Unexpected data type:', typeof data);
                return;
            }

            // Pass to WASM network manager for processing
            await this.wasmModule.network_handle_incoming(this.remotePeerId, bytes);
        } catch (error) {
            console.error('Error handling incoming message:', error);
        }
    }

    /**
     * Send message through data channel
     */
    send(bytes) {
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            // Queue message if not connected
            console.log('Data channel not open, queueing message');
            this.messageQueue.push(bytes);
            return;
        }

        try {
            this.dataChannel.send(bytes);
        } catch (error) {
            console.error('Error sending message:', error);
            // Re-queue on error
            this.messageQueue.push(bytes);
        }
    }

    /**
     * Flush queued messages
     */
    flushMessageQueue() {
        if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
            return;
        }

        console.log(`Flushing ${this.messageQueue.length} queued messages`);
        while (this.messageQueue.length > 0) {
            const message = this.messageQueue.shift();
            try {
                this.dataChannel.send(message);
            } catch (error) {
                console.error('Error flushing message:', error);
                // Put it back and stop
                this.messageQueue.unshift(message);
                break;
            }
        }
    }

    /**
     * Get connection status
     */
    getStatus() {
        if (this.peerConnection) {
            const pcState = this.peerConnection.connectionState;
            if (pcState === 'connected' && this.dataChannel?.readyState === 'open') {
                return 'connected';
            }
            return pcState;
        }
        return this.status;
    }

    /**
     * Close connection
     */
    async close() {
        if (this.dataChannel) {
            this.dataChannel.close();
        }
        if (this.peerConnection) {
            this.peerConnection.close();
        }
        this.status = 'closed';
    }
}

// Export singleton instance creation helper
export function createWebRTCBridge(wasmModule) {
    return new WebRTCBridge(wasmModule);
}
