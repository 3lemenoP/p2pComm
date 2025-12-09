import init, * as p2p from './wasm/wasm_core.js';
import { createWebRTCBridge } from './services/webrtc.js';
import { createKaspaService } from './services/kaspa.js';

// Global state
let wasmModule = null;
let webrtcBridge = null;
let kaspaService = null;
let currentIdentity = null;
let currentContact = null;
let contacts = [];
let conversations = new Map();
let kaspaEnabled = true; // Toggle for Kaspa blockchain integration
let pendingDeepLink = null; // Store deep link to process after init

// ========================================
// DEEP LINK / SHAREABLE URL FUNCTIONS
// ========================================

/**
 * Parse URL hash for deep links
 * Supported formats:
 * - #/add-contact/<base64-encoded-public-identity>
 * - #/connect/<base64-encoded-offer-data>
 * - #/answer/<base64-encoded-answer-data>
 */
function parseUrlHash() {
    const hash = window.location.hash;
    if (!hash || hash.length < 10) return null;

    try {
        if (hash.startsWith('#/add-contact/')) {
            const encoded = hash.substring(14);
            const data = JSON.parse(atob(encoded));
            return { type: 'add-contact', data };
        }
        if (hash.startsWith('#/connect/')) {
            const encoded = hash.substring(10);
            const data = JSON.parse(atob(encoded));
            return { type: 'connect', data };
        }
        if (hash.startsWith('#/answer/')) {
            const encoded = hash.substring(9);
            const data = JSON.parse(atob(encoded));
            return { type: 'answer', data };
        }
    } catch (error) {
        console.error('Failed to parse deep link:', error);
    }
    return null;
}

/**
 * Generate shareable link to add this user as a contact
 */
function generateContactLink() {
    const publicIdentity = getPublicIdentity();
    const encoded = btoa(JSON.stringify(publicIdentity));
    return `${window.location.origin}${window.location.pathname}#/add-contact/${encoded}`;
}

/**
 * Generate shareable link with WebRTC offer for direct connection
 */
async function generateOfferLink(contactPeerId) {
    const offer = await webrtcBridge.createOffer(contactPeerId);
    const publicIdentity = getPublicIdentity();
    const data = {
        offer: offer,
        identity: publicIdentity
    };
    const encoded = btoa(JSON.stringify(data));
    return `${window.location.origin}${window.location.pathname}#/connect/${encoded}`;
}

/**
 * Get public identity for sharing (no private keys)
 */
function getPublicIdentity() {
    const peerId = currentIdentity.peer_id || currentIdentity.peerId;

    // Build base public identity
    const publicIdentity = {
        peer_id: {
            hash: {
                bytes: Array.from(hexToBytes(peerId))
            }
        },
        display_name: currentIdentity.display_name,
        signing_public_key: Array.from(hexToBytes(currentIdentity.keypair.signing.public_key)),
        encryption_public_key: Array.from(hexToBytes(currentIdentity.keypair.encryption.public_key))
    };

    // Add Kaspa address if wallet is connected
    if (kaspaService && kaspaService.kaspaAddress) {
        publicIdentity.kaspa_address = kaspaService.kaspaAddress;
    }

    return publicIdentity;
}


/**
 * Handle deep links after app initialization
 */
async function handleDeepLink(deepLink) {
    if (!deepLink) return;

    // Clear the URL hash to prevent re-processing
    history.replaceState(null, '', window.location.pathname + window.location.search);

    if (deepLink.type === 'add-contact') {
        await handleAddContactDeepLink(deepLink.data);
    } else if (deepLink.type === 'connect') {
        await handleConnectDeepLink(deepLink.data);
    } else if (deepLink.type === 'answer') {
        await handleAnswerDeepLink(deepLink.data);
    }
}

/**
 * Handle add-contact deep link
 */
async function handleAddContactDeepLink(publicIdentity) {
    try {
        // Convert peer_id bytes to hex
        const peerIdBytes = publicIdentity.peer_id?.hash?.bytes || publicIdentity.peer_id;
        const peerId = Array.isArray(peerIdBytes) ? bytesToHex(new Uint8Array(peerIdBytes)) : peerIdBytes;

        // Check if contact already exists
        const existing = contacts.find(c => c.peerId === peerId);
        if (existing) {
            // Update kaspa address if provided (contact may have added wallet since last share)
            if (publicIdentity.kaspa_address && existing.kaspaAddress !== publicIdentity.kaspa_address) {
                existing.kaspaAddress = publicIdentity.kaspa_address;
                localStorage.setItem(window.contactsKey || 'p2pcomm_contacts', JSON.stringify(contacts));
                showNotification(`Updated Kaspa address for "${existing.displayName}"`, 'success');
            } else {
                showNotification(`Contact "${existing.displayName}" already exists`, 'info');
            }
            // Select the existing contact
            openConversation(existing);
            return;
        }


        // Add new contact
        const newContact = {
            peerId: peerId,
            displayName: publicIdentity.display_name || 'Unknown',
            signingPublicKey: bytesToHex(new Uint8Array(publicIdentity.signing_public_key)),
            encryptionPublicKey: bytesToHex(new Uint8Array(publicIdentity.encryption_public_key)),
            kaspaAddress: publicIdentity.kaspa_address || null, // Store Kaspa address for blockchain messaging
            verified: true,
            addedAt: Date.now()
        };


        contacts.push(newContact);
        localStorage.setItem(window.contactsKey || 'p2pcomm_contacts', JSON.stringify(contacts));
        renderConversations();

        showNotification(`Added contact: ${newContact.displayName}`, 'success');
        openConversation(newContact);

    } catch (error) {
        console.error('Failed to add contact from link:', error);
        showNotification('Failed to add contact from link', 'error');
    }
}

/**
 * Handle connect deep link (WebRTC offer)
 */
async function handleConnectDeepLink(data) {
    console.log('=== handleConnectDeepLink called ===');
    console.log('Data received:', JSON.stringify(data, null, 2).substring(0, 500));

    try {
        const { offer, identity } = data;

        // First add the contact if not exists
        await handleAddContactDeepLink(identity);

        // Find the contact
        const peerIdBytes = identity.peer_id?.hash?.bytes || identity.peer_id;
        const peerId = Array.isArray(peerIdBytes) ? bytesToHex(new Uint8Array(peerIdBytes)) : peerIdBytes;
        const contact = contacts.find(c => c.peerId === peerId);

        if (!contact) {
            showNotification('Failed to find contact for connection', 'error');
            return;
        }

        // Show notification
        showNotification(`Connection request from ${contact.displayName}`, 'info');

        // Auto-handle the WebRTC offer
        const answerData = await webrtcBridge.handleOffer({
            peerId: peerId,
            sdp: offer.sdp
        });

        if (answerData) {
            // If Kaspa is available, send answer via blockchain
            if (kaspaService && kaspaService.isConnected) {
                await kaspaService.sendAnswer(peerId, answerData.sdp, answerData.sessionId || generateId());
                showNotification('Connection answer sent via blockchain', 'success');

                // Open the conversation with this contact
                openConversation(contact);
            } else {
                // Generate answer link for User B to send back to User A
                const answerLink = generateAnswerLink(peerId, answerData);

                // LOG: Verify the answer link format
                console.log('=== ANSWER LINK GENERATED (User B side) ===');
                console.log('Answer link URL (first 150 chars):', answerLink.substring(0, 150));
                console.log('Link contains #/answer/:', answerLink.includes('#/answer/'));
                console.log('Link contains #/connect/:', answerLink.includes('#/connect/'));

                // Store the answer link for the copy button
                window.pendingAnswerLink = answerLink;
                window.pendingAnswerContact = contact;

                // AUTO-COPY the answer link to clipboard
                try {
                    console.log('Copying answer link to clipboard...');
                    await copyToClipboard(answerLink);
                    console.log('Answer link copied successfully!');

                    // Show prominent alert that REQUIRES action
                    alert(`⚠️ IMPORTANT: Connection answer copied to clipboard!\n\nYou MUST send this link back to ${contact.displayName} to complete the connection.\n\nWithout this step, neither of you can send messages.\n\n[DEBUG] URL includes #/answer/: ${answerLink.includes('#/answer/')}`);

                    showNotification('Answer link copied! Send it back to complete connection.', 'success');
                } catch (err) {
                    console.error('Failed to copy to clipboard:', err);
                    // Fallback if clipboard fails - show modal
                    showNotification('Copy the answer link below and send it back!', 'warning');
                }

                // Also show modal with the answer for manual copy if needed
                setTimeout(() => {
                    const answerOutput = document.getElementById('answerOutput');
                    const answerText = document.getElementById('answerText');
                    if (answerOutput && answerText) {
                        answerText.value = `⚠️ SEND THIS BACK TO ${contact.displayName.toUpperCase()}:\n\n${answerLink}`;
                        answerOutput.style.display = 'block';
                    }
                    document.getElementById('connectModal').classList.add('active');
                }, 100);

                // Open the conversation so user sees who they're connecting to
                openConversation(contact);
            }
        }

    } catch (error) {
        console.error('Failed to handle connect link:', error);
        showNotification('Failed to process connection request', 'error');
    }
}

/**
 * Handle answer deep link (complete WebRTC connection)
 * This is called on User A's side when they click an answer link from User B
 */
async function handleAnswerDeepLink(data) {
    try {
        console.log('=== handleAnswerDeepLink called ===');
        console.log('Data received:', JSON.stringify(data, null, 2).substring(0, 500));

        // Support both old format (peerId) and new format (answererPeerId)
        const answererPeerId = data.answererPeerId || data.peerId;
        const answer = data.answer;
        const identity = data.identity;

        console.log('Parsed answer data:', {
            answererPeerId,
            hasAnswer: !!answer,
            hasIdentity: !!identity,
            answerSdpPreview: answer?.sdp?.substring(0, 100)
        });

        // First check if we have a pending connection for this peer
        const activeConnections = webrtcBridge.getActiveConnections();
        console.log('Active WebRTC connections:', activeConnections);

        if (!activeConnections.includes(answererPeerId)) {
            // No pending connection - this can happen if:
            // 1. User A generated the offer but then reloaded the page
            // 2. User A opened the answer link in a new tab
            // 3. Too much time passed and the connection timed out

            console.error('No pending connection for peer:', answererPeerId);
            console.error('This usually means the page was reloaded after generating the offer.');

            showNotification(
                '⚠️ Connection expired! The original offer is no longer valid. ' +
                'Please generate a new connection link and try again.',
                'error'
            );

            // Still add the contact if we have their identity
            if (identity) {
                await handleAddContactDeepLink(identity);
            }

            // Open conversation so they can easily reconnect
            const contact = contacts.find(c => c.peerId === answererPeerId);
            if (contact) {
                openConversation(contact);
                showNotification(`Open the Connect dialog to create a new connection with ${contact.displayName}`, 'info');
            }
            return;
        }

        // Add contact if identity is included and not already added
        if (identity) {
            await handleAddContactDeepLink(identity);
        }

        // Find the contact (User B) in our contacts list
        const contact = contacts.find(c => c.peerId === answererPeerId);
        if (!contact) {
            showNotification('Unknown peer - add them as a contact first', 'error');
            console.error('Could not find contact with peerId:', answererPeerId);
            console.error('Available contacts:', contacts.map(c => c.peerId));
            return;
        }

        showNotification(`Completing connection with ${contact.displayName}...`, 'info');

        // Import the answer to complete the WebRTC connection
        console.log('Calling webrtcBridge.handleAnswer with peerId:', answererPeerId);

        await webrtcBridge.handleAnswer({
            peerId: answererPeerId,
            sdp: answer.sdp
        });

        showNotification(`Connected to ${contact.displayName}!`, 'success');
        openConversation(contact);

    } catch (error) {
        console.error('Failed to handle answer link:', error);
        showNotification('Failed to complete connection: ' + error.message, 'error');
    }
}

/**
 * Generate answer link for manual sharing
 * @param {string} offerSenderPeerId - The peer ID of the person who sent the offer (User A)
 * @param {object} answerData - The answer SDP data from webrtcBridge.handleOffer
 */
function generateAnswerLink(offerSenderPeerId, answerData) {
    const publicIdentity = getPublicIdentity();
    // The answer link contains:
    // - answererPeerId: OUR peer ID (User B) so User A can find us in their contacts
    // - offerSenderPeerId: User A's peer ID so we know who to look up the connection for
    // - answer: The SDP answer data
    // - identity: Our public identity so User A can verify us
    const myPeerId = currentIdentity.peer_id || currentIdentity.peerId;
    const data = {
        answererPeerId: myPeerId,  // User B's peerId - for User A to find User B in contacts
        offerSenderPeerId: offerSenderPeerId,  // User A's peerId - for webrtcBridge lookup
        answer: answerData,
        identity: publicIdentity  // User B's identity so User A can verify
    };
    const encoded = btoa(JSON.stringify(data));
    const answerUrl = `${window.location.origin}${window.location.pathname}#/answer/${encoded}`;
    console.log('=== generateAnswerLink ===');
    console.log('Generated answer URL starts with:', answerUrl.substring(0, 100));
    console.log('URL contains #/answer/:', answerUrl.includes('#/answer/'));
    return answerUrl;
}

// Initialize application
async function initApp() {
    try {
        // Parse deep link early (before init completes)
        pendingDeepLink = parseUrlHash();
        if (pendingDeepLink) {
            console.log('Deep link detected:', pendingDeepLink.type);
        }

        showNotification('Initializing p2pComm...', 'info');

        // Initialize WASM module
        await init();
        wasmModule = p2p;
        console.log('WASM module loaded, version:', wasmModule.get_version());

        // Check for existing identity or create new one
        await loadOrCreateIdentity();

        // Initialize network manager
        // IMPORTANT: Derive correct peer_id from signing public key (Blake3 hash)
        // Don't trust the peer_id stored in identity (may be old incorrect format)
        const signingPublicKey = currentIdentity.keypair.signing.public_key;
        const myPeerId = wasmModule.derive_peer_id_from_public_key(signingPublicKey);
        console.log('Using derived peer_id:', myPeerId);

        // Update identity with correct peer_id if it was wrong
        if (currentIdentity.peer_id !== myPeerId && currentIdentity.peerId !== myPeerId) {
            console.log('Updating identity with correct peer_id');
            currentIdentity.peer_id = myPeerId;
            currentIdentity.peerId = myPeerId;
            localStorage.setItem('p2pcomm_identity', JSON.stringify(currentIdentity));
        }

        await wasmModule.network_init(myPeerId);
        console.log('Network manager initialized');

        // Set message callback for incoming messages
        wasmModule.network_set_message_callback((fromPeerId, messageJson) => {
            handleIncomingMessage(fromPeerId, messageJson);
        });

        // Initialize WebRTC bridge
        webrtcBridge = createWebRTCBridge(wasmModule);
        webrtcBridge.setLocalPeerId(myPeerId);
        console.log('WebRTC bridge initialized with peer_id:', myPeerId);

        // Initialize Kaspa service for blockchain signaling and discovery
        if (kaspaEnabled) {
            await initKaspaService(myPeerId);
        }

        // Load contacts and conversations
        await loadContacts();
        await loadConversations();

        // Setup event listeners
        setupEventListeners();

        // Load saved Kaspa settings
        loadKaspaSettings();

        showNotification('p2pComm ready!', 'success');
        updateNetworkStatus(kaspaEnabled ? 'KASPA' : 'OFFLINE', 0);

        // Handle any pending deep links after init is complete
        if (pendingDeepLink) {
            setTimeout(() => handleDeepLink(pendingDeepLink), 500);
        }
    } catch (error) {
        console.error('Initialization error:', error);
        showNotification('Failed to initialize: ' + error.message, 'error');
    }
}

// Initialize Kaspa blockchain service
async function initKaspaService(myPeerId) {
    // Check if we have saved wallet credentials for auto-connect
    const sessionPassword = sessionStorage.getItem('p2pcomm_kaspa_password');
    const savedRpc = localStorage.getItem('p2pcomm_kaspa_rpc');
    const autoConnectEnabled = localStorage.getItem('p2pcomm_auto_connect') === 'true';

    // Only auto-initialize if user explicitly opted in AND we have credentials
    if (!autoConnectEnabled || !sessionPassword) {
        console.log('Kaspa wallet not auto-connecting. Set up in Settings to enable blockchain messaging.');
        kaspaEnabled = false;
        return;
    }

    try {
        kaspaService = createKaspaService(wasmModule);

        await kaspaService.initialize(myPeerId, null, {
            password: sessionPassword,
            rpcEndpoint: savedRpc || null
        });

        // Set up ALL Kaspa callbacks
        kaspaService.onPeerDiscovered = handleKaspaPeerDiscovered;
        kaspaService.onSignalingMessage = handleKaspaSignaling;
        kaspaService.onMessageReceived = handleKaspaMessage;
        kaspaService.onConnectionStatusChanged = handleKaspaStatusChange;
        kaspaService.onWalletInitialized = handleWalletInitialized;
        kaspaService.onBalanceChanged = handleBalanceChanged;
        kaspaService.onDeliveryConfirmation = handleKaspaDeliveryConfirmation;

        // Callback to resolve recipient's Kaspa address from contacts
        kaspaService.onResolveRecipientAddress = (peerId) => {
            const contact = contacts.find(c => c.peerId === peerId);
            return contact?.kaspaAddress || null;
        };



        // Announce presence on the blockchain
        const publicKey = currentIdentity.keypair.signing.public_key;
        await kaspaService.announcePresence(publicKey);

        console.log('Kaspa service initialized');
        showNotification('Kaspa blockchain connected', 'success');

    } catch (error) {
        console.error('Kaspa service init error:', error);
        kaspaEnabled = false;
        showNotification('Kaspa service unavailable: ' + error.message, 'warning');
    }
}

// Handle peer discovered via blockchain
function handleKaspaPeerDiscovered(peerInfo) {
    console.log('Peer discovered via Kaspa:', peerInfo);

    // Check if peer is already in contacts
    const existing = contacts.find(c => c.peerId === peerInfo.peerId);
    if (!existing) {
        showNotification(`New peer discovered: ${peerInfo.peerId.substring(0, 8)}...`, 'info');
    }

    // Update network peer count
    const stats = kaspaService.getStats();
    updateNetworkStatus('KASPA', stats.peersDiscovered);
}

// Handle signaling messages from blockchain
async function handleKaspaSignaling(signal) {
    console.log('Kaspa signaling received:', signal.type, 'from:', signal.fromPeerId);
    console.log('Current contacts:', JSON.stringify(contacts.map(c => ({ name: c.displayName, peerId: c.peerId }))));

    try {
        // Find contact for this peer
        const contact = contacts.find(c => c.peerId === signal.fromPeerId);
        if (!contact) {
            console.warn('Signaling from unknown peer:', signal.fromPeerId);
            console.warn('Looking for peer starting with:', signal.fromPeerId?.substring(0, 8));
            return;
        }

        switch (signal.type) {
            case 'offer':
                // Auto-handle incoming offer
                showNotification(`Connection request from ${contact.displayName}`, 'info');

                // Generate answer and send back via blockchain
                const answerData = await webrtcBridge.handleOffer({
                    peerId: signal.fromPeerId,
                    sdp: signal.sdp
                });

                if (kaspaService) {
                    await kaspaService.sendAnswer(
                        signal.fromPeerId,
                        answerData.sdp,
                        signal.sessionId
                    );
                }
                break;

            case 'answer':
                // Complete connection with answer
                await webrtcBridge.handleAnswer({
                    peerId: signal.fromPeerId,
                    sdp: signal.sdp
                });
                showNotification(`Connected to ${contact.displayName}`, 'success');
                break;

            case 'ice':
                // Handle ICE candidates (if trickle ICE is enabled)
                console.log('ICE candidates received:', signal.candidates?.length);
                break;
        }

        updateContactConnectionStatus(signal.fromPeerId, 'connecting');

    } catch (error) {
        console.error('Error handling Kaspa signaling:', error);
    }
}

// Handle messages received via blockchain (fallback delivery)
function handleKaspaMessage(message) {
    console.log('Message received via Kaspa blockchain:', message);

    // The message structure from WASM ReceivedMessage struct:
    // - sender_peer_id (not fromPeerId)  
    // - content (not payload) - this is the envelope's payload string
    // - message_type, timestamp, transaction_id, etc.

    // Extract the content - this should be JSON from the envelope payload
    const content = message.content || message.get?.('content');
    const senderPeerId = message.sender_peer_id || message.get?.('sender_peer_id');

    if (!content || !senderPeerId) {
        console.error('[Kaspa] Missing content or sender_peer_id in received message:', message);
        return;
    }

    console.log('Received message from:', senderPeerId, 'via blockchain');

    try {
        // Process as regular incoming message with blockchain delivery method
        handleIncomingMessage(senderPeerId, content, 'blockchain');
        showNotification('Message received via blockchain', 'info');
    } catch (error) {
        console.error('Error handling incoming message:', error);
    }
}

// Handle Kaspa connection status changes
function handleKaspaStatusChange(status) {
    console.log('Kaspa status:', status);

    if (status === 'connected') {
        updateNetworkStatus('KASPA', kaspaService.getStats().peersDiscovered);
    } else if (status === 'error' || status === 'disconnected') {
        updateNetworkStatus('OFFLINE', 0);
    }
}

// Handle delivery confirmations from Kaspa blockchain
function handleKaspaDeliveryConfirmation(confirmation) {
    console.log('Kaspa delivery confirmation:', confirmation);

    // Update message status in UI
    updateMessageDeliveryStatus(confirmation.messageId, confirmation.status);

    // Show notification for important statuses
    if (confirmation.status === 'confirmed') {
        showNotification('Message confirmed on blockchain', 'success');
    } else if (confirmation.status === 'failed') {
        showNotification('Message delivery failed', 'error');
    }
}

// Update message delivery status in conversations
function updateMessageDeliveryStatus(messageId, status) {
    // Find message in conversations
    for (const [peerId, conv] of conversations) {
        const msg = conv.messages.find(m => m.id === messageId);
        if (msg) {
            msg.blockchainStatus = status; // 'queued', 'submitted', 'confirmed', 'failed'
            saveConversations();
            // Re-render if viewing this conversation
            if (currentContact && currentContact.peerId === peerId) {
                renderMessages(peerId);
            }
            break;
        }
    }
}

async function loadOrCreateIdentity() {
    try {
        // Check URL for test mode (allows multiple identities in same browser)
        const urlParams = new URLSearchParams(window.location.search);
        const testUser = urlParams.get('user'); // e.g., ?user=alice or ?user=bob

        // Use different storage keys for different test users
        window.testUser = testUser;
        window.storageKey = testUser ? `p2pcomm_identity_${testUser}` : 'p2pcomm_identity';
        window.contactsKey = testUser ? `p2pcomm_contacts_${testUser}` : 'p2pcomm_contacts';
        window.convsKey = testUser ? `p2pcomm_conversations_${testUser}` : 'p2pcomm_conversations';

        if (testUser) {
            console.log(`[TEST MODE] Using identity slot: ${testUser}`);
        }

        // Try to load existing identity from localStorage
        const savedIdentity = localStorage.getItem(window.storageKey);

        if (savedIdentity) {
            // Parse and load existing identity
            const identityData = JSON.parse(savedIdentity);
            currentIdentity = identityData;
            document.getElementById('userName').textContent = identityData.display_name || identityData.displayName;
            document.getElementById('settingsYourName').textContent = identityData.display_name || identityData.displayName;
            document.getElementById('settingsYourPeerId').textContent = identityData.peer_id || identityData.peerId;
        } else {
            // Create new identity - Show Modal
            showCreateIdentityModal();
        }
    } catch (error) {
        console.error('Identity load error:', error);
        throw error;
    }
}

function showCreateIdentityModal() {
    // Check if modal already exists
    if (document.getElementById('createIdentityModal')) {
        document.getElementById('createIdentityModal').classList.add('active');
        return;
    }

    // Create modal HTML
    const modalHtml = `
                <div class="modal-overlay active" id="createIdentityModal" style="z-index: 3000;">
                    <div class="modal">
                        <div class="modal-header">
                            <div class="modal-title">Welcome to p2pComm</div>
                        </div>
                        <div class="modal-body">
                            <p style="color: var(--color-text-secondary); margin-bottom: 16px;">
                                Create a new decentralized identity. Your keys are generated locally and never leave your device.
                            </p>
                            <div class="form-group">
                                <label class="form-label">Display Name</label>
                                <input type="text" class="form-input" id="createIdentityName" placeholder="Enter your name" autofocus>
                            </div>
                            <button class="btn btn-primary" style="width: 100%;" onclick="window.p2pcomm.createIdentity()">Create Identity</button>
                        </div>
                    </div>
                </div>
            `;

    // Append to body
    document.body.insertAdjacentHTML('beforeend', modalHtml);

    // Focus input
    setTimeout(() => {
        const input = document.getElementById('createIdentityName');
        if (input) {
            input.focus();
            // Add enter key listener
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') window.p2pcomm.createIdentity();
            });
        }
    }, 100);
}

window.createIdentity = function () {
    const nameInput = document.getElementById('createIdentityName');
    const displayName = nameInput.value.trim();

    if (!displayName) {
        showNotification('Please enter a display name', 'warning');
        return;
    }

    try {
        // Generate keypair
        const keypair = new wasmModule.IdentityKeyPair();
        const signingKeypair = keypair.getSigningKeyPair();
        const encryptionKeypair = keypair.getEncryptionKeyPair();
        const peerId = signingKeypair.publicKeyHex();

        currentIdentity = {
            peer_id: peerId,  // snake_case for Rust
            display_name: displayName,  // snake_case for Rust
            keypair: {
                signing: {
                    public_key: signingKeypair.publicKeyHex(),
                    private_key: signingKeypair.privateKeyHex()
                },
                encryption: {
                    public_key: encryptionKeypair.publicKeyHex(),
                    private_key: encryptionKeypair.privateKeyHex()
                }
            },
            created_at: Date.now()
        };

        // Save to localStorage
        localStorage.setItem(window.storageKey, JSON.stringify(currentIdentity));

        // Update UI
        document.getElementById('userName').textContent = currentIdentity.display_name;
        document.getElementById('settingsYourName').textContent = currentIdentity.display_name;
        document.getElementById('settingsYourPeerId').textContent = currentIdentity.peer_id;

        // Close modal
        document.getElementById('createIdentityModal').classList.remove('active');

        // Continue initialization
        // We need to re-run the parts of initApp that depend on identity
        // But since initApp awaits loadOrCreateIdentity, we can just let it continue if we were inside it.
        // However, loadOrCreateIdentity is async and we are now in a callback.
        // So we need to trigger the rest of the init flow.

        // Ideally, we should reload the page to ensure clean state, 
        // OR we can manually trigger the next steps.
        // For simplicity and robustness, reloading is safest as it picks up the identity from storage.
        window.location.reload();

    } catch (error) {
        console.error('Error creating identity:', error);
        showNotification('Failed to create identity: ' + error.message, 'error');
    }
};

async function loadContacts() {
    const savedContacts = localStorage.getItem(window.contactsKey || 'p2pcomm_contacts');
    if (savedContacts) {
        contacts = JSON.parse(savedContacts);
    } else {
        contacts = [];
    }
}

async function loadConversations() {
    const savedConversations = localStorage.getItem(window.convsKey || 'p2pcomm_conversations');
    if (savedConversations) {
        const convArray = JSON.parse(savedConversations);
        conversations = new Map(convArray);
    } else {
        conversations = new Map();
    }
    renderConversations();
}

function renderConversations() {
    const list = document.getElementById('conversationsList');

    if (contacts.length === 0) {
        list.innerHTML = `
                    <div class="empty-state" style="padding: 40px 20px;">
                        <div class="empty-state-text">No contacts yet</div>
                        <button class="btn btn-primary" onclick="showAddContactModal()">Add Contact</button>
                    </div>
                `;
        return;
    }

    list.innerHTML = '';

    contacts.forEach(contact => {
        const conv = conversations.get(contact.peerId) || {
            messages: [],
            lastMessage: null,
            unreadCount: 0
        };

        const item = document.createElement('div');
        item.className = 'conversation-item';
        item.dataset.peerId = contact.peerId;  // Add data attribute for finding active item
        item.onclick = () => openConversation(contact);

        const lastMsgPreview = conv.lastMessage
            ? conv.lastMessage.text.substring(0, 40) + (conv.lastMessage.text.length > 40 ? '...' : '')
            : 'No messages yet';

        const lastMsgTime = conv.lastMessage
            ? formatTime(conv.lastMessage.timestamp)
            : '';

        item.innerHTML = `
                    <div class="conversation-header">
                        <span class="conversation-name">${contact.displayName}</span>
                        <span class="conversation-time">${lastMsgTime}</span>
                    </div>
                    <div class="conversation-preview">
                        ${lastMsgPreview}
                        ${conv.unreadCount > 0 ? `<span class="conversation-unread">${conv.unreadCount}</span>` : ''}
                    </div>
                `;

        list.appendChild(item);
    });
}

function openConversation(contact) {
    currentContact = contact;

    // Close mobile panels when conversation is selected
    closeMobilePanelsOnSelect();

    // Update UI
    const emptyState = document.getElementById('emptyState');
    if (emptyState) emptyState.style.display = 'none';

    const threadHeader = document.getElementById('threadHeader');
    if (threadHeader) threadHeader.style.display = 'flex';

    const composeArea = document.getElementById('composeArea');
    if (composeArea) composeArea.style.display = 'flex';

    document.getElementById('threadContactName').textContent = contact.displayName;

    // Get real connection status from WebRTC bridge
    const connectionStatus = webrtcBridge ? webrtcBridge.getConnectionStatus(contact.peerId) : 'disconnected';
    updateContactConnectionStatus(contact.peerId, connectionStatus);

    // Update info panel
    document.getElementById('infoContactName').textContent = contact.displayName;
    document.getElementById('infoContactPeerId').textContent = contact.peerId.substring(0, 16) + '...';
    document.getElementById('infoContactConnectionStatus').textContent = connectionStatus.toUpperCase();

    // Update security section based on whether contact has public keys
    const hasKeys = contact.signingPublicKey && contact.encryptionPublicKey;

    if (hasKeys) {
        // Show verification status with badge
        const verifiedElement = document.getElementById('infoContactVerified');
        if (contact.verified) {
            verifiedElement.innerHTML = '✅ YES';
            verifiedElement.style.color = 'var(--color-success)';
        } else {
            verifiedElement.innerHTML = '⚠️ NO';
            verifiedElement.style.color = 'var(--color-warning)';
        }

        // Format and show key fingerprints (first 8 + last 8 chars)
        const formatFingerprint = (hex) => {
            if (!hex || hex.length < 16) return '-';
            return hex.substring(0, 8) + '...' + hex.substring(hex.length - 8);
        };

        document.getElementById('infoSigningKey').textContent = formatFingerprint(contact.signingPublicKey);
        document.getElementById('infoEncryptionKey').textContent = formatFingerprint(contact.encryptionPublicKey);

        // Show key sections, hide warning
        document.getElementById('signingKeySection').style.display = 'block';
        document.getElementById('encryptionKeySection').style.display = 'block';
        document.getElementById('noKeysWarning').style.display = 'none';

        // Show copy button for verified contacts
        document.getElementById('copyPublicIdentityBtn').style.display = 'block';
    } else {
        // Legacy contact without keys
        document.getElementById('infoContactVerified').innerHTML = '⚠️ UNVERIFIED';
        document.getElementById('infoContactVerified').style.color = 'var(--color-warning)';

        // Hide key sections, show warning
        document.getElementById('signingKeySection').style.display = 'none';
        document.getElementById('encryptionKeySection').style.display = 'none';
        document.getElementById('noKeysWarning').style.display = 'block';

        // Hide copy button
        document.getElementById('copyPublicIdentityBtn').style.display = 'none';
    }

    // Load messages
    renderMessages(contact.peerId);

    // Mark as active in the conversation list
    document.querySelectorAll('.conversation-item').forEach(item => {
        item.classList.remove('active');
        // Find and mark the matching contact's item as active
        if (item.dataset && item.dataset.peerId === contact.peerId) {
            item.classList.add('active');
        }
    });

    // Clear unread count
    const conv = conversations.get(contact.peerId);
    if (conv) {
        conv.unreadCount = 0;
        saveConversations();
        renderConversations();
    }
}

function renderMessages(peerId) {
    const container = document.getElementById('messagesContainer');
    container.innerHTML = '';

    const conv = conversations.get(peerId);
    if (!conv || conv.messages.length === 0) {
        container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-text">No messages yet. Start the conversation!</div>
                    </div>
                `;
        return;
    }

    conv.messages.forEach(msg => {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${msg.fromMe ? 'sent' : 'received'}`;

        // Determine delivery method badge
        let deliveryBadge = '';
        if (msg.deliveryMethod === 'webrtc') {
            deliveryBadge = '<span class="message-status" style="color: var(--color-info);" title="Delivered via WebRTC (direct P2P)">⚡</span>';
        } else if (msg.deliveryMethod === 'blockchain') {
            // Show blockchain status with more detail
            const status = msg.blockchainStatus || 'submitted';
            let statusIcon = '⛓️';
            let statusColor = 'var(--color-primary)';
            let statusTitle = 'Sent via Kaspa blockchain';

            if (status === 'queued') {
                statusIcon = '⛓️⏳';
                statusColor = 'var(--color-text-muted)';
                statusTitle = 'Queued for blockchain delivery';
            } else if (status === 'submitted') {
                statusIcon = '⛓️';
                statusColor = 'var(--color-primary)';
                statusTitle = 'Submitted to blockchain';
            } else if (status === 'confirmed') {
                statusIcon = '⛓️✓';
                statusColor = 'var(--color-success)';
                statusTitle = 'Confirmed on blockchain';
            } else if (status === 'failed') {
                statusIcon = '⛓️✗';
                statusColor = 'var(--color-danger)';
                statusTitle = 'Blockchain delivery failed';
            }

            deliveryBadge = `<span class="message-status" style="color: ${statusColor};" title="${statusTitle}">${statusIcon}</span>`;
        }

        // Determine verification badge
        let verificationBadge = '';
        if (!msg.fromMe) {
            // Only show verification status for received messages
            if (msg.verified === true) {
                verificationBadge = '<span class="message-status" style="color: var(--color-success);" title="Signature verified">🔒</span>';
            } else if (msg.verified === false) {
                verificationBadge = '<span class="message-status" style="color: var(--color-warning);" title="Unverified (no public keys)">⚠️</span>';
            }
        }

        // Combine status badges
        const statusBadges = msg.fromMe
            ? `${deliveryBadge}<span class="message-status encrypted">sent</span>`
            : `${deliveryBadge}${verificationBadge}`;

        msgDiv.innerHTML = `
                    <div class="message-content">
                        <div class="message-text">${escapeHtml(msg.text)}</div>
                        <div class="message-meta">
                            <span class="message-time">${formatTime(msg.timestamp)}</span>
                            ${statusBadges}
                        </div>
                    </div>
                `;

        container.appendChild(msgDiv);
    });

    // Scroll to bottom
    container.scrollTop = container.scrollHeight;
}

window.handleMessageInput = function (event) {
    if (event.key === 'Enter' && event.ctrlKey) {
        event.preventDefault();
        sendMessage();
    }
};

window.sendMessage = async function () {
    const input = document.getElementById('messageInput');
    const text = input.value.trim();

    if (!text || !currentContact) return;

    try {
        // Check if we have a WebRTC connection to this peer
        const connectionStatus = webrtcBridge.getConnectionStatus(currentContact.peerId);
        const useBlockchainFallback = connectionStatus !== 'connected' && kaspaEnabled && kaspaService;

        if (connectionStatus !== 'connected' && !useBlockchainFallback) {
            showNotification('Not connected to peer. Please establish connection first.', 'warning');
            return;
        }

        // Create message object for UI
        const messageId = generateId();
        const message = {
            id: messageId,
            fromMe: true,
            text: text,
            timestamp: Date.now(),
            encrypted: false, // MVP: encryption to be added later
            delivered: false
        };

        // Add to conversation UI immediately
        let conv = conversations.get(currentContact.peerId);
        if (!conv) {
            conv = { messages: [], lastMessage: null, unreadCount: 0 };
            conversations.set(currentContact.peerId, conv);
        }

        conv.messages.push(message);
        conv.lastMessage = message;

        // Save and update UI
        saveConversations();
        renderMessages(currentContact.peerId);
        renderConversations();

        // Clear input
        input.value = '';

        // Create and send message via WASM network module
        // Use the corrected peer_id (was fixed during init if needed)
        const myPeerId = currentIdentity.peer_id || currentIdentity.peerId;
        const signingPrivateKey = currentIdentity.keypair.signing.private_key;

        const messageJson = await wasmModule.create_text_message(
            myPeerId,  // from
            currentContact.peerId,  // to
            text,
            null,  // reply_to
            signingPrivateKey
        );

        // Wrap in protocol message envelope
        const protocolBytes = await wasmModule.create_protocol_message(
            myPeerId,
            currentContact.peerId,
            messageJson,
            'user_message'
        );

        // Send the protocol message - WebRTC or blockchain fallback
        if (connectionStatus === 'connected') {
            // Send via WebRTC (fast, direct)
            webrtcBridge.send(currentContact.peerId, protocolBytes);
            message.deliveryMethod = 'webrtc';
            message.delivered = true;
            showNotification('Message sent', 'success');
        } else if (useBlockchainFallback) {
            // Send via Kaspa blockchain (slower, but reliable)
            const userMessage = JSON.parse(messageJson);
            message.deliveryMethod = 'blockchain';
            message.blockchainStatus = 'queued';
            message.delivered = false; // Not confirmed yet

            // Send and get back the tracking message ID
            await kaspaService.sendMessage(currentContact.peerId, {
                type: 'user_message',
                message: userMessage,
                messageId: messageId  // Pass our message ID for tracking
            });

            showNotification('Message queued for blockchain', 'info');
        }

        saveConversations();
        renderMessages(currentContact.peerId);

    } catch (error) {
        console.error('Send error:', error);
        showNotification('Failed to send message: ' + error.message, 'error');
    }
};

// Handle incoming P2P messages from WASM callback
function handleIncomingMessage(fromPeerId, messageJson, deliveryMethod = 'webrtc') {
    try {
        console.log('Received message from:', fromPeerId, 'via', deliveryMethod);
        const protocolMessage = JSON.parse(messageJson);
        console.log('Protocol message structure:', protocolMessage);

        // Extract user message from protocol envelope
        // Support both formats: WebRTC (payload.UserMessage) and Blockchain (type: 'user_message')
        let message;
        if (protocolMessage.payload && protocolMessage.payload.UserMessage) {
            // WebRTC format
            message = protocolMessage.payload.UserMessage.message;
        } else if (protocolMessage.type === 'user_message' && protocolMessage.message) {
            // Blockchain format
            message = protocolMessage.message;
        } else {
            console.warn('Non-user message received:', Object.keys(protocolMessage.payload || protocolMessage));
            return;
        }

        // Find sender in contacts
        const sender = contacts.find(c => c.peerId === fromPeerId);
        if (!sender) {
            console.warn('Message from unknown peer:', fromPeerId);
            showNotification('Message from unknown peer', 'warning');
            return;
        }

        // Verify message signature (if contact has public keys)
        let verified = false;
        if (sender.signingPublicKey && sender.encryptionPublicKey) {
            try {
                // Convert sender to Rust-compatible Contact format
                const senderContact = {
                    peer_id: {
                        hash: {
                            bytes: Array.from(hexToBytes(sender.peerId))
                        }
                    },
                    display_name: sender.displayName,
                    signing_public_key: Array.from(hexToBytes(sender.signingPublicKey)),
                    encryption_public_key: Array.from(hexToBytes(sender.encryptionPublicKey)),
                    verified: sender.verified,
                    added_at: sender.addedAt,
                    last_seen: sender.lastSeen || null,
                    notes: sender.notes || null
                };

                const userMessageJson = JSON.stringify(message);
                const senderJson = JSON.stringify(senderContact);

                verified = wasmModule.verify_message_signature(userMessageJson, senderJson);

                if (!verified) {
                    console.error('❌ Invalid signature from', fromPeerId);
                    showNotification('⚠️ Message with INVALID signature rejected', 'error');
                    return;  // Reject message with invalid signature
                }

                console.log('✅ Message signature verified from', sender.displayName);
            } catch (error) {
                console.error('Error verifying signature:', error);
                showNotification('⚠️ Signature verification failed: ' + error.message, 'error');
                return;  // Reject on verification error
            }
        } else {
            console.warn('⚠️ Contact has no public keys - signature cannot be verified');
            // Allow message but mark as unverified
        }

        // Get or create conversation
        let conv = conversations.get(fromPeerId);
        if (!conv) {
            conv = { messages: [], lastMessage: null, unreadCount: 0 };
            conversations.set(fromPeerId, conv);
        }

        // Add message to conversation
        // Extract text from content (handle Rust enum serialization)
        const messageText = message.content.Text?.text || message.content.text || '';

        const incomingMessage = {
            id: message.id,
            fromMe: false,
            text: messageText,
            timestamp: message.timestamp,
            encrypted: false, // MVP: encryption to be added later
            delivered: true,
            verified: verified,  // Store verification status
            deliveryMethod: deliveryMethod  // Track delivery method (webrtc or blockchain)
        };

        conv.messages.push(incomingMessage);
        conv.lastMessage = incomingMessage;

        // Increment unread count if not viewing this conversation
        if (!currentContact || currentContact.peerId !== fromPeerId) {
            conv.unreadCount++;
        }

        // Save and update UI
        saveConversations();
        renderConversations();

        // If viewing this conversation, render messages
        if (currentContact && currentContact.peerId === fromPeerId) {
            renderMessages(fromPeerId);
        }

        // Show notification
        showNotification(`New message from ${sender.displayName}`, 'info');

    } catch (error) {
        console.error('Error handling incoming message:', error);
        showNotification('Error processing incoming message', 'error');
    }
}

// WebRTC Connection Functions
window.showConnectModal = function () {
    if (!currentContact) {
        showNotification('Please select a contact first', 'warning');
        return;
    }
    document.getElementById('connectModal').classList.add('active');
};

window.generateConnectionOffer = async function () {
    try {
        if (!currentContact) {
            showNotification('No contact selected', 'error');
            return;
        }

        showNotification('Generating offer...', 'info');

        // Create WebRTC offer
        const offerData = await webrtcBridge.createOffer(currentContact.peerId);

        // Generate a session ID for tracking
        const sessionId = generateId();

        // Display in textarea for manual sharing
        const offerJson = JSON.stringify(offerData, null, 2);
        document.getElementById('offerText').value = offerJson;
        document.getElementById('offerOutput').style.display = 'block';

        // Also send via Kaspa blockchain for automatic signaling
        if (kaspaEnabled && kaspaService) {
            try {
                await kaspaService.sendOffer(
                    currentContact.peerId,
                    offerData.sdp,
                    sessionId
                );
                showNotification('Offer generated & sent via blockchain!', 'success');
            } catch (blockchainError) {
                console.warn('Could not send offer via blockchain:', blockchainError);
                showNotification('Offer generated! Share it with your peer.', 'success');
            }
        } else {
            showNotification('Offer generated! Share it with your peer.', 'success');
        }

    } catch (error) {
        console.error('Error generating offer:', error);
        showNotification('Failed to generate offer: ' + error.message, 'error');
    }
};

window.copyOffer = function () {
    const offerText = document.getElementById('offerText');
    offerText.select();
    document.execCommand('copy');
    showNotification('Offer copied to clipboard', 'success');
};

window.importAnswer = async function () {
    try {
        const answerInput = document.getElementById('answerInput').value.trim();

        if (!answerInput) {
            showNotification('Please paste an answer', 'warning');
            return;
        }

        showNotification('Importing answer...', 'info');

        // Parse answer JSON
        const answerData = JSON.parse(answerInput);

        // Handle the answer
        await webrtcBridge.handleAnswer(answerData);

        showNotification('Answer imported! Connection establishing...', 'success');

        // Clear input
        document.getElementById('answerInput').value = '';

        // Update connection status
        updateContactConnectionStatus(answerData.peerId, 'connecting');

    } catch (error) {
        console.error('Error importing answer:', error);
        showNotification('Failed to import answer: ' + error.message, 'error');
    }
};

window.handleIncomingOffer = async function () {
    try {
        const offerInput = document.getElementById('offerInput').value.trim();

        if (!offerInput) {
            showNotification('Please paste an offer', 'warning');
            return;
        }

        showNotification('Processing offer...', 'info');

        // Parse offer JSON
        const offerData = JSON.parse(offerInput);

        // Handle the offer and generate answer
        const answerData = await webrtcBridge.handleOffer(offerData);

        // Display answer in textarea
        const answerJson = JSON.stringify(answerData, null, 2);
        document.getElementById('answerText').value = answerJson;
        document.getElementById('answerOutput').style.display = 'block';

        showNotification('Answer generated! Share it with your peer.', 'success');

        // Clear input
        document.getElementById('offerInput').value = '';

        // Update connection status
        updateContactConnectionStatus(offerData.peerId, 'connecting');

    } catch (error) {
        console.error('Error handling offer:', error);
        showNotification('Failed to handle offer: ' + error.message, 'error');
    }
};

window.copyAnswer = async function () {
    // If we have a pending answer link (from connection link flow), copy that
    if (window.pendingAnswerLink) {
        try {
            await copyToClipboard(window.pendingAnswerLink);
            showNotification('Answer link copied! Send it back to complete connection.', 'success');
        } catch (err) {
            console.error('Failed to copy:', err);
            showNotification('Failed to copy to clipboard', 'error');
        }
    } else {
        // Fallback to copying the textarea content
        const answerText = document.getElementById('answerText');
        answerText.select();
        document.execCommand('copy');
        showNotification('Answer copied to clipboard', 'success');
    }
};

function updateContactConnectionStatus(peerId, status) {
    // Update the thread header if this is the current contact
    if (currentContact && currentContact.peerId === peerId) {
        const statusElement = document.getElementById('threadContactStatus');
        if (statusElement) {
            statusElement.textContent = status.charAt(0).toUpperCase() + status.slice(1);
            statusElement.className = 'thread-contact-status';

            if (status === 'connected') {
                statusElement.style.color = 'var(--color-success)';
            } else if (status === 'connecting') {
                statusElement.style.color = 'var(--color-warning)';
            } else {
                statusElement.style.color = 'var(--color-text-muted)';
            }
        }
    }
}

// Helper: Convert hex string to byte array
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Helper: Convert byte array to hex string
function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

window.showAddContactModal = function () {
    document.getElementById('addContactModal').classList.add('active');
    // Clear all form fields
    document.getElementById('publicIdentityJson').value = '';
    document.getElementById('newContactName').value = '';
    document.getElementById('newContactPeerId').value = '';
};

// Import contact from PublicIdentity JSON (Recommended - Verified)
window.importPublicIdentity = async function () {
    try {
        const jsonText = document.getElementById('publicIdentityJson').value.trim();

        if (!jsonText) {
            showNotification('Please paste PublicIdentity JSON', 'error');
            return;
        }

        // Parse JSON
        let publicIdentity;
        try {
            publicIdentity = JSON.parse(jsonText);
        } catch (e) {
            showNotification('Invalid JSON format', 'error');
            return;
        }

        // Verify the public identity (peer ID matches public key)
        const publicIdentityJson = JSON.stringify(publicIdentity);
        const valid = wasmModule.verify_public_identity(publicIdentityJson);

        if (!valid) {
            showNotification('Invalid: Peer ID does not match public key', 'error');
            return;
        }

        // Create contact from public identity
        const contactJson = wasmModule.create_contact_from_public_identity(publicIdentityJson);
        const rustContact = JSON.parse(contactJson);

        // Convert to JavaScript contact format with public keys
        const contact = {
            id: generateId(),
            displayName: rustContact.display_name,
            peerId: rustContact.peer_id.hash.bytes ? bytesToHex(rustContact.peer_id.hash.bytes) : rustContact.peer_id,
            signingPublicKey: bytesToHex(rustContact.signing_public_key),
            encryptionPublicKey: bytesToHex(rustContact.encryption_public_key),
            kaspaAddress: publicIdentity.kaspa_address || null, // Get from original publicIdentity
            verified: true,  // Cryptographically verified
            addedAt: Date.now(),
            lastSeen: null,
            notes: null
        };

        // Check if contact already exists
        const existingIndex = contacts.findIndex(c => c.peerId === contact.peerId);
        if (existingIndex >= 0) {
            contacts[existingIndex] = contact;  // Update existing
            showNotification('Contact updated: ' + contact.displayName, 'success');
        } else {
            contacts.push(contact);
            showNotification('Contact added & verified: ' + contact.displayName, 'success');
        }

        localStorage.setItem(window.contactsKey || 'p2pcomm_contacts', JSON.stringify(contacts));
        renderConversations();
        closeModal('addContactModal');

        // Clear form
        document.getElementById('publicIdentityJson').value = '';

    } catch (error) {
        console.error('Error importing public identity:', error);
        showNotification('Failed to import: ' + error.message, 'error');
    }
};

// Manual contact entry (Legacy - Unverified)
window.addContactManual = function () {
    const name = document.getElementById('newContactName').value.trim();
    const peerId = document.getElementById('newContactPeerId').value.trim();

    if (!name || !peerId) {
        showNotification('Name and Peer ID required', 'error');
        return;
    }

    const contact = {
        id: generateId(),
        displayName: name,
        peerId: peerId,
        signingPublicKey: null,  // No keys - unverified
        encryptionPublicKey: null,
        verified: false,
        addedAt: Date.now(),
        lastSeen: null,
        notes: null
    };

    contacts.push(contact);
    localStorage.setItem(window.contactsKey || 'p2pcomm_contacts', JSON.stringify(contacts));

    renderConversations();
    closeModal('addContactModal');
    showNotification('⚠️ Contact added (unverified): ' + name, 'warning');

    // Clear form
    document.getElementById('newContactName').value = '';
    document.getElementById('newContactPeerId').value = '';
};

window.toggleSettings = function () {
    document.getElementById('settingsModal').classList.add('active');
};

window.closeModal = function (modalId) {
    document.getElementById(modalId).classList.remove('active');
};

// ========================================
// KASPA WALLET UI FUNCTIONS
// ========================================

// Mode UI update function removed


async function loadKaspaSettings() {
    const savedRpc = localStorage.getItem('p2pcomm_kaspa_rpc');
    const sessionPassword = sessionStorage.getItem('p2pcomm_kaspa_password');
    const autoConnectEnabled = localStorage.getItem('p2pcomm_auto_connect') === 'true';

    if (savedRpc) {
        const rpcInput = document.getElementById('kaspaRpcEndpoint');
        if (rpcInput) {
            rpcInput.value = savedRpc;
        }
    }

    // Restore checkbox state
    const autoConnectCheckbox = document.getElementById('kaspaAutoConnect');
    if (autoConnectCheckbox) {
        autoConnectCheckbox.checked = autoConnectEnabled;
    }

    // Only auto-connect if user explicitly opted in AND we have a session password
    if (autoConnectEnabled && sessionPassword) {
        const passInput = document.getElementById('kaspaPassword');
        if (passInput) {
            passInput.value = sessionPassword;
            console.log('Auto-connecting wallet (user opted in)...');
            setTimeout(() => window.initializeKaspaWallet(), 500);
        }
    }
}

window.initializeKaspaWallet = async function () {
    const password = document.getElementById('kaspaPassword').value;
    if (!password) {
        showNotification('Please enter a wallet password', 'warning');
        return;
    }

    const rpcEndpoint = document.getElementById('kaspaRpcEndpoint').value;

    try {
        showNotification('Initializing Kaspa wallet...', 'info');

        // Reinitialize Kaspa service
        if (kaspaService) {
            await kaspaService.disconnect();
        }

        kaspaService = createKaspaService(wasmModule);
        const peerId = currentIdentity.peer_id || currentIdentity.peerId;
        const kaspaAddress = 'kaspatest:' + peerId.substring(0, 58);

        await kaspaService.initialize(peerId, kaspaAddress, {
            mode: 'testnet',
            password: password,
            rpcEndpoint: rpcEndpoint
        });

        // Set up ALL callbacks
        kaspaService.onPeerDiscovered = handleKaspaPeerDiscovered;
        kaspaService.onSignalingMessage = handleKaspaSignaling;
        kaspaService.onMessageReceived = handleKaspaMessage;
        kaspaService.onConnectionStatusChanged = handleKaspaStatusChange;
        kaspaService.onWalletInitialized = handleWalletInitialized;
        kaspaService.onBalanceChanged = handleBalanceChanged;
        kaspaService.onDeliveryConfirmation = handleKaspaDeliveryConfirmation;

        // Callback to resolve recipient's Kaspa address from contacts
        kaspaService.onResolveRecipientAddress = (peerId) => {
            const contact = contacts.find(c => c.peerId === peerId);
            return contact?.kaspaAddress || null;
        };



        // Announce presence
        const publicKey = currentIdentity.keypair.signing.public_key;
        await kaspaService.announcePresence(publicKey);

        // Save settings
        localStorage.setItem('p2pcomm_kaspa_rpc', rpcEndpoint);
        sessionStorage.setItem('p2pcomm_kaspa_password', password); // Session only

        // Save auto-connect preference
        const autoConnectCheckbox = document.getElementById('kaspaAutoConnect');
        if (autoConnectCheckbox) {
            localStorage.setItem('p2pcomm_auto_connect', autoConnectCheckbox.checked ? 'true' : 'false');
        }

        showNotification('Kaspa wallet initialized', 'success');
    } catch (error) {
        console.error('Kaspa wallet init error:', error);
        showNotification('Wallet initialization failed: ' + error.message, 'error');
    }
};

function handleWalletInitialized(walletInfo) {
    console.log('Wallet initialized:', walletInfo);

    // Update settings modal
    document.getElementById('kaspaWalletInfo').style.display = 'flex';
    document.getElementById('kaspaBalanceInfo').style.display = 'flex';
    document.getElementById('kaspaAddressDisplay').textContent = walletInfo.primary_address || '-';

    // Show header wallet display
    document.getElementById('kaspaWalletDisplay').style.display = 'flex';
}

function handleBalanceChanged(balance) {
    console.log('Balance changed:', balance);

    // Update balance displays
    const kasAmount = kaspaService ? kaspaService.sompisToKas(balance) : 0;
    const formatted = kasAmount.toFixed(4);

    document.getElementById('kaspaBalanceDisplay').textContent = formatted + ' KAS';
    document.getElementById('headerKaspaBalance').textContent = formatted;
}

window.refreshKaspaBalance = async function () {
    if (kaspaService && kaspaService.hasWallet()) {
        try {
            showNotification('Refreshing balance...', 'info');
            await kaspaService.refreshBalance();
        } catch (error) {
            showNotification('Failed to refresh balance: ' + error.message, 'error');
        }
    } else {
        showNotification('Wallet not initialized', 'warning');
    }
};

// ========================================
// MOBILE NAVIGATION FUNCTIONS
// ========================================

window.toggleMobileSidebar = function () {
    const sidebar = document.getElementById('sidebarLeft');
    const hamburger = document.getElementById('hamburgerMenu');
    const overlay = document.getElementById('mobileOverlay');
    const infoPanel = document.getElementById('sidebarRight');

    // Close info panel if open
    if (infoPanel && infoPanel.classList.contains('active')) {
        infoPanel.classList.remove('active');
    }

    // Toggle sidebar and overlay
    sidebar.classList.toggle('active');
    hamburger.classList.toggle('active');
    overlay.classList.toggle('active');
};

window.toggleMobileInfoPanel = function () {
    const infoPanel = document.getElementById('sidebarRight');
    const overlay = document.getElementById('mobileOverlay');
    const sidebar = document.getElementById('sidebarLeft');
    const hamburger = document.getElementById('hamburgerMenu');

    // Close sidebar if open
    if (sidebar.classList.contains('active')) {
        sidebar.classList.remove('active');
        hamburger.classList.remove('active');
    }

    // Toggle info panel and overlay
    infoPanel.classList.toggle('active');
    overlay.classList.toggle('active');
};

window.closeMobilePanels = function () {
    const sidebar = document.getElementById('sidebarLeft');
    const infoPanel = document.getElementById('sidebarRight');
    const hamburger = document.getElementById('hamburgerMenu');
    const overlay = document.getElementById('mobileOverlay');

    // Close everything
    sidebar.classList.remove('active');
    infoPanel.classList.remove('active');
    hamburger.classList.remove('active');
    overlay.classList.remove('active');
};

// Close mobile panels when conversation is selected
function closeMobilePanelsOnSelect() {
    if (window.innerWidth <= 767) {
        closeMobilePanels();
    }
}

window.exportIdentity = function () {
    const data = JSON.stringify(currentIdentity, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'p2pcomm_identity.json';
    a.click();
    showNotification('Identity exported', 'success');
};

// Copy text to clipboard with fallback for HTTP contexts
async function copyToClipboard(text) {
    // Try modern clipboard API first (requires HTTPS or localhost)
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
    }

    // Fallback for HTTP: use textarea + execCommand
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
        document.execCommand('copy');
        return true;
    } finally {
        textArea.remove();
    }
}

// Copy contact's PublicIdentity JSON for sharing
window.copyContactPublicIdentity = async function () {
    if (!currentContact) {
        showNotification('No contact selected', 'error');
        return;
    }

    if (!currentContact.signingPublicKey || !currentContact.encryptionPublicKey) {
        showNotification('Contact has no public keys to share', 'error');
        return;
    }

    try {
        // Derive correct peer_id from signing public key (should match stored peerId)
        const correctPeerId = wasmModule.derive_peer_id_from_public_key(currentContact.signingPublicKey);

        // Reconstruct PublicIdentity format from contact
        const publicIdentity = {
            peer_id: {
                hash: {
                    bytes: Array.from(hexToBytes(correctPeerId))
                }
            },
            display_name: currentContact.displayName,
            signing_public_key: Array.from(hexToBytes(currentContact.signingPublicKey)),
            encryption_public_key: Array.from(hexToBytes(currentContact.encryptionPublicKey))
        };

        // Include Kaspa address if contact has one
        if (currentContact.kaspaAddress) {
            publicIdentity.kaspa_address = currentContact.kaspaAddress;
        }


        const jsonText = JSON.stringify(publicIdentity, null, 2);

        // Copy to clipboard (with HTTP fallback)
        await copyToClipboard(jsonText);
        showNotification('PublicIdentity copied to clipboard', 'success');
    } catch (error) {
        console.error('Error generating PublicIdentity:', error);
        showNotification('Failed to copy: ' + error.message, 'error');
    }
};

// Share user's own PublicIdentity
window.showQRCode = async function () {
    try {
        if (!currentIdentity) {
            showNotification('No identity loaded', 'error');
            return;
        }

        // Use centralized getPublicIdentity() which includes kaspa_address
        const publicIdentity = getPublicIdentity();

        // Pretty print for display
        const prettyJson = JSON.stringify(publicIdentity, null, 2);

        // Set in textarea
        document.getElementById('myPublicIdentityJson').value = prettyJson;

        // Show modal
        document.getElementById('shareIdentityModal').classList.add('active');

    } catch (error) {
        console.error('Error generating PublicIdentity:', error);
        showNotification('Failed to generate PublicIdentity: ' + error.message, 'error');
    }
};


// Copy user's PublicIdentity to clipboard
window.copyMyPublicIdentity = async function () {
    const jsonText = document.getElementById('myPublicIdentityJson').value;

    if (!jsonText) {
        showNotification('No PublicIdentity to copy', 'error');
        return;
    }

    try {
        await copyToClipboard(jsonText);
        showNotification('PublicIdentity copied to clipboard', 'success');
    } catch (err) {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy to clipboard', 'error');
    }
};

// Copy shareable contact link to clipboard
window.copyContactLink = async function () {
    try {
        const link = generateContactLink();
        await copyToClipboard(link);
        showNotification('Contact link copied! Share it with others.', 'success');
    } catch (error) {
        console.error('Failed to generate contact link:', error);
        showNotification('Failed to copy link: ' + error.message, 'error');
    }
};

// Copy shareable offer link to clipboard (for connection)
window.copyOfferLink = async function () {
    if (!currentContact) {
        showNotification('Select a contact first', 'warning');
        return;
    }

    try {
        showNotification('Generating connection link...', 'info');
        const link = await generateOfferLink(currentContact.peerId);
        await copyToClipboard(link);
        showNotification('Connection link copied! Share it with ' + currentContact.displayName, 'success');
    } catch (error) {
        console.error('Failed to generate offer link:', error);
        showNotification('Failed to generate connection link: ' + error.message, 'error');
    }
};

window.saveSettings = function () {
    showNotification('Settings saved', 'success');
    closeModal('settingsModal');
};

window.clearConversation = function () {
    if (!currentContact) return;

    if (confirm('Clear conversation with ' + currentContact.displayName + '?')) {
        conversations.delete(currentContact.peerId);
        saveConversations();
        renderMessages(currentContact.peerId);
        renderConversations();
        showNotification('Conversation cleared', 'success');
    }
};

window.deleteContact = function () {
    if (!currentContact) return;

    if (confirm('Delete contact ' + currentContact.displayName + '?')) {
        contacts = contacts.filter(c => c.peerId !== currentContact.peerId);
        conversations.delete(currentContact.peerId);
        localStorage.setItem(window.contactsKey || 'p2pcomm_contacts', JSON.stringify(contacts));
        saveConversations();

        // Reset UI
        currentContact = null;
        document.getElementById('emptyState').style.display = 'flex';
        document.getElementById('threadHeader').style.display = 'none';
        document.getElementById('composeArea').style.display = 'none';

        renderConversations();
        showNotification('Contact deleted', 'success');
    }
};

window.verifyContact = function () {
    showNotification('Contact verification coming soon', 'info');
};

window.exportContactKey = function () {
    if (!currentContact) return;
    showNotification('Key export coming soon', 'info');
};

window.showContactInfo = function () {
    // On mobile, use overlay toggle; on desktop, use collapsed state
    if (window.innerWidth <= 767) {
        toggleMobileInfoPanel();
    } else {
        document.getElementById('sidebarRight').classList.toggle('collapsed');
    }
};

window.clearAllData = function () {
    if (confirm('Clear all data? This cannot be undone!')) {
        localStorage.clear();
        location.reload();
    }
};

window.deleteIdentity = function () {
    if (confirm('Delete identity? This cannot be undone!')) {
        localStorage.removeItem('p2pcomm_identity');
        location.reload();
    }
};

function saveConversations() {
    const convArray = Array.from(conversations.entries());
    localStorage.setItem(window.convsKey || 'p2pcomm_conversations', JSON.stringify(convArray));
}

function setupEventListeners() {
    // Search
    document.getElementById('searchInput').addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        document.querySelectorAll('.conversation-item').forEach(item => {
            const name = item.querySelector('.conversation-name').textContent.toLowerCase();
            item.style.display = name.includes(query) ? 'block' : 'none';
        });
    });

    // Close modals on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.classList.remove('active');
            }
        });
    });
}

function showNotification(message, type = 'info') {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    container.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}

function updateNetworkStatus(status, peerCount) {
    document.getElementById('networkStatusText').textContent = status;
    document.getElementById('networkPeers').textContent = `(${peerCount})`;
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'now';
    if (diffMins < 60) return `${diffMins}m`;
    if (diffHours < 24) return `${diffHours}h`;
    if (diffDays < 7) return `${diffDays}d`;

    return date.toLocaleDateString();
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Export globals
window.wasmModule = wasmModule;
window.currentIdentity = currentIdentity;

// Initialize on load

// Export functions for use in HTML onclick handlers
// Attach to window.p2pcomm namespace
if (typeof window !== 'undefined') {
    window.p2pcomm = {
        // Exported functions
        initApp,
        handleMessageInput: (event) => {
            if (event.key === 'Enter' && event.ctrlKey) {
                event.preventDefault();
                sendMessage();
            }
        },
        sendMessage,
        showConnectModal,
        generateConnectionOffer,
        copyOffer,
        importAnswer,
        handleIncomingOffer,
        copyAnswer,
        showAddContactModal,
        importPublicIdentity,
        addContactManual,
        toggleSettings,
        closeModal,
        initializeKaspaWallet,
        refreshKaspaBalance,
        toggleMobileSidebar,
        toggleMobileInfoPanel,
        closeMobilePanels,
        exportIdentity,
        copyContactPublicIdentity,
        showQRCode,
        copyMyPublicIdentity,
        saveSettings,
        clearConversation,
        deleteContact,
        verifyContact,
        exportContactKey,
        showContactInfo,
        clearAllData,
        deleteIdentity,
        createIdentity,
        // Shareable link functions
        copyContactLink,
        copyOfferLink,
        generateContactLink,
        generateOfferLink
    };
}

// Export initApp for main.js
export { initApp };
