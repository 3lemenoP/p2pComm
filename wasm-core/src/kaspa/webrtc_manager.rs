//! WebRTC Manager for WASM
//!
//! Pure Rust WebRTC implementation using web-sys bindings:
//! - RTCPeerConnection management
//! - Offer/Answer creation
//! - ICE candidate handling
//! - Data channel management
//! - Connection state tracking

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    RtcPeerConnection, RtcSessionDescription, RtcSessionDescriptionInit, RtcSdpType,
    RtcPeerConnectionIceEvent, RtcIceCandidate, RtcIceCandidateInit,
    RtcDataChannel, RtcDataChannelEvent, RtcDataChannelInit,
    RtcConfiguration, RtcIceServer, RtcPeerConnectionState,
    MessageEvent,
};
use serde::{Serialize, Deserialize};
use std::cell::RefCell;
use std::collections::HashMap;
use js_sys::{Array, Object, Reflect};

thread_local! {
    /// Global WebRTC manager
    static WEBRTC_MANAGER: RefCell<Option<WebRtcManagerState>> = RefCell::new(None);
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Closed,
}

impl From<RtcPeerConnectionState> for ConnectionState {
    fn from(state: RtcPeerConnectionState) -> Self {
        match state {
            RtcPeerConnectionState::New => ConnectionState::New,
            RtcPeerConnectionState::Connecting => ConnectionState::Connecting,
            RtcPeerConnectionState::Connected => ConnectionState::Connected,
            RtcPeerConnectionState::Disconnected => ConnectionState::Disconnected,
            RtcPeerConnectionState::Failed => ConnectionState::Failed,
            RtcPeerConnectionState::Closed => ConnectionState::Closed,
            _ => ConnectionState::New,
        }
    }
}

/// WebRTC connection wrapper
struct WebRtcConnection {
    peer_id: String,
    peer_connection: RtcPeerConnection,
    data_channel: Option<RtcDataChannel>,
    state: ConnectionState,
    // Store closures to prevent them from being dropped
    _onicecandidate: Closure<dyn FnMut(RtcPeerConnectionIceEvent)>,
    _onconnectionstatechange: Closure<dyn FnMut()>,
    _ondatachannel: Option<Closure<dyn FnMut(RtcDataChannelEvent)>>,
    _onmessage: Option<Closure<dyn FnMut(MessageEvent)>>,
    _onopen: Option<Closure<dyn FnMut()>>,
    _onclose: Option<Closure<dyn FnMut()>>,
}

/// Pending ICE candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidateData {
    pub peer_id: String,
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_m_line_index: Option<u16>,
}

/// Internal manager state
struct WebRtcManagerState {
    local_peer_id: String,
    connections: HashMap<String, WebRtcConnection>,
    pending_ice_candidates: Vec<IceCandidateData>,
    pending_messages: Vec<(String, Vec<u8>)>, // (peer_id, data)
}

/// Initialize the WebRTC manager
#[wasm_bindgen]
pub fn webrtc_manager_init(local_peer_id: String) -> Result<(), JsValue> {
    WEBRTC_MANAGER.with(|manager| {
        let mut manager = manager.borrow_mut();
        *manager = Some(WebRtcManagerState {
            local_peer_id,
            connections: HashMap::new(),
            pending_ice_candidates: Vec::new(),
            pending_messages: Vec::new(),
        });
        Ok(())
    })
}

/// Create a new RTCPeerConnection with STUN servers
fn create_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    let mut config = RtcConfiguration::new();

    // Add STUN servers
    let ice_servers = Array::new();

    let stun_server = RtcIceServer::new();
    stun_server.set_urls(&JsValue::from_str("stun:stun.l.google.com:19302"));
    ice_servers.push(&stun_server);

    let stun_server2 = RtcIceServer::new();
    stun_server2.set_urls(&JsValue::from_str("stun:stun1.l.google.com:19302"));
    ice_servers.push(&stun_server2);

    config.ice_servers(&ice_servers);

    RtcPeerConnection::new_with_configuration(&config)
}

/// Create an offer for a peer
#[wasm_bindgen]
pub async fn webrtc_manager_create_offer(remote_peer_id: String) -> Result<JsValue, JsValue> {
    // Create peer connection
    let pc = create_peer_connection()?;

    // Create data channel
    let mut dc_init = RtcDataChannelInit::new();
    dc_init.set_ordered(true);
    let dc = pc.create_data_channel_with_data_channel_dict("p2pcomm-data", &dc_init);

    // Store local peer ID for closures
    let local_peer_id = WEBRTC_MANAGER.with(|manager| {
        let manager = manager.borrow();
        manager.as_ref()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))
            .map(|m| m.local_peer_id.clone())
    })?;

    // Set up ICE candidate callback
    let peer_id_for_ice = remote_peer_id.clone();
    let onicecandidate = Closure::wrap(Box::new(move |event: RtcPeerConnectionIceEvent| {
        if let Some(candidate) = event.candidate() {
            // Store ICE candidate
            let candidate_str = candidate.candidate();
            if !candidate_str.is_empty() {
                let ice_data = IceCandidateData {
                    peer_id: peer_id_for_ice.clone(),
                    candidate: candidate_str,
                    sdp_mid: candidate.sdp_mid(),
                    sdp_m_line_index: candidate.sdp_m_line_index(),
                };

                WEBRTC_MANAGER.with(|manager| {
                    if let Some(manager) = manager.borrow_mut().as_mut() {
                        manager.pending_ice_candidates.push(ice_data);
                    }
                });
            }
        }
    }) as Box<dyn FnMut(_)>);

    pc.set_onicecandidate(Some(onicecandidate.as_ref().unchecked_ref()));

    // Set up connection state change callback
    let peer_id_for_state = remote_peer_id.clone();
    let pc_for_state = pc.clone();
    let onconnectionstatechange = Closure::wrap(Box::new(move || {
        let state = pc_for_state.connection_state();
        let conn_state: ConnectionState = state.into();

        WEBRTC_MANAGER.with(|manager| {
            if let Some(manager) = manager.borrow_mut().as_mut() {
                if let Some(conn) = manager.connections.get_mut(&peer_id_for_state) {
                    conn.state = conn_state;
                }
            }
        });
    }) as Box<dyn FnMut()>);

    pc.set_onconnectionstatechange(Some(onconnectionstatechange.as_ref().unchecked_ref()));

    // Set up data channel open callback
    let peer_id_for_open = remote_peer_id.clone();
    let onopen = Closure::wrap(Box::new(move || {
        web_sys::console::log_1(&format!("Data channel opened for peer: {}", peer_id_for_open).into());
    }) as Box<dyn FnMut()>);

    dc.set_onopen(Some(onopen.as_ref().unchecked_ref()));

    // Set up data channel message callback
    let peer_id_for_message = remote_peer_id.clone();
    let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
        if let Ok(array_buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
            let uint8_array = js_sys::Uint8Array::new(&array_buffer);
            let data = uint8_array.to_vec();

            WEBRTC_MANAGER.with(|manager| {
                if let Some(manager) = manager.borrow_mut().as_mut() {
                    manager.pending_messages.push((peer_id_for_message.clone(), data));
                }
            });
        }
    }) as Box<dyn FnMut(_)>);

    dc.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

    // Create offer
    let offer_promise = pc.create_offer();
    let offer = JsFuture::from(offer_promise).await?;

    // Set local description
    let offer_sdp = Reflect::get(&offer, &JsValue::from_str("sdp"))?;
    let offer_sdp_str = offer_sdp.as_string()
        .ok_or_else(|| JsValue::from_str("Failed to get SDP string"))?;

    let mut desc_init = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    desc_init.sdp(&offer_sdp_str);

    let set_local_promise = pc.set_local_description(&desc_init);
    JsFuture::from(set_local_promise).await?;

    // Store connection
    let connection = WebRtcConnection {
        peer_id: remote_peer_id.clone(),
        peer_connection: pc,
        data_channel: Some(dc),
        state: ConnectionState::Connecting,
        _onicecandidate: onicecandidate,
        _onconnectionstatechange: onconnectionstatechange,
        _ondatachannel: None,
        _onmessage: Some(onmessage),
        _onopen: Some(onopen),
        _onclose: None,
    };

    WEBRTC_MANAGER.with(|manager| {
        if let Some(manager) = manager.borrow_mut().as_mut() {
            manager.connections.insert(remote_peer_id, connection);
        }
    });

    // Return offer SDP
    serde_wasm_bindgen::to_value(&offer_sdp_str)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Handle an incoming answer
#[wasm_bindgen]
pub async fn webrtc_manager_handle_answer(peer_id: String, answer_sdp: String) -> Result<(), JsValue> {
    let pc = WEBRTC_MANAGER.with(|manager| {
        let manager = manager.borrow();
        let manager = manager.as_ref()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        let conn = manager.connections.get(&peer_id)
            .ok_or_else(|| JsValue::from_str("Connection not found"))?;

        Ok::<RtcPeerConnection, JsValue>(conn.peer_connection.clone())
    })?;

    let mut desc_init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    desc_init.sdp(&answer_sdp);

    let set_remote_promise = pc.set_remote_description(&desc_init);
    JsFuture::from(set_remote_promise).await?;

    Ok(())
}

/// Handle an incoming offer (create answer)
#[wasm_bindgen]
pub async fn webrtc_manager_handle_offer(remote_peer_id: String, offer_sdp: String) -> Result<JsValue, JsValue> {
    // Create peer connection
    let pc = create_peer_connection()?;

    // Store local peer ID for closures
    let local_peer_id = WEBRTC_MANAGER.with(|manager| {
        let manager = manager.borrow();
        manager.as_ref()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))
            .map(|m| m.local_peer_id.clone())
    })?;

    // Set up ICE candidate callback
    let peer_id_for_ice = remote_peer_id.clone();
    let onicecandidate = Closure::wrap(Box::new(move |event: RtcPeerConnectionIceEvent| {
        if let Some(candidate) = event.candidate() {
            let candidate_str = candidate.candidate();
            if !candidate_str.is_empty() {
                let ice_data = IceCandidateData {
                    peer_id: peer_id_for_ice.clone(),
                    candidate: candidate_str,
                    sdp_mid: candidate.sdp_mid(),
                    sdp_m_line_index: candidate.sdp_m_line_index(),
                };

                WEBRTC_MANAGER.with(|manager| {
                    if let Some(manager) = manager.borrow_mut().as_mut() {
                        manager.pending_ice_candidates.push(ice_data);
                    }
                });
            }
        }
    }) as Box<dyn FnMut(_)>);

    pc.set_onicecandidate(Some(onicecandidate.as_ref().unchecked_ref()));

    // Set up connection state change callback
    let peer_id_for_state = remote_peer_id.clone();
    let pc_for_state = pc.clone();
    let onconnectionstatechange = Closure::wrap(Box::new(move || {
        let state = pc_for_state.connection_state();
        let conn_state: ConnectionState = state.into();

        WEBRTC_MANAGER.with(|manager| {
            if let Some(manager) = manager.borrow_mut().as_mut() {
                if let Some(conn) = manager.connections.get_mut(&peer_id_for_state) {
                    conn.state = conn_state;
                }
            }
        });
    }) as Box<dyn FnMut()>);

    pc.set_onconnectionstatechange(Some(onconnectionstatechange.as_ref().unchecked_ref()));

    // Set up data channel event callback (for receiving data channel)
    let peer_id_for_dc = remote_peer_id.clone();
    let ondatachannel = Closure::wrap(Box::new(move |event: RtcDataChannelEvent| {
        let dc = event.channel();

        // Set up message callback for this data channel
        let peer_id_for_message = peer_id_for_dc.clone();
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            if let Ok(array_buffer) = event.data().dyn_into::<js_sys::ArrayBuffer>() {
                let uint8_array = js_sys::Uint8Array::new(&array_buffer);
                let data = uint8_array.to_vec();

                WEBRTC_MANAGER.with(|manager| {
                    if let Some(manager) = manager.borrow_mut().as_mut() {
                        manager.pending_messages.push((peer_id_for_message.clone(), data));
                    }
                });
            }
        }) as Box<dyn FnMut(_)>);

        dc.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        // Store data channel
        WEBRTC_MANAGER.with(|manager| {
            if let Some(manager) = manager.borrow_mut().as_mut() {
                if let Some(conn) = manager.connections.get_mut(&peer_id_for_dc) {
                    conn.data_channel = Some(dc);
                    conn._onmessage = Some(onmessage);
                }
            }
        });
    }) as Box<dyn FnMut(_)>);

    pc.set_ondatachannel(Some(ondatachannel.as_ref().unchecked_ref()));

    // Set remote description (offer)
    let mut offer_desc_init = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    offer_desc_init.sdp(&offer_sdp);

    let set_remote_promise = pc.set_remote_description(&offer_desc_init);
    JsFuture::from(set_remote_promise).await?;

    // Create answer
    let answer_promise = pc.create_answer();
    let answer = JsFuture::from(answer_promise).await?;

    // Set local description
    let answer_sdp_value = Reflect::get(&answer, &JsValue::from_str("sdp"))?;
    let answer_sdp_str = answer_sdp_value.as_string()
        .ok_or_else(|| JsValue::from_str("Failed to get answer SDP string"))?;

    let mut answer_desc_init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
    answer_desc_init.sdp(&answer_sdp_str);

    let set_local_promise = pc.set_local_description(&answer_desc_init);
    JsFuture::from(set_local_promise).await?;

    // Store connection
    let connection = WebRtcConnection {
        peer_id: remote_peer_id.clone(),
        peer_connection: pc,
        data_channel: None, // Will be set by ondatachannel
        state: ConnectionState::Connecting,
        _onicecandidate: onicecandidate,
        _onconnectionstatechange: onconnectionstatechange,
        _ondatachannel: Some(ondatachannel),
        _onmessage: None, // Will be set by ondatachannel
        _onopen: None,
        _onclose: None,
    };

    WEBRTC_MANAGER.with(|manager| {
        if let Some(manager) = manager.borrow_mut().as_mut() {
            manager.connections.insert(remote_peer_id, connection);
        }
    });

    // Return answer SDP
    serde_wasm_bindgen::to_value(&answer_sdp_str)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Add ICE candidate
#[wasm_bindgen]
pub async fn webrtc_manager_add_ice_candidate(
    peer_id: String,
    candidate: String,
    sdp_mid: Option<String>,
    sdp_m_line_index: Option<u16>,
) -> Result<(), JsValue> {
    let pc = WEBRTC_MANAGER.with(|manager| {
        let manager = manager.borrow();
        let manager = manager.as_ref()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        let conn = manager.connections.get(&peer_id)
            .ok_or_else(|| JsValue::from_str("Connection not found"))?;

        Ok::<RtcPeerConnection, JsValue>(conn.peer_connection.clone())
    })?;

    let mut candidate_init = RtcIceCandidateInit::new(&candidate);
    if let Some(mid) = sdp_mid {
        candidate_init.sdp_mid(Some(&mid));
    }
    if let Some(index) = sdp_m_line_index {
        candidate_init.sdp_m_line_index(Some(index));
    }

    let ice_candidate = RtcIceCandidate::new(&candidate_init)?;
    let add_ice_promise = pc.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&ice_candidate));
    JsFuture::from(add_ice_promise).await?;

    Ok(())
}

/// Send data to a peer
#[wasm_bindgen]
pub fn webrtc_manager_send(peer_id: String, data: Vec<u8>) -> Result<(), JsValue> {
    WEBRTC_MANAGER.with(|manager| {
        let manager = manager.borrow();
        let manager = manager.as_ref()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        let conn = manager.connections.get(&peer_id)
            .ok_or_else(|| JsValue::from_str("Connection not found"))?;

        let dc = conn.data_channel.as_ref()
            .ok_or_else(|| JsValue::from_str("Data channel not available"))?;

        dc.send_with_u8_array(&data)?;

        Ok(())
    })
}

/// Get pending ICE candidates
#[wasm_bindgen]
pub fn webrtc_manager_pop_ice_candidates() -> Result<JsValue, JsValue> {
    WEBRTC_MANAGER.with(|manager| {
        let mut manager = manager.borrow_mut();
        let manager = manager.as_mut()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        let candidates = std::mem::take(&mut manager.pending_ice_candidates);

        serde_wasm_bindgen::to_value(&candidates)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get pending received messages
#[wasm_bindgen]
pub fn webrtc_manager_pop_messages() -> Result<JsValue, JsValue> {
    WEBRTC_MANAGER.with(|manager| {
        let mut manager = manager.borrow_mut();
        let manager = manager.as_mut()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        let messages = std::mem::take(&mut manager.pending_messages);

        serde_wasm_bindgen::to_value(&messages)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get connection state
#[wasm_bindgen]
pub fn webrtc_manager_get_connection_state(peer_id: String) -> Result<JsValue, JsValue> {
    WEBRTC_MANAGER.with(|manager| {
        let manager = manager.borrow();
        let manager = manager.as_ref()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        let conn = manager.connections.get(&peer_id)
            .ok_or_else(|| JsValue::from_str("Connection not found"))?;

        serde_wasm_bindgen::to_value(&conn.state)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Close connection
#[wasm_bindgen]
pub fn webrtc_manager_close_connection(peer_id: String) -> Result<(), JsValue> {
    WEBRTC_MANAGER.with(|manager| {
        let mut manager = manager.borrow_mut();
        let manager = manager.as_mut()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        if let Some(conn) = manager.connections.remove(&peer_id) {
            conn.peer_connection.close();
        }

        Ok(())
    })
}

/// Get number of active connections
#[wasm_bindgen]
pub fn webrtc_manager_connection_count() -> Result<usize, JsValue> {
    WEBRTC_MANAGER.with(|manager| {
        let manager = manager.borrow();
        let manager = manager.as_ref()
            .ok_or_else(|| JsValue::from_str("WebRTC manager not initialized"))?;

        Ok(manager.connections.len())
    })
}
