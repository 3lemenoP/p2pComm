// Bootstrap API for JavaScript
// Provides QR code and invite link functionality

use wasm_bindgen::prelude::*;
use crate::bootstrap::{PeerInfo, ConnectionInfo};
use crate::bootstrap::qr::{generate_qr_code_svg, generate_qr_code_data, parse_qr_code_data};
use crate::bootstrap::invite::{generate_invite_link, parse_invite_link};
use crate::identity::PeerId;

/// Generate a PeerInfo JSON string from identity
#[wasm_bindgen]
pub fn create_peer_info(
    peer_id_hex: String,
    signing_public_key_hex: String,
    encryption_public_key_hex: String,
) -> Result<String, String> {
    // Parse peer ID
    let peer_id = PeerId::from_hex(&peer_id_hex)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    // Parse public keys from hex
    let signing_pk = hex::decode(&signing_public_key_hex)
        .map_err(|e| format!("Invalid signing public key: {}", e))?;

    let encryption_pk = hex::decode(&encryption_public_key_hex)
        .map_err(|e| format!("Invalid encryption public key: {}", e))?;

    // Create connection info with default STUN servers
    let conn_info = ConnectionInfo::new();

    // Create peer info
    let peer_info = PeerInfo::new(peer_id, signing_pk, encryption_pk, conn_info);

    // Serialize to JSON
    peer_info.to_json()
}

/// Generate QR code SVG from peer info
#[wasm_bindgen]
pub fn generate_qr_code(peer_info_json: String) -> Result<String, String> {
    let peer_info = PeerInfo::from_json(&peer_info_json)?;
    generate_qr_code_svg(&peer_info)
}

/// Parse QR code data to peer info
#[wasm_bindgen]
pub fn parse_qr_code(qr_data: String) -> Result<String, String> {
    let peer_info = parse_qr_code_data(&qr_data)?;
    peer_info.to_json()
}

/// Generate invite link from peer info
#[wasm_bindgen]
pub fn create_invite_link(peer_info_json: String) -> Result<String, String> {
    let peer_info = PeerInfo::from_json(&peer_info_json)?;
    generate_invite_link(&peer_info)
}

/// Parse invite link to peer info
#[wasm_bindgen]
pub fn parse_invite(invite_link: String) -> Result<String, String> {
    let peer_info = parse_invite_link(&invite_link)?;
    peer_info.to_json()
}

/// Add a direct address to connection info
#[wasm_bindgen]
pub fn add_direct_address(peer_info_json: String, address: String) -> Result<String, String> {
    let mut peer_info = PeerInfo::from_json(&peer_info_json)?;
    peer_info.connection_info.add_address(address);
    peer_info.to_json()
}

/// Check if peer info is expired
#[wasm_bindgen]
pub fn is_peer_info_expired(peer_info_json: String, max_age_hours: Option<u32>) -> Result<bool, String> {
    let peer_info = PeerInfo::from_json(&peer_info_json)?;
    let max_age_ms = max_age_hours.map(|h| (h as u64) * 60 * 60 * 1000);
    Ok(peer_info.is_expired(max_age_ms))
}

// ============================================================================
// Deep Link API - Parse and generate shareable URLs
// ============================================================================

use serde::{Serialize, Deserialize};

/// Deep link types supported by the application
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum DeepLinkData {
    /// Add a contact from their public identity
    AddContact {
        public_identity: String,
    },
    /// Initiate a WebRTC connection with an offer
    Connect {
        peer_id: String,
        offer: String,
    },
    /// Respond to a WebRTC offer with an answer
    Answer {
        peer_id: String,
        answer: String,
    },
    /// Unknown or invalid deep link
    Unknown {
        raw: String,
    },
}

/// Parse a URL hash fragment into structured deep link data
///
/// Supports the following formats:
/// - `#add-contact=<base64_public_identity>`
/// - `#connect=<base64_encoded_offer>`
/// - `#answer=<base64_encoded_answer>`
///
/// Returns JSON with { type, ...data }
#[wasm_bindgen]
pub fn parse_deep_link(url_hash: &str) -> Result<JsValue, JsValue> {
    // Remove leading # if present
    let hash = url_hash.strip_prefix('#').unwrap_or(url_hash);

    if hash.is_empty() {
        return Ok(JsValue::NULL);
    }

    let result = if let Some(data) = hash.strip_prefix("add-contact=") {
        // Decode base64 public identity
        match base64::decode(data) {
            Ok(bytes) => {
                match String::from_utf8(bytes) {
                    Ok(public_identity) => DeepLinkData::AddContact { public_identity },
                    Err(_) => DeepLinkData::Unknown { raw: hash.to_string() },
                }
            }
            Err(_) => DeepLinkData::Unknown { raw: hash.to_string() },
        }
    } else if let Some(data) = hash.strip_prefix("connect=") {
        // Parse connect data (peer_id:offer_base64)
        if let Some((peer_id, offer_b64)) = data.split_once(':') {
            match base64::decode(offer_b64) {
                Ok(bytes) => {
                    match String::from_utf8(bytes) {
                        Ok(offer) => DeepLinkData::Connect {
                            peer_id: peer_id.to_string(),
                            offer,
                        },
                        Err(_) => DeepLinkData::Unknown { raw: hash.to_string() },
                    }
                }
                Err(_) => DeepLinkData::Unknown { raw: hash.to_string() },
            }
        } else {
            DeepLinkData::Unknown { raw: hash.to_string() }
        }
    } else if let Some(data) = hash.strip_prefix("answer=") {
        // Parse answer data (peer_id:answer_base64)
        if let Some((peer_id, answer_b64)) = data.split_once(':') {
            match base64::decode(answer_b64) {
                Ok(bytes) => {
                    match String::from_utf8(bytes) {
                        Ok(answer) => DeepLinkData::Answer {
                            peer_id: peer_id.to_string(),
                            answer,
                        },
                        Err(_) => DeepLinkData::Unknown { raw: hash.to_string() },
                    }
                }
                Err(_) => DeepLinkData::Unknown { raw: hash.to_string() },
            }
        } else {
            DeepLinkData::Unknown { raw: hash.to_string() }
        }
    } else {
        DeepLinkData::Unknown { raw: hash.to_string() }
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Generate a contact sharing link from public identity JSON
///
/// Returns: `#add-contact=<base64_encoded_identity>`
#[wasm_bindgen]
pub fn generate_contact_link(public_identity_json: &str) -> String {
    let encoded = base64::encode(public_identity_json.as_bytes());
    format!("#add-contact={}", encoded)
}

/// Generate a WebRTC offer link for initiating connections
///
/// Returns: `#connect=<peer_id>:<base64_encoded_offer>`
#[wasm_bindgen]
pub fn generate_offer_link(peer_id: &str, offer_sdp: &str) -> String {
    let encoded = base64::encode(offer_sdp.as_bytes());
    format!("#connect={}:{}", peer_id, encoded)
}

/// Generate a WebRTC answer link for responding to offers
///
/// Returns: `#answer=<peer_id>:<base64_encoded_answer>`
#[wasm_bindgen]
pub fn generate_answer_link(peer_id: &str, answer_sdp: &str) -> String {
    let encoded = base64::encode(answer_sdp.as_bytes());
    format!("#answer={}:{}", peer_id, encoded)
}

/// Check if a URL hash contains a valid deep link
#[wasm_bindgen]
pub fn is_valid_deep_link(url_hash: &str) -> bool {
    let hash = url_hash.strip_prefix('#').unwrap_or(url_hash);
    hash.starts_with("add-contact=") ||
    hash.starts_with("connect=") ||
    hash.starts_with("answer=")
}

/// Get the type of deep link without fully parsing it
///
/// Returns: "add-contact", "connect", "answer", or "unknown"
#[wasm_bindgen]
pub fn get_deep_link_type(url_hash: &str) -> String {
    let hash = url_hash.strip_prefix('#').unwrap_or(url_hash);

    if hash.starts_with("add-contact=") {
        "add-contact".to_string()
    } else if hash.starts_with("connect=") {
        "connect".to_string()
    } else if hash.starts_with("answer=") {
        "answer".to_string()
    } else {
        "unknown".to_string()
    }
}
