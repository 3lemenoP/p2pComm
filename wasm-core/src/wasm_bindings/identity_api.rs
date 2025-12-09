// Identity API for JavaScript
// Provides identity management functions

use wasm_bindgen::prelude::*;
use crate::identity::{PeerId, Identity, Contact, PublicIdentity};

/// Create a new identity with a display name
/// Returns a JSON string with the identity information
#[wasm_bindgen]
pub fn create_identity(display_name: String) -> Result<String, String> {
    let identity = Identity::new(display_name)
        .map_err(|e| format!("Failed to create identity: {:?}", e))?;

    // Serialize to JSON
    serde_json::to_string(&identity)
        .map_err(|e| format!("Failed to serialize identity: {}", e))
}

/// Export identity as encrypted bytes (for backup)
/// Returns hex-encoded encrypted data
#[wasm_bindgen]
pub fn export_identity(identity_json: String, password: String) -> Result<String, String> {
    // Deserialize identity
    let identity: Identity = serde_json::from_str(&identity_json)
        .map_err(|e| format!("Failed to deserialize identity: {}", e))?;

    // Export with password
    let encrypted_bytes = identity.export(&password)
        .map_err(|e| format!("Failed to export identity: {:?}", e))?;

    // Return as hex
    Ok(hex::encode(encrypted_bytes))
}

/// Import identity from encrypted bytes
#[wasm_bindgen]
pub fn import_identity(encrypted_hex: String, password: String, peer_id_hex: String) -> Result<String, String> {
    // Decode hex
    let encrypted_bytes = hex::decode(&encrypted_hex)
        .map_err(|e| format!("Invalid hex data: {}", e))?;

    // Parse peer ID
    let peer_id = PeerId::from_hex(&peer_id_hex)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    // Import identity
    let identity = Identity::import(&encrypted_bytes, &password, &peer_id)
        .map_err(|e| format!("Failed to import identity: {:?}", e))?;

    // Serialize to JSON
    serde_json::to_string(&identity)
        .map_err(|e| format!("Failed to serialize identity: {}", e))
}

/// Get peer ID from identity
#[wasm_bindgen]
pub fn get_peer_id(identity_json: String) -> Result<String, String> {
    let identity: Identity = serde_json::from_str(&identity_json)
        .map_err(|e| format!("Failed to deserialize identity: {}", e))?;

    Ok(identity.peer_id.to_hex())
}

/// Get public identity (safe to share)
#[wasm_bindgen]
pub fn get_public_identity(identity_json: String) -> Result<String, String> {
    let identity: Identity = serde_json::from_str(&identity_json)
        .map_err(|e| format!("Failed to deserialize identity: {}", e))?;

    let public_identity = identity.public_info();

    serde_json::to_string(&public_identity)
        .map_err(|e| format!("Failed to serialize public identity: {}", e))
}

/// Create a contact from public identity
#[wasm_bindgen]
pub fn create_contact_from_public_identity(
    public_identity_json: String,
) -> Result<String, String> {
    let public_identity: PublicIdentity = serde_json::from_str(&public_identity_json)
        .map_err(|e| format!("Failed to deserialize public identity: {}", e))?;

    let contact = Contact::from_public_identity(public_identity);

    serde_json::to_string(&contact)
        .map_err(|e| format!("Failed to serialize contact: {}", e))
}

/// Verify a public identity's peer ID matches the public key
#[wasm_bindgen]
pub fn verify_public_identity(public_identity_json: String) -> Result<bool, String> {
    let public_identity: PublicIdentity = serde_json::from_str(&public_identity_json)
        .map_err(|e| format!("Failed to deserialize public identity: {}", e))?;

    Ok(public_identity.verify())
}

/// Derive peer ID from signing public key (Blake3 hash)
#[wasm_bindgen]
pub fn derive_peer_id_from_public_key(public_key_hex: String) -> Result<String, String> {
    let public_key_bytes = hex::decode(&public_key_hex)
        .map_err(|e| format!("Invalid public key hex: {}", e))?;

    let peer_id = PeerId::from_public_key(&public_key_bytes);

    Ok(peer_id.to_hex())
}

/// Get contact's peer ID
#[wasm_bindgen]
pub fn get_contact_peer_id(contact_json: String) -> Result<String, String> {
    let contact: Contact = serde_json::from_str(&contact_json)
        .map_err(|e| format!("Failed to deserialize contact: {}", e))?;

    Ok(contact.peer_id.to_hex())
}

/// Parse peer ID from hex string
#[wasm_bindgen]
pub fn parse_peer_id(hex: String) -> Result<String, String> {
    let peer_id = PeerId::from_hex(&hex)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    Ok(peer_id.to_hex())
}

/// Hash password for verification (for UI password strength indicator)
#[wasm_bindgen]
pub fn check_password_strength(password: String) -> u32 {
    // Simple strength check based on length and character variety
    let len_score = (password.len() as u32).min(20) * 2;

    let mut variety_score = 0;
    if password.chars().any(|c| c.is_lowercase()) {
        variety_score += 10;
    }
    if password.chars().any(|c| c.is_uppercase()) {
        variety_score += 10;
    }
    if password.chars().any(|c| c.is_numeric()) {
        variety_score += 10;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        variety_score += 10;
    }

    len_score + variety_score
}
