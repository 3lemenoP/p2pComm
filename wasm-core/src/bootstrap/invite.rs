// Invite Link Support
// Generate and parse invite links for peer discovery

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL};
use super::PeerInfo;

/// Invite link prefix for peer discovery
const INVITE_PREFIX: &str = "p2p://invite/";

/// Generate an invite link from PeerInfo
///
/// Format: p2p://invite/<base64url-encoded-peer-info>
/// The base64url encoding makes the link URL-safe without percent encoding
pub fn generate_invite_link(peer_info: &PeerInfo) -> Result<String, String> {
    // Serialize to JSON
    let json = peer_info.to_json()?;

    // Encode to base64url (URL-safe, no padding)
    let encoded = BASE64_URL.encode(json.as_bytes());

    // Create invite link
    let link = format!("{}{}", INVITE_PREFIX, encoded);

    Ok(link)
}

/// Parse an invite link back to PeerInfo
///
/// Accepts links in the format: p2p://invite/<base64url-encoded-peer-info>
pub fn parse_invite_link(link: &str) -> Result<PeerInfo, String> {
    // Validate prefix
    if !link.starts_with(INVITE_PREFIX) {
        return Err(format!("Invalid invite link prefix. Expected '{}'", INVITE_PREFIX));
    }

    // Extract base64 data
    let encoded = &link[INVITE_PREFIX.len()..];

    if encoded.is_empty() {
        return Err("Invite link contains no data".to_string());
    }

    // Decode from base64url
    let decoded_bytes = BASE64_URL.decode(encoded)
        .map_err(|e| format!("Failed to decode invite link: {}", e))?;

    // Convert to UTF-8 string
    let json = String::from_utf8(decoded_bytes)
        .map_err(|e| format!("Failed to convert to UTF-8: {}", e))?;

    // Deserialize from JSON
    let peer_info = PeerInfo::from_json(&json)?;

    // Validate version
    if peer_info.version != PeerInfo::VERSION {
        return Err(format!(
            "Unsupported PeerInfo version: {} (expected {})",
            peer_info.version,
            PeerInfo::VERSION
        ));
    }

    Ok(peer_info)
}

/// Check if a string is a valid invite link
pub fn is_valid_invite_link(link: &str) -> bool {
    parse_invite_link(link).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;
    use crate::identity::PeerId;
    use crate::bootstrap::ConnectionInfo;

    fn create_test_peer_info() -> PeerInfo {
        let keypair = IdentityKeyPair::generate().unwrap();
        let peer_id = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let signing_pk = keypair.signing_keypair.verifying_key.to_bytes().to_vec();
        let encryption_pk = keypair.encryption_keypair.public_key.as_bytes().to_vec();
        let conn_info = ConnectionInfo::new();

        PeerInfo::new(peer_id, signing_pk, encryption_pk, conn_info)
    }

    #[test]
    fn test_invite_link_generation_and_parsing() {
        let peer_info = create_test_peer_info();

        // Generate invite link
        let link = generate_invite_link(&peer_info).unwrap();
        assert!(link.starts_with(INVITE_PREFIX));

        // Parse back
        let parsed = parse_invite_link(&link).unwrap();

        // Verify
        assert_eq!(parsed.peer_id, peer_info.peer_id);
        assert_eq!(parsed.version, peer_info.version);
        assert_eq!(parsed.signing_public_key, peer_info.signing_public_key);
    }

    #[test]
    fn test_is_valid_invite_link() {
        let peer_info = create_test_peer_info();
        let link = generate_invite_link(&peer_info).unwrap();

        assert!(is_valid_invite_link(&link));
        assert!(!is_valid_invite_link("not-a-link"));
        assert!(!is_valid_invite_link("http://example.com"));
    }

    #[test]
    fn test_invalid_invite_link() {
        assert!(parse_invite_link("p2p://invite/").is_err());
        assert!(parse_invite_link("http://invite/data").is_err());
        assert!(parse_invite_link("p2p://invite/!!!invalid!!!").is_err());
    }

    #[test]
    fn test_invite_link_round_trip() {
        let peer_info = create_test_peer_info();

        let link = generate_invite_link(&peer_info).unwrap();
        let parsed = parse_invite_link(&link).unwrap();

        assert_eq!(parsed.peer_id, peer_info.peer_id);
        assert_eq!(parsed.signing_public_key, peer_info.signing_public_key);
        assert_eq!(parsed.encryption_public_key, peer_info.encryption_public_key);
    }
}
