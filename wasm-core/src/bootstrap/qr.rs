// QR Code Support
// Generate and parse QR codes for peer discovery

use qrcode::{QrCode, EcLevel};
use qrcode::render::svg;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use wasm_bindgen::prelude::*;
use super::PeerInfo;

/// Error correction level for QR codes
/// Medium (15%) is a good balance between size and reliability
const ERROR_CORRECTION_LEVEL: EcLevel = EcLevel::M;

/// Maximum QR code data size (to keep codes scannable)
/// Version 10 at Medium EC can hold ~1663 bytes
const MAX_QR_DATA_SIZE: usize = 1600;

/// Generate QR code data (as PNG bytes) from PeerInfo
///
/// The PeerInfo is serialized to JSON, compressed with base64 encoding,
/// and then converted to a QR code. Returns the encoded base64 string
/// that can be embedded in the QR code.
pub fn generate_qr_code_data(peer_info: &PeerInfo) -> Result<String, String> {
    // Serialize to JSON
    let json = peer_info.to_json()?;

    // Encode to base64 for efficient QR representation
    let encoded = BASE64.encode(json.as_bytes());

    // Check size limit
    if encoded.len() > MAX_QR_DATA_SIZE {
        return Err(format!(
            "PeerInfo too large for QR code: {} bytes (max {})",
            encoded.len(),
            MAX_QR_DATA_SIZE
        ));
    }

    // Validate that we can generate a QR code from this data
    let _code = QrCode::with_error_correction_level(&encoded, ERROR_CORRECTION_LEVEL)
        .map_err(|e| format!("Failed to generate QR code: {:?}", e))?;

    // Return the base64 encoded string (to be embedded in QR code)
    Ok(encoded)
}

/// Generate QR code as SVG string from PeerInfo
///
/// This is useful for displaying the QR code in a web interface.
/// The SVG can be directly embedded in HTML.
#[wasm_bindgen]
pub fn generate_qr_code_svg(peer_info: &PeerInfo) -> Result<String, String> {
    // Serialize to JSON
    let json = peer_info.to_json()?;

    // Encode to base64
    let encoded = BASE64.encode(json.as_bytes());

    // Check size limit
    if encoded.len() > MAX_QR_DATA_SIZE {
        return Err(format!(
            "PeerInfo too large for QR code: {} bytes (max {})",
            encoded.len(),
            MAX_QR_DATA_SIZE
        ));
    }

    // Generate QR code
    let code = QrCode::with_error_correction_level(&encoded, ERROR_CORRECTION_LEVEL)
        .map_err(|e| format!("Failed to generate QR code: {:?}", e))?;

    // Render as SVG
    let svg = code.render::<svg::Color>()
        .min_dimensions(200, 200)
        .max_dimensions(800, 800)
        .build();

    Ok(svg)
}

/// Parse QR code data back to PeerInfo
///
/// Takes the scanned QR code data (as a string), decodes from base64,
/// deserializes from JSON, and returns the PeerInfo.
pub fn parse_qr_code_data(qr_data: &str) -> Result<PeerInfo, String> {
    // Validate input
    if qr_data.is_empty() {
        return Err("QR code data is empty".to_string());
    }

    if qr_data.len() > MAX_QR_DATA_SIZE {
        return Err(format!(
            "QR code data too large: {} bytes (max {})",
            qr_data.len(),
            MAX_QR_DATA_SIZE
        ));
    }

    // Decode from base64
    let decoded_bytes = BASE64.decode(qr_data)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

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

/// Check if PeerInfo can fit in a QR code
///
/// Returns Ok(size) if it fits, Err with size if it doesn't
pub fn check_qr_code_size(peer_info: &PeerInfo) -> Result<usize, String> {
    let json = peer_info.to_json()?;
    let encoded = BASE64.encode(json.as_bytes());
    let size = encoded.len();

    if size > MAX_QR_DATA_SIZE {
        Err(format!(
            "PeerInfo too large: {} bytes (max {})",
            size,
            MAX_QR_DATA_SIZE
        ))
    } else {
        Ok(size)
    }
}

/// Estimate QR code version (size) needed for PeerInfo
///
/// Returns the QR code version number (1-40) needed to encode the data
pub fn estimate_qr_code_version(peer_info: &PeerInfo) -> Result<i16, String> {
    let json = peer_info.to_json()?;
    let encoded = BASE64.encode(json.as_bytes());
    let size = encoded.len();

    // Rough estimation based on data capacity at Medium EC level
    // Version 1: ~77 bytes
    // Version 5: ~370 bytes
    // Version 10: ~1663 bytes
    // Version 15: ~2953 bytes
    let version = if size <= 77 {
        1
    } else if size <= 370 {
        5
    } else if size <= 1663 {
        10
    } else if size <= 2953 {
        15
    } else {
        return Err(format!("Data too large for QR code: {} bytes", size));
    };

    Ok(version)
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
    fn test_qr_code_generation_and_parsing() {
        let peer_info = create_test_peer_info();

        // Generate QR code data (returns base64 string)
        let encoded = generate_qr_code_data(&peer_info).unwrap();
        assert!(!encoded.is_empty());

        // Parse back
        let parsed = parse_qr_code_data(&encoded).unwrap();

        // Verify
        assert_eq!(parsed.peer_id, peer_info.peer_id);
        assert_eq!(parsed.version, peer_info.version);
        assert_eq!(parsed.signing_public_key, peer_info.signing_public_key);
        assert_eq!(parsed.encryption_public_key, peer_info.encryption_public_key);
    }

    #[test]
    fn test_qr_code_svg_generation() {
        let peer_info = create_test_peer_info();

        // Generate SVG
        let svg = generate_qr_code_svg(&peer_info).unwrap();

        // Verify it's valid SVG
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("xmlns"));
    }

    #[test]
    fn test_qr_code_size_check() {
        let peer_info = create_test_peer_info();

        // Should fit in QR code
        let size = check_qr_code_size(&peer_info).unwrap();
        assert!(size > 0);
        assert!(size <= MAX_QR_DATA_SIZE);
    }

    #[test]
    fn test_qr_code_version_estimation() {
        let peer_info = create_test_peer_info();

        // Should return a reasonable version number
        let version = estimate_qr_code_version(&peer_info).unwrap();
        assert!(version >= 1 && version <= 15);
    }

    #[test]
    fn test_invalid_qr_data() {
        // Empty string
        assert!(parse_qr_code_data("").is_err());

        // Invalid base64
        assert!(parse_qr_code_data("!!!invalid!!!").is_err());

        // Valid base64 but invalid JSON
        let invalid = BASE64.encode(b"not json");
        assert!(parse_qr_code_data(&invalid).is_err());
    }

    #[test]
    fn test_qr_code_round_trip() {
        let peer_info = create_test_peer_info();

        // Encode to base64 (simulating QR code scan)
        let json = peer_info.to_json().unwrap();
        let encoded = BASE64.encode(json.as_bytes());

        // Parse back
        let parsed = parse_qr_code_data(&encoded).unwrap();

        // Round-trip should be identical
        assert_eq!(parsed.peer_id, peer_info.peer_id);
        assert_eq!(parsed.signing_public_key, peer_info.signing_public_key);
        assert_eq!(parsed.encryption_public_key, peer_info.encryption_public_key);
        assert_eq!(parsed.connection_info.ice_servers.len(), peer_info.connection_info.ice_servers.len());
    }

    #[test]
    fn test_version_validation() {
        let mut peer_info = create_test_peer_info();

        // Create with invalid version
        peer_info.version = 99;

        let json = serde_json::to_string(&peer_info).unwrap();
        let encoded = BASE64.encode(json.as_bytes());

        // Should fail version check
        let result = parse_qr_code_data(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported PeerInfo version"));
    }
}
