// Identity Manager Module
// Manages user identity and contacts

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use crate::crypto::{
    hash, Blake3Hash, Ed25519KeyPair, IdentityKeyPair, X25519KeyPair,
    decrypt_symmetric, encrypt_symmetric, derive_key_from_password_fixed,
};

/// Error types for identity operations
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Identity not found")]
    NotFound,

    #[error("Contact already exists")]
    ContactExists,

    #[error("Contact not found")]
    ContactNotFound,

    #[error("Invalid peer ID")]
    InvalidPeerId,

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type IdentityResult<T> = Result<T, IdentityError>;

/// Peer ID derived from public key hash
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerId {
    pub hash: Blake3Hash,
}

impl PeerId {
    /// Create a PeerId from a public key
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let hash = hash(public_key);
        PeerId { hash }
    }

    /// Create from hash bytes
    pub fn from_hash(hash: Blake3Hash) -> Self {
        PeerId { hash }
    }

    /// Get as hex string
    pub fn to_hex(&self) -> String {
        self.hash.to_hex()
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> IdentityResult<Self> {
        let hash = Blake3Hash::from_hex(hex)
            .map_err(|_e| IdentityError::InvalidPeerId)?;
        Ok(PeerId { hash })
    }

    /// Get the hash bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.hash.bytes
    }
}

/// User Identity
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub peer_id: PeerId,
    pub display_name: String,
    pub keypair: IdentityKeyPair,
    pub created_at: u64,
}

impl Identity {
    /// Create a new identity
    pub fn new(display_name: String) -> IdentityResult<Self> {
        let keypair = IdentityKeyPair::generate()
            .map_err(|e| IdentityError::CryptoError(e.to_string()))?;

        // Derive peer ID from signing public key
        let peer_id = PeerId::from_public_key(&keypair.signing_keypair.public_key_bytes());

        let created_at = js_sys::Date::now() as u64;

        Ok(Identity {
            peer_id,
            display_name,
            keypair,
            created_at,
        })
    }

    /// Export identity as encrypted bytes
    pub fn export(&self, password: &str) -> IdentityResult<Vec<u8>> {
        // Serialize identity
        let serialized = bincode::serialize(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // Derive encryption key from password
        let salt = self.peer_id.as_bytes();
        let key = derive_key_from_password_fixed(password, salt, 32)
            .map_err(|e| IdentityError::CryptoError(e.to_string()))?;

        // Encrypt
        let encrypted = encrypt_symmetric(&serialized, &key)
            .map_err(|e| IdentityError::CryptoError(e.to_string()))?;

        Ok(encrypted)
    }

    /// Import identity from encrypted bytes
    pub fn import(encrypted: &[u8], password: &str, peer_id: &PeerId) -> IdentityResult<Self> {
        // Derive decryption key
        let salt = peer_id.as_bytes();
        let key = derive_key_from_password_fixed(password, salt, 32)
            .map_err(|e| IdentityError::CryptoError(e.to_string()))?;

        // Decrypt
        let serialized = decrypt_symmetric(encrypted, &key)
            .map_err(|e| IdentityError::CryptoError(e.to_string()))?;

        // Deserialize
        let identity: Identity = bincode::deserialize(&serialized)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // Verify peer ID matches
        if identity.peer_id != *peer_id {
            return Err(IdentityError::InvalidPeerId);
        }

        Ok(identity)
    }

    /// Get public identity info (safe to share)
    pub fn public_info(&self) -> PublicIdentity {
        PublicIdentity {
            peer_id: self.peer_id.clone(),
            display_name: self.display_name.clone(),
            signing_public_key: self.keypair.signing_keypair.public_key_bytes(),
            encryption_public_key: self.keypair.encryption_keypair.public_key_bytes(),
        }
    }
}

/// Public identity information (can be shared)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub peer_id: PeerId,
    pub display_name: String,
    pub signing_public_key: Vec<u8>,
    pub encryption_public_key: Vec<u8>,
}

impl PublicIdentity {
    /// Verify that the peer ID matches the public key
    pub fn verify(&self) -> bool {
        let derived_peer_id = PeerId::from_public_key(&self.signing_public_key);
        derived_peer_id == self.peer_id
    }
}

/// Contact information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub peer_id: PeerId,
    pub display_name: String,
    pub signing_public_key: Vec<u8>,
    pub encryption_public_key: Vec<u8>,
    pub verified: bool,
    pub added_at: u64,
    pub last_seen: Option<u64>,
    pub notes: Option<String>,
}

impl Contact {
    /// Create a new contact from public identity
    pub fn from_public_identity(public_identity: PublicIdentity) -> Self {
        let added_at = js_sys::Date::now() as u64;
        let verified = public_identity.verify();

        Contact {
            peer_id: public_identity.peer_id,
            display_name: public_identity.display_name,
            signing_public_key: public_identity.signing_public_key,
            encryption_public_key: public_identity.encryption_public_key,
            verified,
            added_at,
            last_seen: None,
            notes: None,
        }
    }

    /// Update last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = Some(js_sys::Date::now() as u64);
    }

    /// Get signing public key as Ed25519
    pub fn get_signing_key(&self) -> IdentityResult<ed25519_dalek::VerifyingKey> {
        if self.signing_public_key.len() != 32 {
            return Err(IdentityError::CryptoError("Invalid key length".to_string()));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.signing_public_key);

        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|e| IdentityError::CryptoError(e.to_string()))
    }

    /// Get encryption public key as X25519
    pub fn get_encryption_key(&self) -> IdentityResult<x25519_dalek::PublicKey> {
        if self.encryption_public_key.len() != 32 {
            return Err(IdentityError::CryptoError("Invalid key length".to_string()));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.encryption_public_key);

        Ok(x25519_dalek::PublicKey::from(bytes))
    }
}

/// Identity Manager - manages user identity and contacts
pub struct IdentityManager {
    identity: Option<Identity>,
    contacts: HashMap<PeerId, Contact>,
}

impl IdentityManager {
    /// Create a new identity manager
    pub fn new() -> Self {
        IdentityManager {
            identity: None,
            contacts: HashMap::new(),
        }
    }

    /// Create a new identity
    pub fn create_identity(&mut self, display_name: String) -> IdentityResult<PeerId> {
        let identity = Identity::new(display_name)?;
        let peer_id = identity.peer_id.clone();
        self.identity = Some(identity);
        Ok(peer_id)
    }

    /// Load an existing identity
    pub fn load_identity(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }

    /// Get current identity
    pub fn get_identity(&self) -> IdentityResult<&Identity> {
        self.identity.as_ref().ok_or(IdentityError::NotFound)
    }

    /// Get mutable identity
    pub fn get_identity_mut(&mut self) -> IdentityResult<&mut Identity> {
        self.identity.as_mut().ok_or(IdentityError::NotFound)
    }

    /// Check if identity exists
    pub fn has_identity(&self) -> bool {
        self.identity.is_some()
    }

    /// Add a contact
    pub fn add_contact(&mut self, contact: Contact) -> IdentityResult<()> {
        if self.contacts.contains_key(&contact.peer_id) {
            return Err(IdentityError::ContactExists);
        }

        self.contacts.insert(contact.peer_id.clone(), contact);
        Ok(())
    }

    /// Add contact from public identity
    pub fn add_contact_from_public(&mut self, public_identity: PublicIdentity) -> IdentityResult<()> {
        let contact = Contact::from_public_identity(public_identity);
        self.add_contact(contact)
    }

    /// Get a contact
    pub fn get_contact(&self, peer_id: &PeerId) -> IdentityResult<&Contact> {
        self.contacts.get(peer_id).ok_or(IdentityError::ContactNotFound)
    }

    /// Get mutable contact
    pub fn get_contact_mut(&mut self, peer_id: &PeerId) -> IdentityResult<&mut Contact> {
        self.contacts.get_mut(peer_id).ok_or(IdentityError::ContactNotFound)
    }

    /// Remove a contact
    pub fn remove_contact(&mut self, peer_id: &PeerId) -> IdentityResult<()> {
        self.contacts.remove(peer_id).ok_or(IdentityError::ContactNotFound)?;
        Ok(())
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Vec<&Contact> {
        self.contacts.values().collect()
    }

    /// Update contact's last seen
    pub fn update_contact_last_seen(&mut self, peer_id: &PeerId) -> IdentityResult<()> {
        let contact = self.get_contact_mut(peer_id)?;
        contact.update_last_seen();
        Ok(())
    }

    /// Update contact display name
    pub fn update_contact_name(&mut self, peer_id: &PeerId, name: String) -> IdentityResult<()> {
        let contact = self.get_contact_mut(peer_id)?;
        contact.display_name = name;
        Ok(())
    }

    /// Add notes to a contact
    pub fn update_contact_notes(&mut self, peer_id: &PeerId, notes: String) -> IdentityResult<()> {
        let contact = self.get_contact_mut(peer_id)?;
        contact.notes = Some(notes);
        Ok(())
    }

    /// Mark contact as verified
    pub fn verify_contact(&mut self, peer_id: &PeerId) -> IdentityResult<()> {
        let contact = self.get_contact_mut(peer_id)?;
        contact.verified = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_identity() {
        let identity = Identity::new("Alice".to_string()).unwrap();
        assert_eq!(identity.display_name, "Alice");
        assert_eq!(identity.peer_id.as_bytes().len(), 32);
    }

    #[test]
    fn test_peer_id_from_public_key() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key_bytes();

        let peer_id1 = PeerId::from_public_key(&public_key);
        let peer_id2 = PeerId::from_public_key(&public_key);

        assert_eq!(peer_id1, peer_id2);
    }

    #[test]
    fn test_identity_export_import() {
        let identity = Identity::new("Alice".to_string()).unwrap();
        let password = "super_secret_password";

        let exported = identity.export(password).unwrap();
        let imported = Identity::import(&exported, password, &identity.peer_id).unwrap();

        assert_eq!(identity.peer_id, imported.peer_id);
        assert_eq!(identity.display_name, imported.display_name);
    }

    #[test]
    fn test_public_identity_verify() {
        let identity = Identity::new("Bob".to_string()).unwrap();
        let public_info = identity.public_info();

        assert!(public_info.verify());
    }

    #[test]
    fn test_identity_manager() {
        let mut manager = IdentityManager::new();

        assert!(!manager.has_identity());

        let peer_id = manager.create_identity("Alice".to_string()).unwrap();
        assert!(manager.has_identity());

        let identity = manager.get_identity().unwrap();
        assert_eq!(identity.peer_id, peer_id);
    }

    #[test]
    fn test_contact_management() {
        let mut manager = IdentityManager::new();
        manager.create_identity("Alice".to_string()).unwrap();

        // Create a contact
        let bob_identity = Identity::new("Bob".to_string()).unwrap();
        let bob_public = bob_identity.public_info();

        // Add contact
        manager.add_contact_from_public(bob_public.clone()).unwrap();

        // Get contact
        let contact = manager.get_contact(&bob_public.peer_id).unwrap();
        assert_eq!(contact.display_name, "Bob");
        assert!(contact.verified);

        // List contacts
        let contacts = manager.list_contacts();
        assert_eq!(contacts.len(), 1);

        // Update last seen
        manager.update_contact_last_seen(&bob_public.peer_id).unwrap();
        let contact = manager.get_contact(&bob_public.peer_id).unwrap();
        assert!(contact.last_seen.is_some());

        // Remove contact
        manager.remove_contact(&bob_public.peer_id).unwrap();
        assert_eq!(manager.list_contacts().len(), 0);
    }

    #[test]
    fn test_contact_duplicate() {
        let mut manager = IdentityManager::new();
        manager.create_identity("Alice".to_string()).unwrap();

        let bob_identity = Identity::new("Bob".to_string()).unwrap();
        let bob_public = bob_identity.public_info();

        manager.add_contact_from_public(bob_public.clone()).unwrap();

        // Try to add same contact again
        let result = manager.add_contact_from_public(bob_public);
        assert!(result.is_err());
    }
}
