//! Hierarchical Deterministic (HD) Key Derivation - CIP-1852 & BIP32-Ed25519

use crate::common::{CryptoError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Size of individual key component
pub const KEY_SIZE: usize = 32;

/// Size of chain code  
pub const CHAIN_CODE_SIZE: usize = 32;

/// Hardened derivation offset (2^31)
pub const HARDENED_OFFSET: u32 = 0x80000000;

/// CIP-1852 purpose constant
pub const PURPOSE_CIP1852: u32 = 1852;

/// Cardano coin type (1815 = Ada)
pub const COIN_TYPE_ADA: u32 = 1815;

/// Chain code for BIP32-Ed25519 hierarchical derivation
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct ChainCode([u8; CHAIN_CODE_SIZE]);

impl ChainCode {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; CHAIN_CODE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; CHAIN_CODE_SIZE] {
        &self.0
    }
}

impl core::fmt::Debug for ChainCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChainCode([REDACTED])")
    }
}

/// BIP32-Ed25519 extended private key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivateKey {
    key: [u8; KEY_SIZE],
    chain_code: ChainCode,
}

impl ExtendedPrivateKey {
    /// Create from seed
    pub fn from_seed(seed: &[u8]) -> Self {
        use sha2::{Digest, Sha512};

        let mut hasher = Sha512::new();
        hasher.update(b"ed25519 seed");
        hasher.update(seed);
        let hash = hasher.finalize();

        let mut key = [0u8; KEY_SIZE];
        let mut chain_code_bytes = [0u8; CHAIN_CODE_SIZE];

        key.copy_from_slice(&hash[0..32]);
        chain_code_bytes.copy_from_slice(&hash[32..64]);

        key[0] &= 0xF8;
        key[31] &= 0x7F;
        key[31] |= 0x40;

        Self {
            key,
            chain_code: ChainCode::from_bytes(&chain_code_bytes),
        }
    }

    /// Get key bytes
    pub fn key_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Get chain code
    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }

    /// Derive child key
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        use sha2::{Digest, Sha512};

        let hardened = index >= HARDENED_OFFSET;
        let mut data = Vec::with_capacity(37);

        if hardened {
            data.push(0x00);
            data.extend_from_slice(&self.key);
        } else {
            let pub_key = self.derive_public_key();
            data.extend_from_slice(&pub_key);
        }

        data.extend_from_slice(&index.to_be_bytes());

        let mut hasher = Sha512::new();
        hasher.update(self.chain_code.as_bytes());
        hasher.update(&data);
        let hash = hasher.finalize();

        let mut child_key = [0u8; KEY_SIZE];
        let mut child_chain_code = [0u8; CHAIN_CODE_SIZE];

        child_key.copy_from_slice(&hash[0..32]);
        child_chain_code.copy_from_slice(&hash[32..64]);

        child_key[0] &= 0xF8;
        child_key[31] &= 0x7F;
        child_key[31] |= 0x40;

        Ok(Self {
            key: child_key,
            chain_code: ChainCode::from_bytes(&child_chain_code),
        })
    }

    /// Derive child using path
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self> {
        let mut key = self.clone();
        for &index in path.as_slice() {
            key = key.derive_child(index)?;
        }
        Ok(key)
    }

    fn derive_public_key(&self) -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&self.key);
        signing_key.verifying_key().to_bytes()
    }

    /// Convert to public key
    pub fn to_public(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            key: self.derive_public_key(),
            chain_code: self.chain_code.clone(),
        }
    }
}

impl core::fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// BIP32-Ed25519 extended public key
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedPublicKey {
    key: [u8; KEY_SIZE],
    chain_code: ChainCode,
}

impl ExtendedPublicKey {
    /// Get key bytes
    pub fn key_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Get chain code
    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }
}

impl core::fmt::Debug for ExtendedPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedPublicKey").finish()
    }
}

/// BIP32 derivation path
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath {
    indices: Vec<u32>,
}

impl DerivationPath {
    /// Create new path
    pub fn new() -> Self {
        Self {
            indices: Vec::new(),
        }
    }

    /// Add hardened index
    pub fn push_hardened(&mut self, index: u32) {
        self.indices.push(index | HARDENED_OFFSET);
    }

    /// Get indices
    pub fn as_slice(&self) -> &[u32] {
        &self.indices
    }

    /// Create Cardano payment key path: m/1852'/1815'/account'/0/index
    pub fn cardano_payment(account: u32, index: u32) -> Self {
        Self {
            indices: vec![
                PURPOSE_CIP1852 | HARDENED_OFFSET,
                COIN_TYPE_ADA | HARDENED_OFFSET,
                account | HARDENED_OFFSET,
                0,
                index,
            ],
        }
    }

    /// Create Cardano stake key path: m/1852'/1815'/account'/2/index
    pub fn cardano_stake(account: u32, index: u32) -> Self {
        Self {
            indices: vec![
                PURPOSE_CIP1852 | HARDENED_OFFSET,
                COIN_TYPE_ADA | HARDENED_OFFSET,
                account | HARDENED_OFFSET,
                2,
                index,
            ],
        }
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self::new()
    }
}

pub mod address;
pub use address::{Address, Network, PaymentKeyHash, StakeKeyHash, hash_verification_key};
