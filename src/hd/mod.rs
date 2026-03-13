//! Hierarchical Deterministic (HD) Key Derivation - CIP-1852 & BIP32-Ed25519
//!
//! Implements the BIP32-Ed25519 key derivation scheme (Khovratovich & Law, 2017)
//! as used by Cardano wallets. Extended private keys are 64 bytes (kL || kR)
//! where kL is the Ed25519 scalar and kR is used in child derivation.

use crate::common::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

/// Size of extended key (kL + kR)
pub const EXTENDED_KEY_SIZE: usize = 64;

/// Size of individual key component (kL or kR)
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
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: &[u8; CHAIN_CODE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Get bytes
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CHAIN_CODE_SIZE] {
        &self.0
    }
}

impl core::fmt::Debug for ChainCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChainCode([REDACTED])")
    }
}

/// Add two 256-bit little-endian integers, returning result mod 2^256
fn add_256_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

/// Add a 28-byte little-endian integer * 8 to a 32-byte little-endian integer.
///
/// Computes: result = parent + zL_28 * 8 (mod 2^256)
/// This matches the BIP32-Ed25519 child scalar derivation: kL_child = 8 * zL + kL_parent
fn add_scalar_mul8(parent: &[u8; 32], z_left: &[u8; 32]) -> [u8; 32] {
    // First compute zL[0..28] * 8 as a 32-byte LE value (only first 28 bytes of z_left matter)
    let mut zl8 = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..28 {
        let val = u16::from(z_left[i]) * 8 + carry;
        zl8[i] = val as u8;
        carry = val >> 8;
    }
    // Carry into bytes 28..31
    for byte in zl8.iter_mut().skip(28) {
        let val = carry;
        *byte = val as u8;
        carry = val >> 8;
    }

    add_256_le(parent, &zl8)
}

/// BIP32-Ed25519 extended private key
///
/// Contains kL (32 bytes, clamped Ed25519 scalar), kR (32 bytes, used in
/// child derivation), and a chain code.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedPrivateKey {
    /// kL: the Ed25519 private scalar (clamped)
    key_left: [u8; KEY_SIZE],
    /// kR: right half, used for child key derivation
    key_right: [u8; KEY_SIZE],
    chain_code: ChainCode,
}

impl ExtendedPrivateKey {
    /// Create from seed using HMAC-SHA-512
    ///
    /// Matches BIP32-Ed25519 / cardano-addresses: HMAC-SHA-512 with key "ed25519 seed"
    /// The 64-byte output is split into kL (left 32, clamped) and kR (right 32).
    ///
    /// # Errors
    ///
    /// Returns error if HMAC initialization fails (should not happen in practice).
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed").map_err(|_| {
            crate::common::error::CryptoError::InvalidKeyLength {
                expected: 12,
                got: 0,
            }
        })?;
        mac.update(seed);
        let hash = mac.finalize().into_bytes();

        let mut key_left = [0u8; KEY_SIZE];
        let mut key_right = [0u8; KEY_SIZE];
        let mut chain_code_bytes = [0u8; CHAIN_CODE_SIZE];

        key_left.copy_from_slice(&hash[0..32]);
        key_right.copy_from_slice(&hash[32..64]);

        // Zeroize hash output containing key material
        let mut hash_bytes = [0u8; 64];
        hash_bytes.copy_from_slice(&hash);
        hash_bytes.zeroize();

        // Clamp kL — only done for root key
        key_left[0] &= 0xF8;
        key_left[31] &= 0x7F;
        key_left[31] |= 0x40;

        // Derive chain code from a second HMAC pass
        let mut cc_mac =
            Hmac::<Sha512>::new_from_slice(b"ed25519 seed").map_err(|_| {
                crate::common::error::CryptoError::InvalidKeyLength {
                    expected: 12,
                    got: 0,
                }
            })?;
        cc_mac.update(&[0x01]);
        cc_mac.update(seed);
        let cc_hash = cc_mac.finalize().into_bytes();
        chain_code_bytes.copy_from_slice(&cc_hash[32..64]);

        Ok(Self {
            key_left,
            key_right,
            chain_code: ChainCode::from_bytes(&chain_code_bytes),
        })
    }

    /// Get the left key bytes (kL — the Ed25519 scalar)
    #[inline]
    #[must_use]
    pub fn key_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key_left
    }

    /// Get the right key bytes (kR)
    #[inline]
    #[must_use]
    pub fn key_right_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key_right
    }

    /// Get chain code
    #[inline]
    #[must_use]
    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }

    /// Derive child key using BIP32-Ed25519 (Khovratovich & Law)
    ///
    /// For hardened derivation (index >= 2^31):
    ///   Z = HMAC-SHA-512(cc, 0x00 || kL || kR || index_LE)
    ///   child_cc from HMAC-SHA-512(cc, 0x01 || kL || kR || index_LE)
    ///
    /// For normal derivation:
    ///   Z = HMAC-SHA-512(cc, 0x02 || public_key || index_LE)
    ///   child_cc from HMAC-SHA-512(cc, 0x03 || public_key || index_LE)
    ///
    /// kL_child = 8 * Z[0..28] + kL_parent (scalar addition, no re-clamping)
    /// kR_child = Z[32..64] + kR_parent (mod 2^256)
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let hardened = index >= HARDENED_OFFSET;
        let index_le = index.to_le_bytes();

        // Compute Z
        let mut z_data = Vec::with_capacity(69);
        if hardened {
            z_data.push(0x00);
            z_data.extend_from_slice(&self.key_left);
            z_data.extend_from_slice(&self.key_right);
        } else {
            z_data.push(0x02);
            let pub_key = self.derive_public_key();
            z_data.extend_from_slice(&pub_key);
        }
        z_data.extend_from_slice(&index_le);

        let mut z_mac = Hmac::<Sha512>::new_from_slice(self.chain_code.as_bytes()).map_err(
            |_| crate::common::error::CryptoError::InvalidKeyLength {
                expected: CHAIN_CODE_SIZE,
                got: 0,
            },
        )?;
        z_mac.update(&z_data);
        let z = z_mac.finalize().into_bytes();

        // Compute child chain code
        let mut cc_data = Vec::with_capacity(69);
        if hardened {
            cc_data.push(0x01);
            cc_data.extend_from_slice(&self.key_left);
            cc_data.extend_from_slice(&self.key_right);
        } else {
            cc_data.push(0x03);
            let pub_key = self.derive_public_key();
            cc_data.extend_from_slice(&pub_key);
        }
        cc_data.extend_from_slice(&index_le);

        let mut cc_mac = Hmac::<Sha512>::new_from_slice(self.chain_code.as_bytes()).map_err(
            |_| crate::common::error::CryptoError::InvalidKeyLength {
                expected: CHAIN_CODE_SIZE,
                got: 0,
            },
        )?;
        cc_mac.update(&cc_data);
        let cc_hash = cc_mac.finalize().into_bytes();

        // Zeroize data vecs (may contain secret key bytes)
        z_data.zeroize();
        cc_data.zeroize();

        // kL_child = 8 * Z[0..28] + kL_parent
        let mut z_left = [0u8; 32];
        z_left[..32].copy_from_slice(&z[0..32]);
        let child_key_left = add_scalar_mul8(&self.key_left, &z_left);

        // kR_child = Z[32..64] + kR_parent (mod 2^256)
        let mut z_right = [0u8; 32];
        z_right.copy_from_slice(&z[32..64]);
        let child_key_right = add_256_le(&self.key_right, &z_right);

        // Child chain code is right half of cc_hash
        let mut child_chain_code = [0u8; CHAIN_CODE_SIZE];
        child_chain_code.copy_from_slice(&cc_hash[32..64]);

        // Zeroize intermediates
        z_left.zeroize();
        z_right.zeroize();

        Ok(Self {
            key_left: child_key_left,
            key_right: child_key_right,
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
        let signing_key = SigningKey::from_bytes(&self.key_left);
        signing_key.verifying_key().to_bytes()
    }

    /// Convert to public key
    #[must_use]
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
    #[inline]
    #[must_use]
    pub fn key_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Get chain code
    #[inline]
    #[must_use]
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
    #[must_use]
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
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u32] {
        &self.indices
    }

    /// Create Cardano payment key path: m/1852'/1815'/account'/0/index
    #[must_use]
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
    #[must_use]
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
pub use address::{Address, Network, hash_verification_key};

// Re-export typed key hashes from key::hash module
pub use crate::key::hash::{PaymentKeyHash, StakeKeyHash};
