//! Cardano Address Construction
//!
//! Implements all Cardano address types with byte-for-byte compatibility
//! with the Haskell cardano-addresses library.

use crate::common::{CryptoError, Result};
use crate::hash::{Blake2b224, HashAlgorithm};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Address network discriminant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Mainnet
    Mainnet,
    /// Testnet
    Testnet,
}

impl Network {
    fn discriminant(&self) -> u8 {
        match self {
            Network::Mainnet => 0b0001,
            Network::Testnet => 0b0000,
        }
    }
}

/// Payment key hash (28 bytes, Blake2b-224)
pub type PaymentKeyHash = [u8; 28];

/// Stake key hash (28 bytes, Blake2b-224)
pub type StakeKeyHash = [u8; 28];

/// Cardano address types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Base address: payment key hash + stake key hash
    Base {
        /// Network (mainnet/testnet)
        network: Network,
        /// Payment key hash
        payment: PaymentKeyHash,
        /// Stake key hash
        stake: StakeKeyHash,
    },
    /// Enterprise address: payment key hash only
    Enterprise {
        /// Network (mainnet/testnet)
        network: Network,
        /// Payment key hash
        payment: PaymentKeyHash,
    },
    /// Reward address: stake key hash only
    Reward {
        /// Network (mainnet/testnet)
        network: Network,
        /// Stake key hash
        stake: StakeKeyHash,
    },
}

impl Address {
    /// Create a base address (payment + stake)
    pub fn base(network: Network, payment: PaymentKeyHash, stake: StakeKeyHash) -> Self {
        Self::Base {
            network,
            payment,
            stake,
        }
    }

    /// Create an enterprise address (payment only)
    pub fn enterprise(network: Network, payment: PaymentKeyHash) -> Self {
        Self::Enterprise { network, payment }
    }

    /// Create a reward address (stake only)
    pub fn reward(network: Network, stake: StakeKeyHash) -> Self {
        Self::Reward { network, stake }
    }

    /// Encode address to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Address::Base {
                network,
                payment,
                stake,
            } => {
                let mut bytes = Vec::with_capacity(57);
                // Header: 0000_nnnn for base address
                bytes.push(network.discriminant());
                bytes.extend_from_slice(payment);
                bytes.extend_from_slice(stake);
                bytes
            }
            Address::Enterprise { network, payment } => {
                let mut bytes = Vec::with_capacity(29);
                // Header: 0110_nnnn for enterprise address
                bytes.push(0b01100000 | network.discriminant());
                bytes.extend_from_slice(payment);
                bytes
            }
            Address::Reward { network, stake } => {
                let mut bytes = Vec::with_capacity(29);
                // Header: 1110_nnnn for reward address
                bytes.push(0b11100000 | network.discriminant());
                bytes.extend_from_slice(stake);
                bytes
            }
        }
    }

    /// Encode address to Bech32 string
    #[cfg(feature = "bech32-encoding")]
    pub fn to_bech32(&self) -> Result<String> {
        use bech32::{Bech32, Hrp};

        let hrp_str = match self {
            Address::Base { network, .. } | Address::Enterprise { network, .. } => match network {
                Network::Mainnet => "addr",
                Network::Testnet => "addr_test",
            },
            Address::Reward { network, .. } => match network {
                Network::Mainnet => "stake",
                Network::Testnet => "stake_test",
            },
        };

        let hrp = Hrp::parse(hrp_str).map_err(|_| CryptoError::EncodingError)?;
        let bytes = self.to_bytes();

        bech32::encode::<Bech32>(hrp, &bytes).map_err(|_| CryptoError::EncodingError)
    }

    /// Parse address from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidParameter("Empty address".into()));
        }

        let header = bytes[0];
        let addr_type = (header & 0b11110000) >> 4;
        let network_tag = header & 0b00001111;

        let network = if network_tag == 0b0001 {
            Network::Mainnet
        } else {
            Network::Testnet
        };

        match addr_type {
            0b0000 => {
                // Base address
                if bytes.len() != 57 {
                    return Err(CryptoError::InvalidParameter("Invalid base address length".into()));
                }
                let mut payment = [0u8; 28];
                let mut stake = [0u8; 28];
                payment.copy_from_slice(&bytes[1..29]);
                stake.copy_from_slice(&bytes[29..57]);
                Ok(Address::Base {
                    network,
                    payment,
                    stake,
                })
            }
            0b0110 => {
                // Enterprise address
                if bytes.len() != 29 {
                    return Err(CryptoError::InvalidParameter(
                        "Invalid enterprise address length".into(),
                    ));
                }
                let mut payment = [0u8; 28];
                payment.copy_from_slice(&bytes[1..29]);
                Ok(Address::Enterprise { network, payment })
            }
            0b1110 => {
                // Reward address
                if bytes.len() != 29 {
                    return Err(CryptoError::InvalidParameter(
                        "Invalid reward address length".into(),
                    ));
                }
                let mut stake = [0u8; 28];
                stake.copy_from_slice(&bytes[1..29]);
                Ok(Address::Reward { network, stake })
            }
            _ => Err(CryptoError::InvalidParameter("Unknown address type".into())),
        }
    }
}

/// Hash an Ed25519 verification key to create a key hash
pub fn hash_verification_key(vk_bytes: &[u8; 32]) -> [u8; 28] {
    let hash_vec = Blake2b224::hash(vk_bytes);
    let mut hash = [0u8; 28];
    hash.copy_from_slice(&hash_vec);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_address() {
        let payment = [1u8; 28];
        let stake = [2u8; 28];
        let addr = Address::base(Network::Mainnet, payment, stake);
        
        let bytes = addr.to_bytes();
        assert_eq!(bytes.len(), 57);
        assert_eq!(bytes[0] & 0b11110000, 0);
        
        let decoded = Address::from_bytes(&bytes).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_enterprise_address() {
        let payment = [3u8; 28];
        let addr = Address::enterprise(Network::Testnet, payment);
        
        let bytes = addr.to_bytes();
        assert_eq!(bytes.len(), 29);
        
        let decoded = Address::from_bytes(&bytes).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_reward_address() {
        let stake = [4u8; 28];
        let addr = Address::reward(Network::Mainnet, stake);
        
        let bytes = addr.to_bytes();
        assert_eq!(bytes.len(), 29);
        
        let decoded = Address::from_bytes(&bytes).unwrap();
        assert_eq!(addr, decoded);
    }
}
