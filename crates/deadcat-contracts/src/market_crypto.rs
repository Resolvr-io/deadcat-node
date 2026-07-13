//! Binary-market issuance identities and oracle messages.

use elements::hashes::Hash as _;
use elements::{AssetId, ContractHash, OutPoint};
use sha2::{Digest as _, Sha256};

use crate::rt::tagged_hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuanceAssets {
    pub yes_token: AssetId,
    pub no_token: AssetId,
    pub yes_reissuance_token: AssetId,
    pub no_reissuance_token: AssetId,
}

/// Derive both outcome assets from the official zero-contract-hash,
/// unblinded-issuance bootstrap.
#[must_use]
pub fn derive_issuance_assets(
    yes_defining_outpoint: OutPoint,
    no_defining_outpoint: OutPoint,
) -> IssuanceAssets {
    let contract_hash = ContractHash::from_byte_array([0_u8; 32]);
    IssuanceAssets {
        yes_token: AssetId::new_issuance(yes_defining_outpoint, contract_hash),
        no_token: AssetId::new_issuance(no_defining_outpoint, contract_hash),
        yes_reissuance_token: AssetId::new_reissuance_token(
            yes_defining_outpoint,
            contract_hash,
            false,
        ),
        no_reissuance_token: AssetId::new_reissuance_token(
            no_defining_outpoint,
            contract_hash,
            false,
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOutcome {
    Yes,
    No,
}

impl BinaryOutcome {
    #[must_use]
    pub const fn protocol_byte(self) -> u8 {
        match self {
            Self::Yes => 0x01,
            Self::No => 0x00,
        }
    }
}

#[must_use]
pub fn market_id(yes_token: AssetId, no_token: AssetId) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(yes_token.into_inner().to_byte_array());
    hash.update(no_token.into_inner().to_byte_array());
    hash.finalize().into()
}

#[must_use]
pub fn oracle_message(yes_token: AssetId, no_token: AssetId, outcome: BinaryOutcome) -> [u8; 32] {
    let mut message = [0_u8; 33];
    message[..32].copy_from_slice(&market_id(yes_token, no_token));
    message[32] = outcome.protocol_byte();
    tagged_hash("deadcat/oracle_attestation", &message)
}

#[cfg(test)]
mod tests {
    use elements::Txid;

    use super::*;

    #[test]
    fn issuance_assets_are_unique_per_defining_outpoint() {
        let yes = OutPoint::new(Txid::from_byte_array([0x11; 32]), 0);
        let no = OutPoint::new(Txid::from_byte_array([0x22; 32]), 1);
        let assets = derive_issuance_assets(yes, no);
        assert_ne!(assets.yes_token, assets.no_token);
        assert_ne!(assets.yes_token, assets.yes_reissuance_token);
        assert_ne!(assets.no_token, assets.no_reissuance_token);
    }

    #[test]
    fn oracle_outcomes_are_domain_separated() {
        let yes = AssetId::from_slice(&[0x33; 32]).expect("asset");
        let no = AssetId::from_slice(&[0x44; 32]).expect("asset");
        assert_ne!(
            oracle_message(yes, no, BinaryOutcome::Yes),
            oracle_message(yes, no, BinaryOutcome::No)
        );
        assert_ne!(market_id(yes, no), market_id(no, yes));
    }
}
