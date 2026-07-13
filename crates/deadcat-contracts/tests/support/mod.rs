use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput};
use elements::{AssetId, OutPoint, Script, TxOut, TxOutWitness, Txid};
use simplex::provider::SimplicityNetwork;

pub(crate) fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("32-byte asset ID")
}

pub(crate) fn network(policy_asset: AssetId) -> SimplicityNetwork {
    SimplicityNetwork::ElementsRegtest { policy_asset }
}

pub(crate) fn script(byte: u8) -> Script {
    Script::from(vec![0x6a, 0x01, byte])
}

pub(crate) fn bare_op_return() -> Script {
    Script::from(vec![0x6a])
}

pub(crate) fn explicit_txout(asset_id: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset_id),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

pub(crate) fn pset_input(byte: u8, vout: u32, witness_utxo: TxOut) -> PsetInput {
    let mut input = PsetInput::from_prevout(OutPoint {
        txid: Txid::from_byte_array([byte; 32]),
        vout,
    });
    input.witness_utxo = Some(witness_utxo);
    input
}

pub(crate) fn pset_output(txout: TxOut) -> PsetOutput {
    PsetOutput::from_txout(txout)
}
