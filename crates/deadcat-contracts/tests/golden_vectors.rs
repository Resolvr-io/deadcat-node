use std::fmt::Write as _;

use deadcat_contracts::binary_market::{BinaryMarketSlot, CompiledBinaryMarket};
use deadcat_contracts::rt::{ABF_A, ABF_B, RtLeg, RtSide, YES_CBF, commitments, factors, no_cbf};
use deadcat_types::BinaryMarketParams;
use elements::AssetId;

const NUMS_PUBLIC_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn asset(byte: u8) -> AssetId {
    AssetId::from_slice(&[byte; 32]).expect("asset ID")
}

fn sample_params() -> BinaryMarketParams {
    BinaryMarketParams {
        oracle_public_key: NUMS_PUBLIC_KEY,
        collateral_asset_id: asset(0x11),
        yes_token_asset_id: asset(0x22),
        no_token_asset_id: asset(0x33),
        yes_reissuance_token_id: asset(0x44),
        no_reissuance_token_id: asset(0x55),
        base_payout: 1_000,
        expiry_height: 250_000,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("write to string");
    }
    encoded
}

fn compressed_commitments(leg: RtLeg, side: RtSide, asset_id: AssetId) -> (String, String) {
    let (asset, value) = commitments(asset_id, factors(leg, side)).expect("commitments");
    (
        hex(&asset.commitment().expect("generator").serialize()),
        hex(&value.commitment().expect("commitment").serialize()),
    )
}

#[test]
fn nonuniform_asset_ids_preserve_consensus_byte_order() {
    let yes_asset_id = AssetId::from_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ])
    .expect("YES asset ID");
    let no_asset_id = AssetId::from_slice(&[
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ])
    .expect("NO asset ID");

    let (yes_asset_a, yes_value_a) = compressed_commitments(RtLeg::Yes, RtSide::A, yes_asset_id);
    let (yes_asset_b, yes_value_b) = compressed_commitments(RtLeg::Yes, RtSide::B, yes_asset_id);
    let (no_asset_a, no_value_a) = compressed_commitments(RtLeg::No, RtSide::A, no_asset_id);
    let (no_asset_b, no_value_b) = compressed_commitments(RtLeg::No, RtSide::B, no_asset_id);

    // These vectors were derived independently with direct
    // libsecp256k1-zkp generator and Pedersen-commitment calls. In particular,
    // they make an accidental AssetId display-order reversal observable.
    assert_eq!(
        yes_asset_a,
        "0a6b7cf736b56527f607fd9fe71b3a0649bbc4b93b5b7ce9c96e31779b62b29457"
    );
    assert_eq!(
        yes_asset_b,
        "0be198c61e37632e8f0ca89cf116ff228e09b887148cc40e0020e3090866269636"
    );
    assert_eq!(
        yes_value_a,
        "098782e1417c654dcc926f6183ab4a7dc9a5b217cd7b031ba36059a0132ff079bb"
    );
    assert_eq!(yes_value_b, yes_value_a);
    assert_eq!(
        no_asset_a,
        "0afa9f0eb58eaaaf3d191bc5219cb08b5428000b7af55d9abd892684e132eaae80"
    );
    assert_eq!(
        no_asset_b,
        "0b5ece94298f28e71a0ef6536675b23fd5808065398590158652781ad83bb2196f"
    );
    assert_eq!(
        no_value_a,
        "0957a44cfd0f50e95cddacbf2e90ca2ef806eefaacab7b3ef3a07bd31803c4a7fd"
    );
    assert_eq!(no_value_b, no_value_a);
}

#[test]
fn sample_binary_market_consensus_vectors_are_stable() {
    let params = sample_params();
    assert_eq!(hex(&ABF_A), "01".repeat(32));
    assert_eq!(hex(&ABF_B), "02".repeat(32));
    assert_eq!(hex(&YES_CBF), "03".repeat(32));
    assert_eq!(
        hex(&no_cbf()),
        "fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfbb7abd9e3ac459d38bccf5b89cd333e3e"
    );
    assert_eq!(hex(&factors(RtLeg::Yes, RtSide::A).vbf), "02".repeat(32));
    assert_eq!(hex(&factors(RtLeg::Yes, RtSide::B).vbf), "01".repeat(32));
    assert_eq!(
        hex(&factors(RtLeg::No, RtSide::A).vbf),
        "fbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfab6aad8e2ab449c37bbce5a88cc323d3d"
    );
    assert_eq!(
        hex(&factors(RtLeg::No, RtSide::B).vbf),
        "fafafafafafafafafafafafafafafaf9b5a9d7e1aa439b36bacd5987cb313c3c"
    );

    let (yes_asset_a, yes_value_a) =
        compressed_commitments(RtLeg::Yes, RtSide::A, params.yes_reissuance_token_id);
    let (yes_asset_b, yes_value_b) =
        compressed_commitments(RtLeg::Yes, RtSide::B, params.yes_reissuance_token_id);
    let (no_asset_a, no_value_a) =
        compressed_commitments(RtLeg::No, RtSide::A, params.no_reissuance_token_id);
    let (no_asset_b, no_value_b) =
        compressed_commitments(RtLeg::No, RtSide::B, params.no_reissuance_token_id);
    assert_eq!(
        yes_asset_a,
        "0a35ce4766fa581eb986cc270caef01713e368342d571e847efad66c56fd693ca5"
    );
    assert_eq!(
        yes_asset_b,
        "0a4f6ac3645b2f91592b6636b99794e0c6ed9b31c2d6964d4fac71c3cfafac681b"
    );
    assert_eq!(
        yes_value_a,
        "09262a648409c0b2c1ba561e482501e4807366f1642dd4a4141845487d765f2c87"
    );
    assert_eq!(yes_value_b, yes_value_a);
    assert_eq!(
        no_asset_a,
        "0b095e3f40dd7072396cc32e1fc249d064bfa441d56e97f7c1cdc9753a7aecb9f6"
    );
    assert_eq!(
        no_asset_b,
        "0b3674cc4736116c3d330290c00fa1bbbb1bafb4e7fa0f9ff19144960b271ec6b5"
    );
    assert_eq!(
        no_value_a,
        "0992d5a7df3aa45e7af40032c46ecdffc31823f13510dc882f43a470df940a46d2"
    );
    assert_eq!(no_value_b, no_value_a);

    let compiled = CompiledBinaryMarket::new(params).expect("compile market");
    assert_eq!(
        hex(&compiled.cmr()),
        "74031c77c0d4e678913f7a8685425fea07458851e0246496fd3174d734379301"
    );
    let expected_slots = [
        (
            "51206d1b1eadedbcf3645be406aefb6163dc99c24b0f2ccf8f9d6d30ca63ecfb9950",
            "bf50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac03491a3e42d2db13335d900b3cbadcb0d5088b4eb9073869ff309910862294069",
        ),
        (
            "5120bca09ff0a9321ff0843ad7d914f03546885ffaaaa5765b391f779547fea67c53",
            "bf50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac09c44e27f20b80c93313762a6f4e71fc82db38469d90f902bc1720755b61660f3",
        ),
        (
            "51203d59fdf5892a3dc552717790fc0ea352f6ddb8e45f9ca2f12ebd5929ca7cd63a",
            "be50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac04bbdde171ae4fa8cfe1c7790ec1d737b4044251c647103b3e2c320a25a8b61e2",
        ),
        (
            "512032df2ff6bf37d7a0a3093919ed105b180222317acbbcb07de00a45ba093b0bc1",
            "bf50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac013169a5cae722314cc26e3f278b4f9d087affe9b0dab437d6d8c2b28ace343d0",
        ),
        (
            "5120e95b4fa4bb6f774b19ff3efefca1b71cb51b6f0b7049b3a1bc221b9b4d0009ea",
            "bf50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac04b7b02768d8d3b9339bfd3417355db78cada99eb21f1e32873b3ab77065ee015",
        ),
        (
            "512013af1897417da6a97f43af762a6ec29b30b9957e1ab22efebfc718bea10db765",
            "bf50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac094c17910e4ec9a08d1a445308fd4b66ee01cc818d1772a8deff59dd38b649bee",
        ),
        (
            "5120080bec284767594e161dcae63951d5ad4702c5b7222009fdc4e80542375b9713",
            "bf50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0838594e38820be8487ed62ea7663c1d3ce2f20b3f0c7d8075b1bd3f436239d25",
        ),
        (
            "5120bf341144a3664330de554cb44e5d0b099ab7602dc0a794e3426852ef73cda265",
            "be50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac03efb3634a85ea11aa3a246775edf9406ff088af069350d5b8a4ef7a9f862ae0c",
        ),
    ];
    for (slot, (script, control_block)) in BinaryMarketSlot::ALL.into_iter().zip(expected_slots) {
        assert_eq!(
            hex(compiled.slot(slot).script_pubkey().as_bytes()),
            script,
            "{slot:?} scriptPubKey"
        );
        assert_eq!(
            hex(&compiled.slot(slot).control_block().serialize()),
            control_block,
            "{slot:?} control block"
        );
    }
}
