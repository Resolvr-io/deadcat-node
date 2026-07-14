# Deadcat protocol v1

This document is the implementation target for the first Deadcat contract
release. Historical Deadcat SDK sources and design documents are reference
material only when they agree with this file and the accepted ADRs.

- Status: Proposed for byte-vector review
- Date: 2026-07-13

## 1. Common conventions

### Versioning

Each complete OP_RETURN type tag is a versioned layout discriminant. An
incompatible future layout receives a new tag; an existing tag is never
reinterpreted. Unknown and reserved tags are reported and skipped.

RPC envelopes, redb values, and committed golden-vector manifests carry their
own explicit schema or fixture version in addition to the recovery type tag.

### Integer encoding

All `u16` and `u32` recovery fields are big-endian. Values and asset amounts in
transactions remain the Elements `u64` domain. All off-chain multiplication uses
checked `u128` intermediates and converts to `u64` only after range validation.

Hash-like consensus values in covenant hashes, recovery payloads, HMAC
contexts, and fixed database keys use the pinned `elements` crate's internal
32-byte hash serialization (`to_byte_array()`), not bytes obtained by decoding
the reversed human display string. Cross-language implementations must follow
the committed byte vectors rather than infer order from rendered hex.

### Scalar encoding and reduction

Protocol scalar constants are written and serialized as 32-byte big-endian
integers. Hash-derived secp256k1 scalar uses elsewhere in v1 follow one rule:

```text
hash_to_scalar(domain, message) =
    big_endian_integer(tagged_hash(domain, message)) mod n
```

Zero is permitted. This matches the scalar-reduction behavior of the
Simplicity secp256k1 jets. Committed vectors, rather than rendered hash hex,
are authoritative for cross-language implementations.

### Contract identity

```rust
pub struct ContractId {
    pub cmr: [u8; 32],
    pub creation_txid: Txid,
}
```

Stable fixed-key encoding is `cmr[32] || creation_txid[32]` under the common
hash-byte convention above. CMR identifies the program and parameters;
creation txid identifies the instance.

The binary oracle `market_id` defined below is a different digest and must not
be used as `ContractId`.

### Recovery outputs

Each contract created by the official builders contributes one recovery-hint
output:

```text
asset:  explicit network policy asset
value:  explicit zero
nonce:  null
script: OP_RETURN <single direct-push payload>
proofs: empty
```

A composed transaction may contain other OP_RETURN outputs and multiple
recognized Deadcat hints. Parsers treat each hint independently and reject only
an ambiguous or duplicate association with the contract being registered.
Unknown tags are ignored after their raw occurrence is reported.

Hints are a discovery and recovery convention, not a covenant spend rule. A
manual registration without a hint may still be accepted when full canonical
parameters, issuance relationships, and one unambiguous creation output are
verified from chain data; the node marks it non-recoverable by the v1 hint
scheme. Token and RT burn outputs use the separate bare script `OP_RETURN` with
no pushed payload.

### NUMS internal key

Market Taproot trees use the fixed NUMS x-only internal key:

```text
50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
```

No market key-spend path is assumed usable.

## 2. Binary market

### Parameters

```rust
pub struct BinaryMarketParams {
    pub oracle_public_key: XOnlyPublicKey,
    pub collateral_asset_id: AssetId,
    pub yes_token_asset_id: AssetId,
    pub no_token_asset_id: AssetId,
    pub yes_reissuance_token_id: AssetId,
    pub no_reissuance_token_id: AssetId,
    pub base_payout: u64,
    pub expiry_height: u32,
}
```

The four token/RT asset IDs are derived from the two canonical creation
issuances. The canonical defining-input order is YES then NO.

The official standalone market builder fixes the following bootstrap:

- input 0 is the YES defining outpoint and input 1 is the NO defining outpoint;
- both inputs are new issuances with zero `asset_blinding_nonce`, zero
  asset-contract hash in `asset_entropy`, null asset amount, and explicit
  inflation-key amount one;
- because the issuance amount is null rather than confidential, RT IDs use the
  unblinded-issuance variant even though the RT outputs themselves are
  confidential;
- output 0 is the fixed side-A, one-unit YES RT commitment at `DormantYesRt`,
  and output 1 is the fixed side-A NO counterpart at `DormantNoRt`; and
- no other input carries issuance.

Registration re-derives both entropies and all four asset IDs, derives the two
fixed side-A RT commitments from the RT asset IDs, and verifies the raw creation
outputs exactly. For a custom composed creation, full supplied parameters may
identify the YES/NO defining issuances and dormant RT outputs at other
positions, but each association must be unique; unrelated issuances are
ignored. The covenant cannot enforce creation-time blinding because it does not
execute until a created RT output is spent, so side-A creation is independently
enforced by registration and client replay.

Creation-transaction validation is a solvency boundary, not merely a discovery
or indexing check. For each leg, registration and independent client replay must
establish one unique canonical defining issuance with an explicit one-unit RT
amount, a null initial outcome-token amount, and one exact confidential
value-one side-A commitment locked at the compiled dormant script. Given a
confirmed, Elements-consensus-valid creation transaction, those checks exhaust
the RT's spendable supply: commitment balance precludes another positive RT
output, while Elements consensus rejects both explicit zero-valued spendable
outputs and confidential spendable outputs whose rangeproof admits zero. A
zero-valued RT can therefore exist only at a provably unspendable output such as
`OP_RETURN`, where it carries no reissuance authority. Without this validation,
a creator could retain a positive RT outside the market, reissue YES or NO
independently of the covenant, and create claims with no corresponding
collateral. The pinned Elements consensus rules are visible in the
[explicit-output check](https://github.com/ElementsProject/elements/blob/1af7a4d9bea93b4d7f29a77f9751a0e6e03a4390/src/confidential_validation.cpp#L320-L331)
and [confidential rangeproof check](https://github.com/ElementsProject/elements/blob/1af7a4d9bea93b4d7f29a77f9751a0e6e03a4390/src/script/sigcache.cpp#L198-L208).

```text
collateral_per_pair = cp = checked_mul(base_payout, 2)
```

`base_payout` is one of the 16 v1 values:

```text
100, 200, 500,
1_000, 2_000, 5_000,
10_000, 20_000, 50_000,
100_000, 200_000, 500_000,
1_000_000, 2_000_000, 5_000_000, 10_000_000
```

Its four-bit recovery index is the zero-based position in this list.

Amounts are in the smallest indivisible unit of the relevant asset. The
contract accepts any Liquid collateral asset; transaction fees remain in the
network policy asset.

### Slots

The same parameters produce eight unique static slot scripts:

| Slot | Phase | Role |
|---:|---|---|
| 0 | Dormant | YES reissuance token |
| 1 | Dormant | NO reissuance token |
| 2 | Unresolved | YES reissuance token |
| 3 | Unresolved | NO reissuance token |
| 4 | Unresolved | collateral |
| 5 | ResolvedYes | collateral |
| 6 | ResolvedNo | collateral |
| 7 | Expired | collateral |

All slots share one parameterized Simplicity CMR. Their Taproot outputs differ
through one hidden 32-byte TapData storage word:

```text
bytes 0-29  zero
byte 30     slot encoding version 0x01
byte 31     slot tag 0x00-0x07 from the table above
```

The nonzero version prevents slot zero from collapsing to smplx's default
all-zero storage value. Golden vectors pin every storage word, TapData hash,
Merkle root, script pubkey, and control block.

The canonical node state is:

```rust
pub enum BinaryMarketState {
    Trading { outstanding_pairs: u64 },
    ResolvedYes { collateral_unredeemed: u64 },
    ResolvedNo { collateral_unredeemed: u64 },
    Expired { collateral_unredeemed: u64 },
}
```

Expired state stores collateral, not outstanding pairs. Expiry redemption can
be asymmetric between YES and NO, so remaining collateral need not be divisible
by `cp`.

### Global invariants

Every market path enforces:

- every inspected input and output has the expected asset, value class, and
  script role;
- non-issuance paths reject attached asset issuance;
- each witness-selected input and output window is in bounds, every slot index
  inside its own window is distinct, and every constrained output is checked at
  its selected index;
- every sibling group consumes UTXOs created by one previous transaction: both
  dormant RTs together, or all three unresolved RT/collateral slots together;
- unresolved siblings are the consecutive previous outputs YES RT, NO RT, then
  collateral; dormant RTs need not be consecutive so custom composed creation
  can place them at other uniquely identified positions;
- token or RT destruction goes only to the required bare OP_RETURN burn outputs;
- no transition creates unmatched YES/NO supply; and
- checked arithmetic cannot wrap.

The interpreter uses decoded witness path and exact witness-selected windows. It
does not find a continuation by taking the first output with a matching script.
Decoy same-script outputs in an otherwise valid custom transaction must not
change the interpreted state.

### Spend paths

Let `p > 0` be a pair quantity.

#### Initial issuance

```text
inputs:  DormantYesRt, DormantNoRt
outputs: UnresolvedYesRt, UnresolvedNoRt, UnresolvedCollateral
```

- Reissue exactly `p` YES and `p` NO.
- Lock exactly `p * cp` collateral.
- Produce both RT continuations using the deterministic scheme below.

#### Subsequent issuance

```text
inputs:  all three Unresolved siblings
outputs: all three Unresolved siblings
```

- Reissue exactly `p` YES and `p` NO.
- Increase collateral by exactly `p * cp`.
- Recreate all siblings together and continue both RT legs deterministically.

#### Partial cancellation

```text
inputs:  all three Unresolved siblings plus token inputs
outputs: all three Unresolved siblings plus YES/NO burns
```

- Burn exactly `p` YES and `p` NO.
- Decrease collateral by exactly `p * cp`.
- Require nonzero remaining collateral.
- Recreate all siblings together and continue both RT legs deterministically.

#### Full cancellation

```text
inputs:  all three Unresolved siblings plus token inputs sufficient for burns
outputs: DormantYesRt, DormantNoRt, token burns, wallet collateral refund
```

- Burn exactly the outstanding YES and NO amounts. Token inputs may contain
  excess value returned as wallet change.
- Return all collateral.
- Recreate the two dormant RT siblings deterministically.

#### Oracle resolution

From Unresolved, consume all three siblings, burn both RTs, and move the entire
unchanged explicit collateral value to slot 5 for YES or slot 6 for NO.

From Dormant, consume and burn both RTs and create no covenant continuation.

There is no transition back to Trading and no second terminal transition after
the canonical spend confirms.

#### Expiry

Expiry uses the same unresolved/dormant shapes as resolution. `expiry_height`
is the exact CLTV-style lock-height threshold and must satisfy
`1 <= expiry_height < 500_000_000`. The covenant requires transaction
`nLockTime >= expiry_height`; the transaction must also use a non-final input
sequence so consensus locktime is active. Because consensus requires
`nLockTime < candidate_block_height`, a transaction with locktime exactly `H`
is first confirmable in block `H + 1`. Unresolved collateral moves unchanged
to slot 7.

Timelocks open the expiry path but do not close oracle resolution. Once an
expiry transaction is consensus-final, the first valid oracle-resolution or
expiry transaction in canonical chain order wins the shared live outpoints.

#### Resolved redemption

Burn `t > 0` winning token atoms and release exactly `t * cp` collateral. If
collateral remains, reproduce the same resolved slot with that exact value. A
complete redemption has no covenant continuation.

#### Expiry redemption

Burn `t > 0` YES or NO token atoms and release exactly `t * base_payout`
collateral. If collateral remains, reproduce slot 7 with that exact value. A
complete redemption has no covenant continuation.

### Oracle message

```text
market_id = SHA256(
    yes_token_asset_id_bytes || no_token_asset_id_bytes
)

message = tagged_hash(
    "deadcat/oracle_attestation",
    market_id || outcome_byte
)

outcome_byte = 0x01 for YES
outcome_byte = 0x00 for NO
```

The oracle supplies a BIP-340 signature under `oracle_public_key`.

### Fixed A/B RT construction

Let `n` be the secp256k1 group order. The public 32-byte big-endian scalar
constants are:

```text
ABF_A    = 0x0101010101010101010101010101010101010101010101010101010101010101
ABF_B    = 0x0202020202020202020202020202020202020202020202020202020202020202
C        = 0x0303030303030303030303030303030303030303030303030303030303030303
YES_CBF  = C
NO_CBF   = -C mod n
         = 0xfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfbb7abd9e3ac459d38bccf5b89cd333e3e
```

For RT leg `r` and side `s`:

```text
VBF(r, s) = CBF(r) - ABF(s) mod n
```

The resulting VBFs are:

| Leg | Side A | Side B |
|---|---|---|
| YES | `0x02` repeated 32 bytes | `0x01` repeated 32 bytes |
| NO | `0xfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfab6aad8e2ab449c37bbce5a88cc323d3d` | `0xfafafafafafafafafafafafafafaf9b5a9d7e1aa439b36bacd5987cb313c3c` |

Every RT has confidential value one. Its exact commitments are:

```text
asset(r, s) = H(asset_id(r)) + ABF(s) * G
value(r)    = H(asset_id(r)) + CBF(r) * G
```

The value commitment is identical on A and B. The complementary leg factors
satisfy `YES_CBF + NO_CBF = 0 mod n`, so the two canonical creation outputs
balance against their explicit one-unit issuance pseudo-inputs without a
confidential wallet balancing output.

Both creation legs start on A. Every market operation that consumes live RTs
must find the YES and NO legs on the same current side and must put every RT
continuation on the opposite side. This includes a full cancellation that
returns to Dormant. Every terminal resolution or expiry must instead create
both opposite-side confidential commitments at bare `OP_RETURN` burn outputs.
Same-side continuations and burns are invalid.

The covenant and Rust interpreter infer the current side by comparing each raw
input `TxOut`'s `(asset, value)` pair against the two exact role-specific
commitments. The script and sibling relationship are checked separately. The
raw `TxOut` is authoritative: a side value received from a node, database, or
caller is never trusted as independent state and need not be persisted.

On initial and subsequent issuance, each input's Elements
`asset_blinding_nonce` must equal the exact ABF of that inferred input side:
`ABF_A` for an A input and `ABF_B` for a B input. The continuation still flips
to the other side. Rangeproof construction uses the role- and side-specific VBF
even though each leg's A/B value commitment is byte-identical, and surjection
proofs use the complete Elements input domain in canonical order.

This algebra is specific to a one-unit RT. It must be redesigned if an RT value
can differ from one.

### Recovery hint

Binary market v1 tag is `0x10`.

Known collateral payload, 38 bytes:

```text
Byte 0       0x10
Bytes 1-32   oracle x-only public key
Byte 33      [collateral_index:4][base_payout_index:4]
Bytes 34-37  expiry_height, u32 big-endian
```

If `collateral_index == 15`, append the full internal-byte-order AssetId at
bytes 38-69, for a 70-byte payload.

Both payloads use a one-byte direct-push opcode, so their complete scripts are
40 and 72 bytes respectively, including `OP_RETURN` and the push opcode.

The A/B schedule adds no recovery field. Payloads remain 38 or 70 bytes and
their complete scripts remain 40 or 72 bytes. The fixed side-A creation
commitments are derived from the RT asset IDs already recoverable from the
defining issuances.

Collateral indices:

```text
0     selected network policy asset
1     Liquid-mainnet USDt
2-14  reserved and invalid in v1
15    full 32-byte AssetId escape follows
```

Index 1 is invalid on networks where the v1 table has no assigned USDt asset.
No trailing bytes or truncated escape are accepted.

### Public full-chain market recovery

A node with complete Liquid block history can recover every market following
the v1 hint convention without a mnemonic or Nostr:

1. scan transaction outputs for a length-valid `0x10` recovery payload;
2. decode the oracle key, collateral, payout denomination, and lock-height;
3. derive YES, NO, and both RT asset IDs from the creation transaction's two
   associated new issuances;
4. derive the fixed side-A initial RT commitments;
5. compile all eight slot scripts and require one unambiguous dormant RT pair
   matching the creation transaction; and
6. replay spends from those verified outpoints to the canonical tip.

Automatic global discovery recognizes the official standalone shape with the
fixed defining-input and RT-output positions above. This keeps the scan linear
and prevents transactions containing many unrelated issuances from forcing a
combinatorial candidate search. A composed custom creation remains eligible for
manual registration when supplied full parameters identify one unique issuance
and dormant-output association. A random OP_RETURN that happens to share the
tag is discarded by full compile-and-match verification.

This recovers cryptographic market parameters and chain state, not the
human-readable question, category, or other social metadata. Markets have a
NUMS internal key and no mnemonic-owned creator path. A wallet mnemonic can
still rediscover a market creation transaction it funded, while a token holder
can locate the same transaction through first-issuance lookup for an unknown
YES/NO asset.

## 3. Maker limit order

### Parameters

```rust
pub enum OrderDirection {
    SellBase,
    SellQuote,
}

pub struct MakerOrderParams {
    pub base_asset_id: AssetId,
    pub quote_asset_id: AssetId,
    pub price: u32,
    pub min_active_base: u32,
    pub direction: OrderDirection,
    pub maker_receive_spk_hash: [u8; 32],
    pub maker_pubkey: XOnlyPublicKey,
}
```

BASE is one parent-market outcome token. QUOTE is exactly the parent collateral
asset. Canonical validity is:

```text
1 <= price <= parent_market.cp
1 <= min_active_base
```

The order input and every covenant-constrained output use explicit asset and
value. Taker wallet outputs may be confidential.

The Taproot internal key is `maker_pubkey`. Key-spend is the sole cancellation
mechanism. The Simplicity leaf contains only the permissionless fill path; it has
no cosigner and no script-cancel branch.

### Creation

The public builder accepts `offered_base_capacity: u64` for both directions and
requires it be at least `min_active_base`.

```text
SellBase  locks offered_base_capacity BASE atoms
SellQuote locks offered_base_capacity * price QUOTE atoms
```

The SellQuote rule makes every canonical live remainder an exact multiple of
price. A non-multiple foreign creation is not a canonical v1 order.

### Fill layout

For an order input at index `i`:

- the maker payment is output `i` and must match
  `maker_receive_spk_hash`;
- a partial-fill remainder index is supplied by the Simplicity witness;
- the remainder output must reproduce the exact covenant script; and
- output indices and products are bounds/overflow checked.

Let `I` be order input amount, `M` maker output amount, `R` nonzero remainder,
`P` price, `A` minimum, and `F` filled BASE atoms.

#### SellBase

```text
input asset = BASE
maker asset = QUOTE

full:
    F = I
    M = F * P
    F >= A
    no covenant continuation

partial:
    0 < R < I
    remainder asset = BASE
    F = I - R
    M = F * P
    F >= A
    R >= A
```

#### SellQuote

```text
input asset = QUOTE
maker asset = BASE
F = M

full:
    I = F * P
    F >= A
    no covenant continuation

partial:
    R > 0
    remainder asset = QUOTE
    I = F * P + R
    F >= A
    R >= A * P
```

Every maker payment is exact. Overpayment does not substitute for an equality.

### Cancellation and transition detection

After stripping an optional Taproot annex:

- key-spend of the tracked outpoint is cancellation, regardless of unrelated
  outputs;
- script-spend is a fill;
- a partial fill adopts only the witness-selected remainder output; and
- a full fill has no tracked continuation even if the transaction contains an
  unrelated decoy output with the same script.

The interpreter validates the exact direction-specific equation before updating
state.

Canonical state is:

```rust
pub enum MakerOrderState {
    Active {
        active_outpoint: OutPoint,
        remaining_base: u64,
        total_filled_base: u64,
    },
    Consumed,
    Cancelled,
}
```

For SellQuote, `remaining_base = explicit_quote_amount / price`; canonical
creation and transitions make the division exact.

### Parent-market terminal state

The covenant does not inspect or co-spend the parent market. It remains
consensus-fillable after resolution or expiry until consumed or cancelled.
Official routing stops as soon as the parent is observed outside Trading, and
every preflight carries a fresh parent snapshot. This does not prevent an
adversarial custom fill.

### Key derivation and recovery

The mnemonic derives the Deadcat root:

```text
m/86'/1145258324'
```

Numeric hardened children are fixed as:

```text
m/86'/1145258324'/0'       deadcat_secret_key
m/86'/1145258324'/1'/i'    maker key at u16 order index i
m/86'/1145258324'/2'/i'    reserved future pool admin key
```

```text
order_nonce = HMAC-SHA256(
    deadcat_secret_key,
    "deadcat/order_nonce" || order_index_be_u16
)

order_uid = SHA256(
    "deadcat/order_uid" ||
    maker_pubkey || order_nonce ||
    base_asset_id || quote_asset_id ||
    price_be_u32 || min_active_base_be_u32 || direction_byte
)

order_tweak = hash_to_scalar("deadcat/order_tweak", order_uid)
P_order = xonly_add_tweak(maker_pubkey, order_tweak)
maker_receive_spk = OP_1 PUSH32 P_order
maker_receive_spk_hash = SHA256(maker_receive_spk)
```

`maker_pubkey` is the BIP-340 x-only serialization of the even-Y lift of the
derived maker key. `xonly_add_tweak` uses the standard secp256k1 x-only tweak
operation, records the resulting parity needed to derive the corresponding
private spend key, and returns the result's 32-byte x-only serialization. An
infinity result makes that order index unusable rather than selecting a
different unstated derivation.

`direction_byte` is zero for SellBase and one for SellQuote, matching the order
type-tag direction bit and mask context.

Order-mask context is:

```text
market_creation_txid       32 bytes
price                       4 bytes, BE
side                        1 byte, YES=0, NO=1
direction                   1 byte, SellBase=0, SellQuote=1
min_active_base             4 bytes, BE
```

```text
mask_bytes = HMAC-SHA256(
    deadcat_secret_key,
    "deadcat/order_mask" || context
)[0..2]

mask_u16 = big_endian_u16(mask_bytes)
masked_order_index = order_index XOR mask_u16
```

The order hint is an owner mnemonic-recovery aid. A public node cannot unmask
the index or derive maker-specific params. Public discovery supplies the full
params through Nostr or manual registration; the node verifies them by
recompiling and matching the creation output.

For chain-only owner recovery, the client may either start with creation
transactions found by its normal wallet rescan or ask a node for all
length-valid order-hint candidates. For each candidate it locally derives the
Deadcat secret, unmasks a candidate index, derives the maker/cancellation and
receive keys, compiles the order, and accepts ownership only if the compiled
script matches the unique creation output. XOR unmasking produces some `u16`
for every foreign hint; the script match is therefore the ownership test. The
mnemonic or derived xprv is never sent to the node.

At minimum, public registration supplies the parent market creation txid, side,
direction, price, minimum, maker public key, maker receive script hash, and
creation txid. The creation transaction must contain one unique canonical order
output matching the compiled script. The node derives its current outpoint only
by replaying that output's complete spend lineage; an announced live outpoint is
at most an acceleration hint and is never trusted because anyone can create a
decoy output at a public script.

### Recovery hint

V1 order tags are:

```text
0x40  YES / SellBase
0x44  YES / SellQuote
0x48  NO  / SellBase
0x4c  NO  / SellQuote
```

Payload, 43 bytes:

```text
Byte 0       complete order type tag
Bytes 1-2    masked_order_index, u16 big-endian
Bytes 3-34   parent market creation txid
Bytes 35-38  price, u32 big-endian
Bytes 39-42  min_active_base, u32 big-endian
```

The complete direct-push script is 45 bytes. No trailing bytes are accepted.

## 4. Confidentiality matrix

| Output/input role | Asset/value visibility |
|---|---|
| Market collateral state | explicit |
| Order input, maker payment, remainder | explicit |
| YES/NO cancellation/redemption burns | explicit |
| RT state and RT terminal burns | confidential, covenant verified |
| User token destination | explicit or confidential |
| User collateral payout/change | explicit or confidential |
| Fee output | standard explicit policy-asset fee |

## 5. Required golden vectors

Machine-readable fixtures are committed before a contract is considered stable:

1. fixed market params to arguments, CMR, tapleaf/control block, all eight
   scripts, and addresses per supported network;
2. defining outpoints to issuance entropy and token/RT IDs, plus the fixed A/B
   RT factors, commitments, and side-A creation transaction;
3. RT lineage through every continuing and terminal path;
4. known/exotic market hints and every invalid tag/index/length case;
5. oracle market ID, tagged messages, signatures, and wrong-key/outcome/domain
   failures;
6. every binary path plus sibling, asset, collateral, issuance, burn,
   commitment, arithmetic, and window-aliasing failures;
7. expiry lock-height boundary fixtures (`nLockTime = H - 1` rejected by the
   covenant, block `H` not final, block `H + 1` accepted) plus valid late oracle
   resolution races and the `500_000_000` type boundary;
8. mnemonic to numeric paths, secret, order key, nonce, mask, UID, tweak,
   x-only tweak parity, receive private key, and receive script/hash;
9. all four order hint tags;
10. both directions' full/partial fills at minimum and overflow boundaries;
11. decoy-output and shifted-window transactions proving witness-grounded
    interpretation;
12. key-spend cancellation with and without annex;
13. a custom composed market-plus-multiple-orders transaction and its atomic
    transition batch;
14. ContractId/redb key encodings and apply/rollback fixtures; and
15. `hash_to_scalar` modular-reduction cases generated from fixed artificial
    inputs.

## 6. Superseded historical choices

V1 deliberately supersedes these older proposals:

- rounded `expiry_time / 60` stored as u24;
- u24/u64 canonical order price;
- independent u8 fill/remainder minimums;
- rational price with maker-favoring ceiling rounding;
- maker fill cosigner;
- Simplicity script cancellation;
- fixed `current_index + 1` order remainder;
- first-matching-script transition detection;
- state models that store `outstanding_pairs` after asymmetric expiry
  redemption;
- outpoint-derived RT blinders and witness-authoritative RT factors;
- and any assumption that a custom-valid transaction has the official builder's
  layout beyond what the covenant itself enforces.
