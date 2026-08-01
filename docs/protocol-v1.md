# Deadcat protocol v1

This document is the implementation target for the first Deadcat contract
release. Historical Deadcat SDK sources and design documents are reference
material only when they agree with this file and the accepted ADRs.

- Status: Proposed for byte-vector review
- Date: 2026-07-15

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
#[repr(transparent)]
pub struct ContractId(elements::OutPoint);
```

`ContractId` identifies one on-chain contract instance by its canonical
creation-anchor output. Its stable fixed-key encoding is
`txid_internal_bytes[32] || vout_be_u32[4]` under the common hash-byte
convention above. Its strict human-readable wire encoding is the object
`{"txid": "...", "vout": n}`; the ordinary `elements::OutPoint` string serde
is not inherited.

The creation anchor is the binary market's initial dormant YES RT output. Its
exact side-A commitment and compiled `DormantYesRt` script are verified along
with the NO leg and the complete creation invariant.

For the official standalone market layout the market anchor is vout 0. A
validated custom composition may place it elsewhere, and one transaction may
create multiple independently anchored markets.

The ID remains stable as later transactions move or terminate the contract. It
does not commit to the descriptor and does not certify that the output exists
or is a valid Deadcat contract. That proof belongs to declaration ingestion and
chain evidence. Simplicity CMRs are deterministically derived from the stored
parameters, while stable protocol identity is the verified creation anchor.

Ordinary transaction inputs, outputs, and live contract state use
`elements::OutPoint` directly. The protocol does not define a duplicate generic
outpoint wrapper: rust-elements is the native Liquid transaction model,
`bitcoin::OutPoint` carries the wrong nominal txid type, and an LWK-specific
type would couple the protocol layer to wallet software. `ContractId` is a
newtype only because a creation anchor has stronger domain meaning than an
arbitrary outpoint.

The binary oracle `market_id` defined below is a different digest and must not
be used as `ContractId`.

### Contract declarations and packages

Identity, semantics, and portable ingestion are separate types:

```rust
pub enum ContractDescriptor {
    BinaryMarketV1 {
        params: BinaryMarketParams,
    },
}

pub struct ContractDeclaration {
    pub contract_id: ContractId,
    pub descriptor: ContractDescriptor,
}

pub struct ContractPackage {
    pub format_version: u16,
    pub chain: ChainIdentity, // LiquidNetwork plus exact genesis BlockHash
    pub roots: Vec<ContractId>,
    pub declarations: Vec<ContractDeclaration>,
}
```

A descriptor contains the complete public semantics required to compile one
market. A declaration is an untrusted claim that its descriptor is instantiated
at its `ContractId`. A package is the portable atomic registration unit. None
of these objects attests to chain inclusion or validity.

Package format v1 has these structural rules:

- `format_version` is exactly 1;
- `chain.network` and `chain.genesis_hash` must exactly match the receiving
  node;
- there are 1 through 16 unique roots and 1 through 64 unique declarations,
  with every root declared;
- every included declaration is named as a root, so unrelated payload padding
  is rejected.

Declaration order has no authority over verification. The verifier resolves
each shared creation transaction at most once. Registration receipts preserve
sender order: `roots` matches package root order and `contracts` matches
declaration order. The verifier retrieves confirmed creation transactions and
status from its own chain source, recompiles each market, checks its nominated
anchor and creation invariants, and registers all markets as catching up. The
node then replays each lineage to its indexed tip.

Only after every declaration succeeds does one redb write transaction register
the complete package. One invalid declaration, chain identity, or conflicting
existing record rejects the package without partial insertion. An identical
retry is idempotent. The same transaction also retains a normalized copy of
every verified declaration as explicit watch intent. Chain-derived state is
still disposable: after a destructive rebuild, replay immediately after the
immutable network activation checkpoint matches those declarations by creation
transaction and rematerializes only the claims that remain valid. Registration
rejects v1 creation at or before that checkpoint, making the replay boundary
complete. Missing or invalid claims stay dormant rather than
blocking unrelated synchronization.

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
recognized Deadcat hints. Parsers treat each hint independently. Missing,
mismatched, duplicate, already-associated, or otherwise ambiguous hints prevent
automatic association but never invalidate a complete declaration that passes
the authoritative chain and covenant checks. Unknown tags are ignored after
their raw occurrence is reported.

Hints are a discovery and recovery convention, not a covenant spend rule. A
declaration without a hint may still be accepted when its complete canonical
descriptor, issuance relationships, and unambiguous nominated creation anchor
are verified from chain data; the node marks it non-recoverable by the v1 hint
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
Compiler and creation validation enforce this supported-denomination profile.
The spend covenant commits the selected value and uses checked payout
arithmetic, but does not repeat the recovery-policy membership check on every
spend.

Amounts are in the smallest indivisible unit of the relevant asset. The
contract accepts any Liquid collateral asset; transaction fees remain in the
network policy asset.

### Slots

The same parameters produce eight unique static slot scripts:

| Slot | Phase | Asset role | Authorization role |
|---:|---|---|---|
| 0 | Dormant | YES reissuance token | coordinator |
| 1 | Dormant | NO reissuance token | follower |
| 2 | Unresolved | YES reissuance token | coordinator |
| 3 | Unresolved | NO reissuance token | follower |
| 4 | Unresolved | collateral | follower |
| 5 | ResolvedYes | collateral | self-validating terminal |
| 6 | ResolvedNo | collateral | self-validating terminal |
| 7 | Expired | collateral | self-validating terminal |

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

Multi-input states use one fixed coordinator. Dormant and unresolved YES derive
the contract input base from their own `current_index` and validate the complete
transition. They check every sibling input, both RT legs, every constrained
output, the full collateral equation, and issuance fields on every market input.

Dormant NO, unresolved NO, and unresolved collateral authenticate their
committed slot and exact coordinator group without consulting `ACTION`.
Consensus executes all inputs atomically, so a follower succeeds only when its
coordinator independently authorizes the complete transition. The unresolved
group must also spend consecutive prior outputs YES, NO, collateral. Terminal
collateral inputs authenticate their own slot and validate their redemption.

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
- non-issuance paths reject attached asset issuance on every consumed market
  input, while deliberately allowing issuance on unrelated composable inputs;
- coordinators derive the contiguous market input window from their own
  `current_index`; only the output window is witness-selected, and every
  constrained output is checked at its selected index;
- every sibling group consumes UTXOs created by one previous transaction: both
  dormant RTs together, or all three unresolved RT/collateral slots together;
- unresolved siblings are the consecutive previous outputs YES RT, NO RT, then
  collateral; dormant RTs need not be consecutive so custom composed creation
  can place them at other uniquely identified positions. This relies on
  canonical creation exhausting each unique one-atom RT authority at the exact
  dormant script;
- token or RT destruction goes only to the required bare OP_RETURN burn outputs;
- follower inputs cannot select a transition-specific branch and require the
  exact coordinator sibling group;
- no transition creates unmatched YES/NO supply; and
- checked arithmetic cannot wrap.

The interpreter derives the input base from the tracked coordinator outpoint
and decodes the coordinator's exact typed action. Follower action values are
non-authoritative. It does not find a continuation by taking the first output
with a matching script. Decoy same-script outputs in an otherwise valid custom
transaction must not change the interpreted state.

### Covenant witness ABI

The source-level witness has two fields:

```text
SLOT:   u8
ACTION: Either<Either<u32, u32>,
               Either<(u32, bool, Signature), Either<u32, u32>>>
```

`SLOT` is authenticated against the hidden TapData word before it can grant any
authority. `ACTION` is a five-way semantic sum whose branches are:

| Operation | Encoding | Payload |
|---|---|---|
| Issue | `Left(Left(output_base))` | output window only |
| Cancel | `Left(Right(output_base))` | output window only |
| Resolve | `Right(Left((output_base, outcome_yes, signature)))` | output window and oracle attestation |
| Expire | `Right(Right(Left(output_base)))` | output window only |
| Redeem | `Right(Right(Right(output_base)))` | output window only |

The authenticated slot and transaction determine the old-state variant. In
particular, the slot distinguishes initial from subsequent issuance,
dormant from active resolution/expiry, and resolved from expired redemption.
Cancellation shape is derived from its mandatory outputs. Redemption quantity,
completion, and token side are derived from the explicit burn and collateral
outputs. They are not independently witness-selected.

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
is the exact CLTV-style lock-height threshold. Compiler and creation validation
require `1 <= expiry_height < 500_000_000`; the covenant enforces the committed
height by requiring transaction `nLockTime >= expiry_height`. The transaction
must also use a non-final input sequence so consensus locktime is active.
Because consensus requires
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

The canonical compiler derives both possible messages from the outcome asset
IDs and binds them as internal program arguments. They are not independently
selectable market parameters. At resolution, the covenant selects the bound
digest from `outcome_yes` and verifies the BIP340 signature; this preserves the
message format above while avoiding repeated SHA work at spend time.

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
package registration when its complete declaration identifies one unique
issuance and dormant-output association. A random OP_RETURN that happens to
share the tag is discarded by full compile-and-match verification.

This recovers cryptographic market parameters and chain state, not the
human-readable question, category, or other social metadata. Markets have a
NUMS internal key and no mnemonic-owned creator path. A wallet mnemonic can
still rediscover a market creation transaction it funded, while a token holder
can locate the same transaction through first-issuance lookup for an unknown
YES/NO asset.

## 3. Confidentiality matrix

| Output/input role | Asset/value visibility |
|---|---|
| Market collateral state | explicit |
| YES/NO cancellation/redemption burns | explicit |
| RT state and RT terminal burns | confidential, covenant verified |
| User token destination | explicit or confidential |
| User collateral payout/change | explicit or confidential |
| Fee output | standard explicit policy-asset fee |

## 4. Required golden vectors

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
8. decoy-output and shifted-window transactions proving witness-grounded
    interpretation;
9. a custom transaction advancing multiple independent markets and its atomic
   transition batch;
10. anchor-based ContractId/wire/redb key encodings, multi-market same-tx
    identity, package validation/atomicity, and apply/rollback fixtures; and
11. `hash_to_scalar` modular-reduction cases generated from fixed artificial
    inputs.

## 5. Superseded historical choices

V1 deliberately supersedes these older proposals:

- rounded `expiry_time / 60` stored as u24;
- first-matching-script transition detection;
- state models that store `outstanding_pairs` after asymmetric expiry
  redemption;
- outpoint-derived RT blinders and witness-authoritative RT factors;
- and any assumption that a custom-valid transaction has the official builder's
  layout beyond what the covenant itself enforces.
