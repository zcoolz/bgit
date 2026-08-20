# bgit wire format v1 — git artifacts on BSV (v1.4 — the v1.3 reviewed core + the §11 proof-only amendment, 2026-08-19)

*The forever-format for g-417 (the Monero Mirror) and everything after it. Once one transaction
is published in this format, v1 must be readable FOREVER — this document ships as part of the
artifact and is the contract.*

**REVIEW RECORD:** v1.0 drafted 2026-08-15 ~04:35 UTC → codex-crypto (OpenAI) round 1
**CHANGES-REQUIRED** (wire `9f81c6e9…`) → all folded as v1.1 (sign-the-literal-bytes envelope ·
strict-DER low-S ECDSA · deterministic genesis-anchored forks · 0x06 CLAIM ATTESTATION · v2
non-orphaning · reader hardening · vector pins). Implementation-as-spec-audit yielded 13
ambiguities → v1.2 §10 (A1 key-binding closing squat-by-race + ratifications). → codex-crypto
**round 2 CHANGES-REQUIRED** (wire `6c28d89d…` ← `e4148ced…`, 11:40 UTC) → folded as **v1.3**:
A2 RESOLVED (version+type bytes IN the signed preimage — pinned vector regenerates) · A1
integrated INTO winner-rule resolution (authorization evaluated during the walk, before fork
comparison — a racing unauthorized child can never win) · same-block competing children without
an intra-block index = REFUSE, never source-order (#9 overturned stricter) · dust ENFORCED on
all four record types (#11 overturned stricter) · artifact-signer mismatch = REFUSAL (#12
hardened) · publisher must hash-verify the exact bytes it broadcasts against the plan
immediately before POST (the mutable-fixture-reread bug). Round THREE reviews the folded code +
new pins before the first broadcast. → **Round 3 verdict: PUBLISH-WITH-CHANGES** (wire
`fe593953…` ← `0e586ff4…`, 12:05 UTC): the three residuals RULED — genesis-key-always as an
explicit authorization exception (not temporal retroactivity) · same-block positional
dependencies require the intra-block index or refuse · first-claim-per-key permanent, repeats =
authority no-ops — all three now normative above, three pin families added; **"after those
normative edits and pins pass, PUBLISH; no further package review needed."**

## 0. Design laws (from the CodeOnChain autopsy — the graveyard's antibodies)

1. **READ-OLD-FOREVER.** Version negotiation exists so v2+ can add, never so v1 can be dropped.
   Any conforming reader MUST read every prior version. A format migration that orphans old repos
   is the exact death this design exists to avoid.
2. **A STRANGER CAN REBUILD EVERYTHING.** The reader algorithm (§6) uses only: a BSV node or any
   address-history + raw-tx source. No Indelible service, no privileged index, no secret.
3. **SELF-DOCUMENTING WHERE CHEAP.** Manifest bodies are JSON (a human with a hex editor can read
   the skeleton of the format from the chain itself). Bulk payloads are raw bytes.
4. **RAW PUSHDATA, NEVER BASE64.** The measured 1.78× framing tax is a design failure at archive
   scale. Payloads go on chain as the bytes they are.
5. **SIGN WHAT YOU SHIP** (codex-crypto, v1.1). Signatures cover the LITERAL published body
   bytes, never a canonicalized re-serialization. Canonical-form signing is underspecified in
   practice (Unicode normalization, duplicate keys, number grammar) and splits implementations —
   the one failure a forever-format cannot survive.

## 1. Transaction shape

Every bgit record is one output of a standard BSV transaction:

```
OP_FALSE OP_RETURN <pushdata: PROTOCOL_TAG> <pushdata: RECORD>
```

- `PROTOCOL_TAG` = the 4 ASCII bytes `bgit` (0x62 0x67 0x69 0x74). First pushdata, always.
- `RECORD` = one record (§2). **Exactly one bgit output per transaction** — a transaction with
  more than one output whose first pushdata is `bgit` is NOT a conforming record and readers MUST
  ignore all of them (adversarial multi-output ambiguity refused by construction; codex-crypto).
- **Every transaction in one publication pays at least one output to the REPO ADDRESS** (§5) —
  discovery is a plain address walk.

## 2. RECORD envelope

```
byte 0        FORMAT_VERSION   0x01
byte 1        RECORD_TYPE      see §3
bytes 2..n    BODY             type-dependent
```

Record types: `0x01` PART · `0x02` ARTIFACT MANIFEST · `0x03` REF MANIFEST · `0x06` CLAIM
ATTESTATION. Reserved, allocated now, defined later: `0x04` KEY_ROTATE · `0x05` DELEGATE ·
`0x07`–`0x0F` held. A v1 reader encountering a reserved/unknown type MUST skip it, never error —
and a skipped record MUST NOT affect winner selection (§3) in any way (codex-crypto).

**v2+ extension rules (binding on future versions, codex-crypto):** a later version MUST NOT
redefine the meaning of any v1 RECORD_TYPE, MUST NOT make v1-published artifacts unreachable, and
MUST keep a v1-resolvable REF path for any repo whose artifacts were published under v1.
Extensions add NEW record types; they never repurpose old ones.

## 3. Record types

### 0x01 — PART (bulk payload)

```
BODY = raw bytes of one artifact part (no wrapper, no encoding, no metadata)
```

Identity, order, and integrity live entirely in the ARTIFACT MANIFEST — a part is meaningless
until a manifest claims it (nothing dangles; order is never inferred). Part size is publisher
POLICY, not format: this publish uses ≤ 9,900,000 bytes/part. Kept metadata-free on review
(codex-crypto: metadata-free PARTs make extraction unambiguous).

### Signed-body envelope (used by 0x02, 0x03, 0x06)

```
BODY = varint(body_len) || body_bytes || 0x21 || pubkey(33, compressed) || varint(sig_len) || sig(DER)
```

- `body_bytes` = the record's JSON payload, EXACT literal UTF-8 bytes as published.
- Signature = secp256k1 ECDSA over
  **`SHA256( "bgit1|" (ASCII, 6 bytes) || VERSION_BYTE || TYPE_BYTE || body_bytes )`**
  (v1.3, round-two ruling on A2: the envelope's version and type bytes are cryptographically
  bound into the preimage — typed-body validation is defense in depth, never a substitute for
  binding interpretation; a flipped type byte now fails the signature itself).
  **Strict DER encoding, low-S only.** BSM was considered and rejected (review Q3): raw ECDSA
  with explicit rules is cleaner for independent implementations than BSM's message-envelope
  quirks; the prefix pins protocol+version into the signed bytes (cross-protocol replay refusal).
- Verification rules, explicit: reject high-S; reject non-strict DER; reject any pubkey that is
  not 33-byte compressed; the signed digest is computed over the literal `body_bytes` extracted
  from the transaction — a verifier never re-serializes JSON to check a signature.
- `body_bytes` JSON constraints (rejected on violation, codex-crypto): UTF-8 only · duplicate
  keys REJECTED · numbers MUST be integers within IEEE-754 exact range (|n| ≤ 2^53−1), no
  floats/exponents · parsers MUST enforce a size bound before parsing.

### 0x02 — ARTIFACT MANIFEST (signed-body envelope; JSON body)

```json
{
  "bgit": 1,
  "kind": "git-bundle",
  "repo": "monero/monero",
  "source_hint": "https://github.com/monero-project/monero",
  "artifact_sha256": "<hex of the complete reassembled artifact>",
  "artifact_bytes": 269600118,
  "parts": [
    { "txid": "<hex>", "sha256": "<hex of this part>", "bytes": 9900000 }
  ],
  "bundle_refs_sha256": "<hex, §4>",
  "label": "UNSIGNED MIRROR",
  "claimable": true,
  "spec": "<txid of the on-chain copy of THIS document>",
  "published_at": "2026-08-15T00:00:00Z"
}
```

`parts[]` order IS concatenation order; per-part sha256 makes each part independently verifiable
and fetches resumable. `artifact_sha256` over the reassembled whole is the only success claim a
reader trusts. `kind` is a closed enum: `git-bundle` here, and `proof-only` (§11, a fingerprint-only
notarization publish that OMITS `parts`); `git-bundle-incremental` + `basis` (the bundle-chain)
remains reserved. Unknown JSON fields MUST be ignored (additive evolution). **The ARTIFACT MANIFEST's signer MUST
be an authorized key of the REF chain at the manifest's mined position (the same §3 rule 2
authorization set); a mismatch is a REFUSAL, not a disclosure** (v1.3, round-two: §3 binds the
manifest to the ref-key lineage, so a foreign-signed manifest is invalid, full stop).

### 0x03 — REF MANIFEST (signed-body envelope; the mutable pointer)

```json
{
  "bgit": 1,
  "repo_id": "<P2PKH address, §5>",
  "seq": 1,
  "prev": "<txid of the previous REF MANIFEST, or null iff seq == 1>",
  "artifact": "<txid of the ARTIFACT MANIFEST this ref-state points at>",
  "refs_sha256": "<must equal the artifact manifest's bundle_refs_sha256>",
  "role": "unsigned-mirror",
  "claim_how": "Publish a CLAIM ATTESTATION (0x06) binding this repo_id to your maintainer key and canonical domain, then a REF MANIFEST with role 'maintainer' citing the current tip in prev. Readers prefer the maintainer chain once its attestation verifies."
}
```

**THE WINNER RULE (v1.1, deterministic for a fresh reader — codex-crypto):**

1. **Genesis anchor:** the valid chain for a `repo_id` begins at the earliest-MINED REF MANIFEST
   with `seq == 1` and `prev == null`, signed and paying the repo address. Later "genesis"
   candidates are void.
2. **Chain validity:** each subsequent manifest MUST have `seq == prev.seq + 1`, an unchanged
   `repo_id`, a valid signature, and `prev` naming the mined txid of its parent — **AND (v1.3,
   the A1 law integrated INTO resolution, not appended after it): the signer MUST be an
   AUTHORIZED key at that point in the chain.** Authorized = the genesis manifest's pubkey, OR
   the `maintainer_pubkey` of a valid CLAIM ATTESTATION (0x06) mined EARLIER than this manifest
   whose `target_ref` was the then-current winning tip. Authorization is evaluated DURING the
   mined-order walk, BEFORE any fork comparison — an unauthorized child is INVALID outright and
   can never win a race, at any position, in any order.
   **THE GENESIS AUTHORIZATION EXCEPTION (round three, normative): the genesis manifest's pubkey
   is authorized at EVERY 0x02/0x03 position of its chain — including an ARTIFACT MANIFEST mined
   before the seq=1 REF MANIFEST exists** (every first publication mines its artifact before its
   genesis ref; without this exception no repo could ever be born). This is an explicit
   authorization exception, not temporal retroactivity. Claimant authority begins ONLY at its
   claim's acceptance moment, never earlier.
   **FIRST-CLAIM PERMANENCE (round three, normative): the first ACCEPTED claim per
   `maintainer_pubkey` permanently grants that key. Any later claim by an already-authorized key
   is a validated record whose authority effect is a NO-OP** — it cannot re-anchor, refresh,
   change domain or role, or make a stale `target_ref` current.
3. **Forks:** at the FIRST height where two valid (per rule 2, authorization included) children
   cite the same parent, the **first-mined child wins permanently**; every descendant of the
   losing child is ineligible forever. (Mined order = block height, then transaction index
   within the block.) **Same-block competing children when the reader's source cannot supply the
   intra-block index → the reader REFUSES to resolve the repo (typed), never guesses by source
   order** (v1.3, round-two: a source that cannot implement the forever rule does not get to
   approximate it). **This extends to POSITIONAL DEPENDENCIES between record types (round three):
   a CLAIM ATTESTATION and any REF MANIFEST whose validity or authority could depend on their
   relative order, sharing one block, REQUIRE the intra-block index — without it, typed
   `AMBIGUOUS_MINED_ORDER` refusal; with it, height then index. A positional dependency is NEVER
   source-ordered.**
4. **Tip:** the winner is the highest-seq manifest on the single surviving chain.
5. **Confirmation policy (only-mined-promotes, ours):** a reader treats an unmined manifest as
   PENDING, never as the tip. Mined ordering is the only clock.
6. **Honest limits, documented not hidden:** a FRESH reader (no local state) cannot detect a
   freeze (withheld newer manifests) — mitigation is k-source reads. A STATEFUL reader
   additionally keeps a per-repo high-water seq and never goes backwards. Signatures alone cannot
   prove freshness; nothing in v1 claims otherwise.

### 0x06 — CLAIM ATTESTATION (signed-body envelope; the claim's durable half — codex-crypto)

```json
{
  "bgit": 1,
  "repo_id": "<P2PKH address>",
  "maintainer_pubkey": "<hex compressed>",
  "domain": "getmonero.org",
  "role": "maintainer",
  "target_ref": "<txid of the REF MANIFEST tip being claimed from>"
}
```

Signed by `maintainer_pubkey`. The off-chain half — `https://<domain>/.well-known/bgit`
containing `repo_id` and `maintainer_pubkey` — is AUTHORIZATION EVIDENCE AT CLAIM TIME: readers
(and humans) check it when the claim happens and SHOULD archive proof, but the durable record of
who claimed, from where, binding which tip, lives on chain in this record. A domain that later
dies does not un-claim a repo. A claim is REPLAY-PROOF by `target_ref`: re-presenting an old
attestation against a newer tip binds nothing.

## 4. `bundle_refs_sha256`

`git bundle list-heads <bundle>` → lines `"<sha1> <refname>"` → sort lexicographically by
refname → join with `\n` (no trailing newline) → sha256. Deterministic and computable by anyone
from the bundle alone. A reader MUST recompute this from the reconstructed bundle and match it
against the manifest (codex-crypto: verify the digest from the artifact, not from trust).

## 5. The REPO ADDRESS (repo_id + discovery)

- `repo_id` = a P2PKH address. For the Monero Mirror: a FRESH dedicated key (throwaway-wallet
  law; retired after publish — the repo's future belongs to whoever claims it).
- **Every transaction of the publication — ALL FOUR record types, no exceptions — pays ≥1 output
  (dust) to the repo address**, and readers ENFORCE it: a bgit record in a transaction that pays
  nothing to the walked repo address is rejected (v1.3, round-two: the earlier PART/ARTIFACT
  enforcement exception was a divergence from this law, cured in the reader, not the law).
  **Discovery = walk the address history, filter first-pushdata `bgit`.**

## 6. THE READER ALGORITHM (normative — this section is the product)

Given: a repo address, and any source of (a) address history and (b) raw transactions.

1. Enumerate the address's transactions in MINED order. For each, find outputs matching
   `OP_FALSE OP_RETURN "bgit" <record>`. **Exactly one such output per tx; more than one → the
   whole transaction is non-conforming, ignore it.** Parse the envelope (§2); enforce size
   bounds BEFORE parsing any JSON; skip unknown versions/types (report, never error; skipped
   records never influence winner selection).
2. Collect REF MANIFESTs. Verify each signature over the LITERAL body bytes (strict DER, low-S,
   33-byte compressed pubkey; reject violations). Enforce the JSON constraints (§3): duplicate
   keys, non-integer numbers, or oversize → reject the record. Apply the WINNER RULE including
   the genesis anchor and permanent fork resolution. Verify `repo_id` matches the walked address
   on every record in the chain.
3. Fetch the winning ARTIFACT MANIFEST by txid; verify its record TYPE is 0x02 and its signature.
   For each `parts[]` entry in order: fetch, extract, verify per-part sha256. Concatenate.
4. Verify `artifact_sha256` over the whole. Then reconstruct the bundle's ref digest (§4) and
   verify it equals BOTH the artifact manifest's `bundle_refs_sha256` AND the winning REF
   MANIFEST's `refs_sha256`. Any mismatch → REFUSE loudly; never hand over unverified bytes.
5. `git clone <artifact>.bundle <dir>` — stock git, no plugin, done.
6. An empty or short walk from ONE source proves nothing — cross-check a second source before
   declaring an artifact absent. State PENDING for anything unmined.

## 7. What v1 deliberately does NOT do

No incremental bundles yet (kind reserved, format ready) · no human-readable naming (repo_id
only; naming killed two of the six dead predecessors) · no encryption (this is the PUBLIC
format) · no multi-maintainer/threshold roles (0x04/0x05 reserved are the road) · no freshness
guarantee (stated in §3.6, mitigated by k-source reads, never claimed away).

## 8. TEST VECTORS TO PIN BEFORE FIRST BROADCAST (the review's mandate)

1. Cross-implementation signature vectors (fixed key, fixed body bytes → exact sig; verify in a
   second independent implementation).
2. Unicode/duplicate-key/noncanonical-number REJECTION vectors.
3. Fork-at-every-height winner-selection vectors (incl. losing-descendant ineligibility).
4. Replayed CLAIM ATTESTATION rejection (stale `target_ref`).
5. Unknown-v2-record coexistence (v1 reader resolves the v1 path untouched).
6. Adversarial multi-output extraction (two bgit outputs in one tx → whole tx ignored).

## 9. Resolved questions (v1.0 §8 → v1.1 answers, all per the codex-crypto review)

Q1 one-output-per-tx: KEEP · Q2 metadata-free PARTs: KEEP · Q3 signature: raw ECDSA strict-DER
low-S, not BSM · Q4 claim attestation: ON CHAIN (0x06), .well-known = claim-time evidence ·
Q5 dust-on-every-tx: KEEP · Q6 signing: LITERAL BYTES, never canonical-form.

## 10. v1.2 AMENDMENTS (2026-08-15 morning — closing what IMPLEMENTATION found; round-two input)

*The reader was implemented from this document alone as a deliberate spec audit; it surfaced 13
ambiguities (full list in `./README.md`). The two that are SECURITY and
the mechanical ratifications are amended here; round two reviews these amendments explicitly.*

**A1 — KEY BINDING (closes the squat-by-race hole, ambiguity #1 — SECURITY).** The §3 winner rule
required only "a valid signature," binding a chain to NO key: any signer could extend anyone's
chain by winning the first-mined race after the tip. Amended law: **every REF MANIFEST must be
signed by the SAME pubkey as its chain's genesis manifest**, with exactly one exception — a
manifest whose signer equals the `maintainer_pubkey` of a valid, earlier-mined CLAIM ATTESTATION
(0x06) whose `target_ref` is the then-current tip (the claim escalation, now part of the
NORMATIVE winner rule, not a preference note). A manifest signed by any other key is INVALID
regardless of seq or mining order. Future 0x04 KEY_ROTATE / 0x05 DELEGATE records widen this;
until they are defined, genesis-key-or-valid-claimant is the entire law.

**A2 — SIGN THE ENVELOPE BYTES TOO (ambiguity #2 — proposed, round-two decides).** The version
and type bytes sit OUTSIDE the signed preimage; a flipped type byte reinterprets a signed body.
Proposal: preimage becomes `SHA256("bgit1|" || version_byte || type_byte || body_bytes)`.
Invalidates the pinned test vector (regeneratable — nothing is broadcast yet). If round two
prefers the current preimage, the mitigations are: `"bgit": 1` REQUIRED in every typed body
(ratified below) + per-type required-field validation, which already causes cross-type parses to
fail. Round two picks.

**RATIFIED implementation choices (ambiguities #3-#13, now normative):** varint = Bitcoin
CompactSize, canonical encoding only (non-canonical → record rejected — two encodings is
malleability) · trailing bytes after the signature → record rejected (unsigned bytes are
malleable in flight) · signed-JSON body size bound = 1 MiB · `"bgit": 1` REQUIRED and checked in
every typed body · duplicate-key detection compares ESCAPE-DECODED keys at every depth (a custom
scanner is mandatory; `JSON.parse` silently dedupes) · §4 sort = bytewise UTF-8 · pushdata forms:
writers emit minimal, readers accept all four (read-old-forever); extra pushes beyond the two =
tagged-but-malformed and still COUNT toward the multi-output rule · claim evaluation = tip as of
the claim's mined position (stale `target_ref` → rejected) · mined order: where a source lacks
intra-block index, height-then-source-order WITH disclosure on same-height REF ties (strict
compliance requires block data) · dust-to-repo enforced on REF/CLAIM records, advisory on
PART/ARTIFACT (parts are reached by manifest txid, not by walk) · the artifact manifest's signer
SHOULD equal the ref-tip signer; mismatch is DISCLOSED (round two may harden to refusal) ·
`artifact_bytes` is a REQUIRED reader check · the `spec` field is OPTIONAL on a first-ever
publish (chicken-and-egg; the canary publish of this document fills it for the main publish).

## 11. v1.4 AMENDMENT — the proof-only kind (notarization) (2026-08-19)

*An ADDITIVE v1 extension: a second `kind` value that anchors a repository's FINGERPRINT on chain
without its bytes. It proves EXISTENCE — the artifact existed, at this time, signed by this key,
unaltered since — NOT permanence. The bytes stay in git; only the commitment is published, for a
few hundred satoshis instead of ~$20/GB. Hardened the way this format was: a Claude adversarial
workflow plus the OpenAI Codex (codex-crypto seat) review wire — a design pass, then two rounds on
the built code; every finding folded, none rebutted. The trial record continues below, as before.*

**THE ONE LAW of this amendment:** existence (proof-only) and permanence (a full git-bundle publish)
MUST NEVER blur — at any surface, in any code path — and every ambiguity resolves TOWARD permanence.
A reader that lets a proof-only publish be read, reported, or verified as bytes-on-chain has failed.
Everything below serves that law, fail-closed.

### 11.1 ARTIFACT MANIFEST (0x02) — the proof-only kind
A proof-only artifact manifest is an ordinary 0x02 signed-body envelope with two differences:
- `"kind": "proof-only"` in place of `"git-bundle"`.
- **The `parts` key is ABSENT** — omitted entirely, never `[]` and never `null`. (An empty array
  reconstructs to a zero-byte artifact a reader could "restore"; absence is the on-chain signal that
  NO bytes were published.)
The commitment fields are UNCHANGED and REQUIRED: `artifact_sha256`, `artifact_bytes`,
`bundle_refs_sha256` (§4). They fingerprint the same `git bundle --all` an ordinary publish would
have chunked — the repository is fully described, just not stored. `label`, `claimable`, `spec`,
`published_at`, `source_hint` carry their usual meanings.

```json
{
  "bgit": 1,
  "kind": "proof-only",
  "repo": "you/myrepo",
  "source_hint": "https://github.com/you/myrepo",
  "artifact_sha256": "<hex of the git bundle --all that is NOT published>",
  "artifact_bytes": 269600118,
  "bundle_refs_sha256": "<hex, §4>",
  "label": "PROOF-ONLY",
  "claimable": false,
  "spec": "<txid of the on-chain copy of THIS document>",
  "published_at": "2026-08-19T00:00:00Z"
}
```

The only structural difference from the 0x02 example above is the flipped `kind` and the total
ABSENCE of `parts` — that absence is the on-chain signal that no bytes were published, which is why
`[]` and `null` are both refused (`PROOF_ONLY_HAS_PARTS` / §3 parts validation).

### 11.2 REF MANIFEST (0x03) — the `stores_bytes` ratchet
`kind` lives only in the artifact manifest, but the winner rule (§3) resolves on the REF chain, so
the storage promise is ratcheted into the SIGNED ref body:
- A new OPTIONAL boolean `stores_bytes`, emitted ONLY on a proof-only ref (where it is `false`). A
  git-bundle ref OMITS it — so existing signed refs are byte-identical and their vectors unchanged.
- **A reader reads an ABSENT `stores_bytes` as `true` (permanence)** — the read-old-forever default:
  every REF MANIFEST published before this amendment has no such field and reads, correctly, as a
  full-bundle ref.
- Present → MUST be a boolean, else the record is rejected (`FIELD_INVALID:stores_bytes`).

A proof-only ref is an ordinary 0x03 REF MANIFEST body (the §3 fields — `repo_id`, `seq`, `prev`,
`artifact`, `refs_sha256`, `role`) plus the one added field:

```json
{ "...": "…ordinary 0x03 ref fields…", "stores_bytes": false }
```

### 11.3 THE WINNER RULE IS UNCHANGED
`stores_bytes` and `kind` do NOT affect which chain wins. Resolution stays storage-blind — the
genesis anchor, seq/prev validity, authorization, and permanent fork resolution (§3) select the tip
exactly as before. proof-only adds two layers ON TOP of the resolved chain (a cross-check and a
recovery view), never a change to resolution. A proof-only tip may therefore sit on a chain whose
ancestors are full bundles, and the reverse.

### 11.4 THE STORAGE CROSS-CHECK (reader, normative)
Once the tip and its artifact manifest are resolved and their digests agree (§6.3), the reader MUST
cross-check the tip's declared storage against its artifact's kind: the tip ref's `stores_bytes`
(absent → `true`) MUST equal (`kind` of the tip's artifact === `git-bundle`). A mismatch is a
REFUSAL (`STORAGE_KIND_MISMATCH`), not a disclosure. This is what makes a proof-only publish DECLARE
itself: a proof-only artifact under a ref that omits `stores_bytes` (which reads as permanence) is
refused — a proof-only publish can never masquerade as a full one, nor a full one be mislabeled.

### 11.5 THE KIND CLASSIFIER (reader, normative)
`kind` is a CLOSED enum. The reader classifies each artifact manifest as exactly one of `git-bundle`,
`proof-only`, or REFUSED:
- `kind === "git-bundle"` → REQUIRES a non-empty, well-formed `parts` array (§3).
- `kind === "proof-only"` → REQUIRES the `parts` key ABSENT (present → `PROOF_ONLY_HAS_PARTS`).
- **`kind` ABSENT + a valid non-empty `parts` array → `git-bundle`.** Read-old-forever: this format's
  original reader ignored `kind` entirely and reconstructed any valid-parts artifact, so a pre-`kind`
  record must still read. This branch REQUIRES real parts, so it stores real bytes — no proof-only
  can reach it.
- A `kind` present but outside the enum (a typo, a reserved-future value such as
  `git-bundle-incremental`), or a `kind` ABSENT with no `parts` key at all, is REFUSED
  (`UNSUPPORTED_ARTIFACT_KIND`). (An absent `kind` carrying a present-but-empty-or-malformed `parts`
  array takes the legacy git-bundle path above and is rejected by the ordinary §3 parts validation —
  `FIELD_INVALID:parts` — not the unknown-kind refusal; both refuse fail-closed.) Refusing loudly is
  correct read-old-forever behaviour: a v1 record whose kind THIS reader does not implement is not
  something to guess at — it says "upgrade your reader," never mishandles the bytes.

### 11.6 RECONSTRUCTION AND RECOVERY (reader, normative)
- A proof-only artifact is NEVER reconstructed. The reader returns its commitment (the three
  fingerprints) and writes NO file — not even a partial one — in a distinct result that shares no
  "verified / restored / cloned" vocabulary with a full read.
- The reader ALSO reports the last recoverable FULL bundle on the winning chain: walk the resolved
  chain from the tip toward genesis and name the highest-seq ref whose ARTIFACT is a classified
  `git-bundle` — keyed off the classifier verdict, NOT the ref's self-declared `stores_bytes` (an
  ancestor ref is not cross-checked during resolution, so trusting its flag here would let a
  proof-only ancestor masquerade as recoverable). It further reports whether that ancestor's PART txs
  are actually present in the walk — a git-bundle manifest can be mined while a part never lands, so
  "the manifest DECLARES a full bundle" and "its bytes are reachable from this source" are separate,
  separately reported facts. A proof-only tip can thus never HIDE the recoverable bytes beneath it,
  nor falsely PROMISE bytes that are not there.

### 11.7 VERIFYING A PROOF-ONLY REPOSITORY
A proof-only publish stores no bytes, so its `bundle_refs_sha256` cannot be recomputed from chain.
Verification therefore REQUIRES the caller's own local bundle: run `git bundle verify`, recompute all
three fingerprints from the local bytes, and compare to the on-chain commitment. A full match proves
the LOCAL copy is the one the chain anchored, unaltered — `VERIFIED_LOCAL_BYTES_NOT_STORED_ON_CHAIN`.
A fingerprint or signature match ALONE, against no bytes, MUST NEVER be reported as "verified" or as
chain reconstructability — verifying a fingerprint against nothing is meaningless.

### 11.8 PUBLISHER POLICY — the downgrade is consent-gated
Continuing a chain whose current tip STORES bytes with a proof-only publish is a permanence→existence
DOWNGRADE (the tip flips to unrecoverable-at-the-tip). The publisher REFUSES it (`DOWNGRADE_REFUSED`)
unless the operator explicitly opts in — checked at plan time AND again if the tip moves mid-publish.
Even after a deliberate downgrade the reader still surfaces the last recoverable bundle (§11.6): belt
and suspenders. (Publisher policy, not a reader rule — a reader validates the chain it is handed.)

### 11.9 READ-OLD-FOREVER GUARANTEE
proof-only is purely additive. Every repository published before it is UNAFFECTED: its artifacts
carry `kind:"git-bundle"` and resolve byte-identically; its refs omit `stores_bytes` and read as
permanence. A reader that does not implement this amendment refuses a proof-only record loudly
(unknown kind) rather than mishandling it — a documented integrity floor, not a silent vanish.
proof-only is durable to readers implementing v1.4+; older readers reject it by shape, exactly as
§0.1 requires.

## Provenance

Designed and hardened 2026-08-14/15. Three adversarial review rounds by OpenAI Codex
(codex-crypto seat) over a signed cross-vendor coordination wire; verdicts CHANGES-REQUIRED,
CHANGES-REQUIRED, PUBLISH-WITH-CHANGES; every finding folded, zero rebutted. The §11 v1.4
proof-only amendment (2026-08-19) was hardened the same way — a Claude adversarial workflow (a
design pass, then two rounds on the built code) plus the codex-crypto review wire; three defects
and a compatibility caveat found and folded, none rebutted, each pinned to a red-proven test. The
review record above is part of this document deliberately: a forever-format should carry its own
trial transcript. This document is also published ON CHAIN as the first bgit repository
(repo_id 19Zb3LTpheqZ3XDxJyPEuDcCPyd1re9tWo) — the format hosts itself.
