# The Spec Audit — 13 ambiguities found by implementing the reader from the document alone

*The reader was deliberately written by an implementer who had ONLY the spec text — every place
they had to guess became a finding. All 13 were dispositioned across three adversarial review
rounds; the two security-grade ones (key-lineage binding, envelope-byte signing) became normative
law. This discipline is the reason the format is trustworthy: it was audited by construction.*

## SPEC-AMBIGUITIES — the 13 audit findings and their round-two dispositions

*The reader-as-spec-audit surfaced 13 ambiguities against v1.1. Round two (codex-crypto, wire
`6c28d89d…`) ruled on all of them; v1.2 §10 + v1.3 fold the rulings into the spec, and this
tree implements them. Status per item:*

1. Key lineage unbound (squat-by-race) — **RESOLVED (A1, v1.2→v1.3):** genesis-key-or-valid-
   claimant is now normative AND evaluated inside the walk, before fork comparison. Implemented;
   pinned by tests 9/10.
2. Envelope version/type bytes outside the signature — **RESOLVED (A2, v1.3):** preimage is
   `SHA256("bgit1|" || VERSION || TYPE || body)`; pinned vector regenerated; test 1c pins the
   type-flip failure. `"bgit":1` required in typed bodies stays as defense in depth.
3. "varint" undefined — **RATIFIED:** Bitcoin CompactSize, canonical-only (non-canonical
   rejected).
4. Trailing bytes after the envelope signature — **RATIFIED:** rejected (unsigned → malleable).
5. Size bound mandated but no number — **RATIFIED:** 1 MiB for signed JSON bodies.
6. Pushdata minimality unstated — **RATIFIED:** writers minimal; readers accept all four forms;
   extra pushes = tagged-but-malformed, still counting toward the multi-output rule.
7. Duplicate-key representation — **RATIFIED:** compared escape-decoded at every depth; a custom
   scanner is mandatory (`JSON.parse` dedupes silently).
8. Claim evaluation moment — **RATIFIED:** tip-as-of the claim's mined position; now evaluated
   inside the winner-rule walk (v1.3), where the claim also GRANTS authority from that moment.
9. Mined order without an intra-block index — **OVERTURNED STRICTER (v1.3):** same-block
   competing VALID children → typed `AMBIGUOUS_MINED_ORDER` refusal, never source-order
   approximation. Height-then-source-order remains fine when no such tie exists.
10. §4 sort locale/encoding — **RATIFIED:** bytewise UTF-8.
11. Dust asymmetry (REF/CLAIM only) — **OVERTURNED STRICTER (v1.3):** dust-to-repo enforced on
    ALL FOUR record types, on the walk and on the reassembly fetch-by-txid path. Test 12.
12. Artifact-signer mismatch disclosed-not-refused — **OVERTURNED STRICTER (v1.3):** the
    manifest's signer must be an authorized key of the ref chain at its mined position;
    mismatch = `ARTIFACT_SIGNER_UNAUTHORIZED` refusal. Test 13.
13. `spec` field unfillable on a first-ever publish — **RATIFIED:** optional `--spec-txid`,
    omitted when absent.

**Round three (wire `fe593953`, verdict PUBLISH-WITH-CHANGES): all three implementation
residuals RULED as built, now normative + pinned:**

- **THE GENESIS AUTHORIZATION EXCEPTION** (§3 rule 2): the genesis key is authorized at EVERY
  0x02/0x03 position of its chain, including an artifact manifest mined before the seq=1 ref —
  an explicit exception, not temporal retroactivity; claimant authority begins only at its
  claim's acceptance. Pinned by test 15 (incl. the foreign-key refusal at the same pre-genesis
  position and the no-retroactivity negative).
- **CLAIM/REF POSITIONAL DEPENDENCIES** (§3 rule 3): a claim and any ref whose validity or
  authority could depend on their relative order, sharing one block, require the intra-block
  index — without it, typed `AMBIGUOUS_MINED_ORDER`; with it, height-then-index. The walk now
  detects: authority born and used in one block (both observed orders) AND a claim's
  accept/stale verdict racing a same-block tip advance. Pinned by test 16.
- **FIRST-CLAIM PERMANENCE** (§3 rule 2): the first accepted claim per `maintainer_pubkey`
  grants permanently; any repeat by an already-authorized key is a validated record whose
  authority effect is a NO-OP — no refresh, re-anchor, domain/role change, and a stale target
  can never be made current. Pinned by test 17 (authority timeline proven byte-identical with
  and without the repeats).

**Residual property, stated not hidden:** because claims are wire-open (the `.well-known`
domain check is claim-time evidence, not reader-verifiable), any key can claim the current tip
and thereby stage a same-block race or positional dependency — so against an INDEX-LESS source,
a determined adversary can force `AMBIGUOUS_MINED_ORDER`. That is the ruled trade-off: the cure
is a source with block data (the refusal names it), never a source-order guess.

---

## THE TOOLING TRIALS — claim verb + publisher `--continue` (2026-08-16, two rounds each)

*The same discipline applied to the tools that exercise the law. Both were designed on paper,
adversarially reviewed BEFORE code by the same reviewer lineage (OpenAI Codex, crypto seat)
that tried the wire format, built with every finding folded, and approved on a second round
against the finished code and gates. No finding was rebutted.*

**`claim.mjs` — round one (BUILD-WITH-CHANGES):** the `.well-known` evidence must be FETCHED
and receipted by the verb itself — twice, the second immediately before broadcast — never
asserted by a flag, with no production bypass (the offline fixture seam has no broadcast path
at all). Already-claimed detection must read the resolved authority timeline, not raw 0x06
records, because stale or repeated attestations are not grants. `target_ref` and claim state
must derive from ONE immutable walk snapshot, re-walked immediately before broadcast, refusing
on any motion. Fee math must run on the actual single-input transaction, and the funding
outpoint must provably pay the signing key. **Round two: APPROVED.** Gates: a claim built
through the verb flips the real reader to the maintainer chain, with an inverted-mined-order
red control proving the mined order — not array order — decides; refusal battery; source pins;
a deliberate mutation (bite) test proving the suite catches a neutered refusal.

**`publisher.mjs --continue` — round one (BUILD-WITH-CHANGES):** one shared chain-walker for
reader, claim, and continue, with tip role and grant provenance bound into the snapshot digest
so authority changes count as motion. Continuation authority (genesis key or accepted
claimant) is checked before any satoshi moves. Claimant refs are FORCED to `role:
"maintainer"`, and `claim_how` is emitted only on unsigned mirrors — a claimed repo must not
advertise an invitation already exercised. The required finding: in a multi-transaction
publish, the tip can move WHILE parts are broadcasting, stranding the final ref manifest as a
permanent fork loser after the sats are spent — so the broadcast path walks the chain again
immediately before the ref's POST and either lawfully re-derives it against the new mined tip
(with explicit superseded/pending accounting) or refuses, reporting already-posted data
honestly as reusable strands. **Round two: APPROVED.** Gates: genesis and claimant
continuations executed end-to-end through the real reader; unauthorized-key refusal proven
pre-spend; ordering and retarget invariants source-pinned; an UNAUTHORIZED_KEY bite proving
test sensitivity; the full prior vector suite untouched.
