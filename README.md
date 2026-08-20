# bgit

**Publish git repositories to Bitcoin. Reconstruct them. Clone them with stock git.**

No platform, and no company — including the one that wrote this — that has to stay alive for your
history to be recoverable.

Said precisely, because the precision is the point: mined data is **erasure resistant, not
availability guaranteed**. Recovery works while at least one archival copy exists and some source
will serve it, and anyone may be that source. Git clones the reconstructed bundle, not the
blockchain directly. The [honest limits](#honest-limits-stated-before-you-find-them) are stated in
full below, before you go looking for them.

**Evicted, banned, or displaced by a code host?** We will publish your repository's bundled history to Bitcoin
free of charge — [indelible.one/bgit](https://indelible.one/bgit), or email `indeliblebsv@gmail.com`
with the repository URL.

---

## Why this exists

In July 2026, India ordered GitHub to delete repositories on three hours' notice. The same
season, Codeberg's new terms banned cryptocurrency projects from its platform — and, around the
same time, code written mostly by AI, naming Claude and Codex. (This repository, built with both,
would be banned twice.) On a Monero community podcast,
someone asked the obvious question — *"can we just store it on BSV?"* — and nobody in the room
had an answer.

This is the answer. Every ref and every reachable object a `git bundle --all` captures, written
into Bitcoin SV transactions as plain data and clonable with the git you already have. Removing it
would mean removing it from every copy of a proof-of-work blockchain that still holds one — which
is a different and much harder thing than a platform deleting the canonical copy, though it is not
the same as impossible: data can be withheld, and nodes are not obliged to serve it. Hosting
platforms have policies. Mined blocks don't.

The first repository ever published in this format is [the format's own specification](./SPEC.md).
The second is **Monero's repository history** — 13,241 commits, 8,463 refs, 257 MB, its own bundle in full (submodules are separate repositories; see the limits) — published
as a labeled, claimable **unsigned mirror**: meaning the project itself has not signed it, so any
maintainer can later [claim it](#the-claim-mechanism--why-unsigned-mirror-matters). Total cost: about six dollars, once.

## How it works, in one breath

The **publisher** packs a repo with `git bundle` (git's own portable format), slices it into
~10 MB chunks, and writes each chunk into a transaction. Two small signed records join them on
chain: an **artifact manifest** (the table of contents — every chunk's hash, plus the hash of the
whole) and a **ref manifest** (which state is current, signed by the repo key). The **reader**
reverses it from nothing but a transaction source: walk one address (read every transaction that
address has ever received), collect the records, verify
every signature and every hash, refuse anything that doesn't check out — and hand you a `.bundle`
file that stock git clones. That's the whole trick. Git objects were always content-addressed and
immutable; they were waiting for a ledger with the same properties.

bgit does this two ways: store the whole history on chain so it can be reconstructed (permanent,
~$20/GB), or anchor only its fingerprint to prove it existed exactly as it was (notarization, a
fraction of a cent — the bytes stay in your git). Most of this page is the first;
[the second is below](#proof-only-publishing--anchor-a-repository-without-storing-it).

## Quickstart: reconstruct a repository from the chain

```
git clone https://github.com/zcoolz/bgit && cd bgit && npm install

node reader.mjs \
  --repo-id <the repo address> \
  --history-url 'https://api.whatsonchain.com/v1/bsv/main/address/{address}/history' \
  --tx-url     'https://api.whatsonchain.com/v1/bsv/main/tx/{txid}/hex' \
  --out repo.bundle

git clone repo.bundle my-repo
```

Any address-history + raw-transaction source works, provided it supplies authoritative mined
ordering — including an intra-block index where a same-block dependency decides the outcome.
Without that the reader refuses rather than guessing. The two shown are public examples, not
dependencies. **There are deliberately no default endpoints anywhere in these tools**: your data
source is your choice, always explicit, so no company (ours included) sits silently in your path.

The reader verifies everything it touches: strict-DER low-S signatures over the exact published
bytes, per-chunk SHA-256, whole-artifact SHA-256, and a ref digest recomputed from the
reconstructed bundle itself. If any check fails, it refuses loudly and hands you nothing. An
unverified artifact is not an artifact.

## Publishing your own repository

```
git bundle create myrepo.bundle --all

node publisher.mjs --bundle myrepo.bundle --repo you/myrepo \
  --key-file key.json --local-out ./fixture        # dry-run: full plan, exact cost, zero spend

node publisher.mjs --bundle myrepo.bundle --repo you/myrepo \
  --key-file key.json --local-out ./fixture \
  --broadcast --funding <txid>:<vout>:<sats> --bridge <your broadcast endpoint>
```

`key.json` is `{"wif": "<a BSV WIF>"}`, and this key *is* your repository's identity. Its address
becomes your `repo_id` — the string a reader passes to `--repo-id` to reconstruct you — and the dry
run prints it (`repo_id: ...`) before anything is spent. The `--repo you/myrepo` value is only a
human-readable label stored in the manifest; it is not what readers use to find the repo. Keep the
key to publish updates: whoever holds it controls the chain.

**Updating a published repository** — `--continue` publishes a new bundle onto an existing
chain:

```
node publisher.mjs --bundle updated.bundle --repo you/myrepo --key-file key.json \
  --continue --history-url '<tpl>' --tx-url '<tpl>' --local-out ./fixture
```

The publisher walks the chain itself, derives `seq`/`prev` from the resolved tip (no flag can
supply them), and refuses — before any satoshi moves — if the signing key is neither the
genesis key nor an accepted claimant. A claimant's refs are forced to `role: "maintainer"`,
and if the chain moves *while* a multi-transaction publish is broadcasting, the final ref
manifest is re-derived against the new tip or refused with the already-posted data honestly
reported — never left as a silent fork loser.

Dry-run is the default; broadcasting requires the explicit flag *and* a named coin. Every
transaction is built, hashed, and persisted to disk before the first broadcast — if anything dies
mid-publish, you re-run and already-mined transactions simply confirm. Immediately before each
send, the publisher re-hashes the exact bytes it is about to transmit and refuses on any drift.
After broadcasting, every txid reports **PENDING** — only the separate `--confirm` pass, checking
for mined blocks, is allowed to say "accepted." A relay acknowledgment is not acceptance.

Cost at the proven fee floor (150 sat/KB): roughly **$20 per GB, once** — a typical source repo's
full history lands between pennies and a few dollars. No renewal. No account. The measured
receipt: Monero's entire 257 MB history cost ~40.4M satoshis (≈ $6 at time of publish) across 30
transactions.

## Proof-only publishing — anchor a repository without storing it

Sometimes you don't need the bytes on chain, you need *proof* the bytes existed — exactly as they
were, no later than a given moment, signed by a key you hold. That is notarization: prior-art and IP
disputes, a dated release or a security-disclosure timeline, provenance for AI-generated code, or
simply proving a git history was not backdated. The notary is Bitcoin — no timestamp authority, no
calendar server, nothing that has to still be running years from now for the proof to hold.

It costs a couple hundred satoshis, a fraction of a cent, instead of ~$20/GB — and unlike a full
publish it does not scale with size: a 10 GB monorepo notarizes for the same couple hundred sats as
a single-file gist, because only the fixed-size fingerprint goes on chain:

```
node publisher.mjs --bundle myrepo.bundle --repo you/myrepo --key-file key.json \
  --proof-only --local-out ./fixture        # dry-run: two transactions, a couple hundred sats
```

To broadcast it for real, add the same `--broadcast --funding <txid>:<vout>:<sats> --bridge
<endpoint>` a full publish uses: the identical two-transaction path, only without the chunk
transactions.

A proof-only publish writes the artifact manifest and the ref manifest — the same signed
fingerprint an ordinary publish carries — and *no chunk transactions*. It proves **that this exact
artifact existed, no later than this block, signed by this key, and unaltered since** — existence,
not permanence: anyone who later holds a copy can re-hash it and check it against the on-chain
commitment. It does **not** prove authorship — a signature attests control of a key, not that the
signer wrote the code, the same distinction the claim mechanism draws below — nor permanence. The
code stays in your git, not on chain, so lose every copy and the proof remains but the code is gone.

The two promises are never allowed to blur. A proof-only publish declares itself in the signed
record; the reader refuses anything that would let it read, report, or verify as bytes-on-chain, and
a full permanent publish can never be silently downgraded to a proof. Reading a proof-only
repository returns the fingerprint and a flat "the code is NOT on chain, keep your git copy," never
a faked reconstruction. The normative seam is §11 of [SPEC.md](./SPEC.md).

The proof-only seam was hardened the same way as the core format: a design pass and two adversarial
rounds on the built code over the same cross-vendor review wire, with three defects and a
compatibility caveat folded, none rebutted, each pinned to a red-proven test.

To check a copy you already hold against the on-chain proof:

```
node reader.mjs --verify --repo-id <address> --bundle mycopy.bundle \
  --history-url '<tpl>' --tx-url '<tpl>'
```

VERIFY requires your local bytes on purpose: it runs `git bundle verify`, recomputes all three
fingerprints from *your* file, and compares them to the chain. A match means your copy is the one
that was anchored, unaltered. A fingerprint checked against no bytes proves nothing, and VERIFY will
never call that "verified."

## The claim mechanism — why "unsigned mirror" matters

Anyone can mirror a repository they don't own; the format says so honestly. A mirror *begins*
published with `role: "unsigned-mirror"` and `claimable: true` — a label that says *the project
itself has not signed this.* The instructions for claiming are written **into the chain records
themselves**: a maintainer publishes the required evidence on the project's canonical domain and
a signed claim attestation on chain, and from that moment their records win the chain —
permanently, under a first-claim-per-key law with deterministic fork resolution. No permission
from us and no deadline, and it needs nothing from our servers as long as an archival copy and
some serving source exist.

⚠️ **What a claim proves, exactly:** control of a key and of the canonical domain **at the moment
the claim is mined**. It is not proof of project authorship, and no reader re-checks the domain
afterward — so archive evidence that the file was live. Losing the domain later does not undo a
claim.

**Claiming, in three passes** (`claim.mjs`, in this repo) — all of it refusable before it costs
you anything:

```
# 1. dry run — walks the repo with the real reader, derives the current tip itself
#    (a stale claim is impossible to build), prints the exact evidence file. Spends nothing.
node claim.mjs --repo-id <the repo address> --key-file maintainer-key.json \
  --domain yourproject.org --history-url '<tpl>' --tx-url '<tpl>' --out ./claim

# 2. host the printed file at https://yourproject.org/.well-known/bgit, then:
node claim.mjs ...same flags... \
  --broadcast --funding <txid>:<vout>:<sats> --bridge <endpoint>

# 3. the ONLY pass allowed to say ACCEPTED
node claim.mjs --confirm --state ./claim/claim-state.json --tx-url '<tpl>'
```

The claim transaction costs a few thousand satoshis of your own money — cents, but yours, and the
dry run tells you the number before anything is signed. Before broadcasting, the verb fetches and
receipts your evidence, re-checks it and re-walks the chain immediately before sending, and
refuses by name every situation that would waste the fee: already claimed, chain moved, evidence
missing, funding that isn't yours, ambiguous mined order. Every txid reports PENDING;
only the separate `--confirm` pass may say accepted. The claim's durable half lives on chain;
a domain that later dies does not un-claim a repository.

## The trial record — three adversarial rounds before one byte was broadcast

A format that can never be patched deserves enemies before it gets users. Before the first
broadcast, this specification survived **three adversarial review rounds by OpenAI's Codex**
(against a design built with Anthropic's Claude — two rival labs' models, one signed review wire).
Round one killed canonical-JSON signing before it could split implementations. Round two caught
that the ref-chain security claim was false three ways (rollback, freeze, mix-and-match — the TUF
attack classes) and that authorization wasn't enforced *inside* fork resolution. Round three
ruled on the genesis paradox, same-block ordering, and claim permanence. Every finding was folded;
none was rebutted; the full verdicts live in [SPEC.md](./SPEC.md)'s review record — the trial
transcript ships inside the law.

One caveat we will not leave for you to raise: these were model-driven adversarial reviews — Codex
against a Claude-built design, two rival labs' models on one wire — not a professional third-party
cryptographic audit, and none has been done. They caught real, specific, folded findings; model
review has its own blind spots too. Treat the trial record as evidence of adversarial pressure, not
as a security certification.

The reader has its own origin discipline: it was implemented by someone given *only the spec
text*, and every place they had to guess became a formal finding — [AUDIT.md](./AUDIT.md) lists
all 13, each dispositioned. Two became normative security law. If you implement your own reader
(please do), start there.

Run the vectors yourself: `npm test` — 49 pins covering signature vectors verified across two
independent implementations, every rejection class, fork races at every height, claim replay,
version-coexistence, an end-to-end publish→reconstruct→clone loop, and the §11 proof-only kind (the
closed-enum classifier, the storage cross-check, reconstruction refusal, the ancestor recover walk,
the VERIFY verb and the downgrade gate — each with a red-control that breaks the guard and confirms
it bites).

## Designed for our own death

Every prior attempt at this died — six of them, 2014 to 2021, none of technical impossibility.
The closest ancestor put "GitHub on BSV" live in 2019; its bytes are still on chain today, but
the reader died with the company, so nobody can get them out. This design treats that graveyard
as a spec:

- **The reader is open and the format documented to genesis** — a stranger who can reach a source
  that retains the payloads, the address history, and the ordering rebuilds everything with zero
  contact with us. What they need is data availability, never our cooperation.
- **The spec is published on chain in its own format** — so the knowledge does not depend on this
  website, or on any website, for as long as the chain data remains served.
- **Version byte from byte zero, and a read-old-forever rule** — v2 may add, but a conforming
  reader must keep reading v1. Format migrations that orphan old repos
  are the death this design exists to refuse.

## Honest limits, stated before you find them

- **This protects the artifact, not the author.** Writing costs money on a transparent chain. If
  you need anonymous authorship, git over Tor beats us and we won't pretend otherwise — but the
  writer and the author don't have to be the same person, and a throwaway key can mirror anything.
- **Permanence means erasure-resistance while one archival copy exists** — and anyone may run
  one. That is a different (and better) failure mode than a platform, where one policy decision
  deletes the canonical copy. It is not magic.
- **Proof-only proves existence, not permanence — and not authorship, or first place.** A proof-only
  publish (notarization) anchors only the fingerprint; the bytes never go on chain, so lose every
  copy of your git repository and the proof still stands, but it cannot hand the code back. It proves
  a specific key signed a specific bundle no later than a specific block. It does not prove the signer
  wrote the code, that the bundle matches its `repo` label (that field is self-asserted), or that no
  one holds an earlier proof of the same bytes — for already-public code anyone can fingerprint the
  same bytes and anchor them earlier, so it shows "existed by then," not "existed first," and is
  strongest for bytes that were never public before you anchored them. And no proof-only publish has
  been broadcast to chain yet (the kind shipped 2026-08-19), so the cost figures above are the
  dry-run plan, not a measured receipt like Monero's.
- **Signatures cannot prove freshness.** A frozen ref chain is undetectable from one source, and
  neither is withholding — a single source cannot prove absence. Read from several.
- **"Forever" is bounded by the primitives.** Integrity and authenticity here rest on SHA-256 and
  secp256k1/ECDSA; if either is broken, "unaltered since" and "signed by this key" weaken with it.
  The version byte and the read-old-forever rule are the migration path for that day — nothing in v1
  pretends the math is eternal, only that the format can outlive any one algorithm.
- **Miners and nodes are not obliged to retain or serve historical payloads.** Nothing compels
  anyone to keep your data reachable. That is exactly why the reader is open and the format is
  documented: being the archive requires no permission, and the set of people who can be one is
  not us.
- **A claim proves control of a key and a domain at claim time, not project authorship.** No
  reader re-checks the domain afterward, so archive your evidence.
- **Submodules are separate repositories.** A repository's bundle contains its own history, not
  the histories of code it references. Mirroring a project's submodules is a separate act, and
  they are absent unless separately mirrored.
- **`reader.mjs` here is the only known implementation, and that is a real dependency on us.**
  The format is specified so it does not have to stay that way — §6 of [SPEC.md](SPEC.md) is
  normative and this reader was deliberately written from the spec alone as an audit of it — but
  until a second implementation exists, "anyone can rebuild it" means "anyone can run our code."
  Those are not the same claim and we are not going to blur them. If you want to close this,
  [IMPLEMENTERS.md](IMPLEMENTERS.md) is a guide to building one, including the traps that cost us
  time and the three published repositories to validate against.
- No shallow clones, no LFS-scale binaries, no issue tracker, no pull requests. This is the
  layer designed to stay reconstructable while an archival copy and a serving source exist, not
  the social layer. Bring your own social layer.

## The Monero Mirror — receipts

| What | Where |
|---|---|
| Spec repo (the format hosting itself) | repo_id `19Zb3LTpheqZ3XDxJyPEuDcCPyd1re9tWo` |
| Spec genesis ref (mined block 962425) | `e79469b288a74af081e92c8356b5aeffc577f52794fd62ce35b6bf6ea6c8d60c` |
| Monero mirror repo_id | `1DjP78YzJEB7eXKYQ8gyoS4PE2fyzkAHYv` |
| Monero genesis ref (mined block 962429) | `8a6bce9473a0f00e9908ebab35337f08a90a45379fa90c7d567876585d509e57` |
| Monero artifact manifest (mined block 962429) | `0d9b5db246b3b503cb7b0284c1a803a3e2f6e4f7c2c7904acb9e5eb7f1576929` |
| The 28 parts | mined blocks 962427–962429; txids resolvable from the artifact manifest |
| Bundle SHA-256 | `70462ee62fa951558514b8dee54fb265bb677f77ac0401d81c034221c08bb7ed` |
| Published | 2026-08-15, 30 transactions, ≈40.44M satoshis (≈ $6) |
| Independent reconstruction | 2026-08-15: rebuilt on a separate machine that had never held this code, via public endpoints only — all 269,600,118 bytes, sha256 byte-identical, `git clone` succeeded |

Reconstruct it yourself with the quickstart above, hash it, and compare. That's the entire trust
model: don't believe us, check.


## Repository updates — the format updated itself

A repository on chain is not frozen. On 2026-08-16 the specification became the first bgit
repository updated in place, publishing seq=2 of itself: a stale title (the document read
`DRAFT v1.1` while its body, review record, and shipped implementation were all v1.3) and a
clarification that `claim_how` is an optional invitation field that implementers must never
require — no reader consults it, and a claimed repository's maintainer refs deliberately omit
it, so a strict implementer would have rejected every maintainer ref this format produces.

| What | Where |
|---|---|
| Spec seq=2 ref manifest (mined block 962578) | `9a8bd1dac66545607f1da9345a150147f42f30740bcf4894a3adc30752694a76` |
| Spec seq=2 artifact manifest | `079d9d67745df613267018537205bc9457dc6aede72b0d31ba821019967edd05` |
| Spec seq=2 part | `56409ccba31ddfe0839dc98616c74737066fb7140138daa5f5840222826f9695` |
| Cost | 2,468 satoshis, three transactions |
| Reader behavior | walk the spec repo_id and the reader now serves seq=2; seq=1 remains on chain as history |

## Monero's submodules

Monero declares four submodules. Two are Monero's own code and are mirrored here as their own
claimable repositories; two are third-party libraries (Google's test framework and Tencent's
JSON parser) with their own homes and thousands of existing mirrors, and are deliberately not
mirrored — publishing them would have cost more than Monero's entire history and would not have
been Monero's code. **A repository's bundle contains its own history, not its dependencies'.**

| What | Where |
|---|---|
| RandomX (Monero's proof of work) repo_id | `1BEG5i16hSAHRMKUAX9pimQcXyYHKRDXDV` |
| RandomX genesis ref (mined block 962580) | `df1655dc764bf7750f48c824ac3d067bc8f8be36b36ea29e48188ad37a873b2c` |
| RandomX bundle SHA-256 | `1e3b446cd396b9b5c303aad9c055089297da6a5b323d678d9979a040e0a6a75e` |
| supercop (`monero-project/supercop`) repo_id | `12msgniRtLfxZyv12WqvgGouNsfU1L5v22` |
| supercop genesis ref (mined block 962580) | `b73964dea80ee790e89739d0f44dd25cbd60c7e0ecbf19e2997547c62d4ef311` |
| supercop bundle SHA-256 | `cc650d95aa3a754259ba9fbdf68ccaf3c493f747b05aa519f5ccd9443d25b6fb` |
| Published | 2026-08-16, six transactions, ≈608,000 satoshis total |
| Independent reconstruction | 2026-08-16: both read back from the chain through a third-party explorer, byte-identical to the SHA-256s above, and cloned with stock git (RandomX 534 commits, supercop 13) |

## Free rescue for evicted projects

If a code host has evicted, banned, or displaced your project, we publish your repository's
bundled history to Bitcoin at no charge — the write is funded from a treasury that exists for exactly that
(`1C4MhoG586zGeLPbQx6wFTJo2APtEdYKY2`). Email `indeliblebsv@gmail.com` with the canonical
repository URL. It publishes as an unsigned mirror, claimable by a maintainer who can publish the required
evidence on the project's canonical domain — see the claim mechanism above.


## License

MIT. The format belongs to everyone; a format with an owner is a platform wearing a costume.

Built by [Indelible](https://indelible.one/bgit) — Bitcoin persistence tooling for AI memory — with Claude (Anthropic) and Codex (OpenAI) as the design-and-review pair. The
coordination wire, the reviews, and this repository's own history are all, of course, on chain.

**[indelible.one/bgit](https://indelible.one/bgit)** is this project's home page: the live
receipts, the free-rescue intake for evicted projects, and the claim walkthrough for maintainers.
bgit grew out of Indelible's Bitcoin persistence tooling, and subscriptions to that product are
what fund the free rescues.
