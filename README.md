# bgit

**Publish git repositories to Bitcoin. Clone them back with stock git. Forever.**

No platform. No server. No company — including the one that wrote this — required to exist for
your code to survive.

---

## Why this exists

In August 2026, India ordered GitHub to delete repositories on three hours' notice. The same
season, Codeberg's new terms banned cryptocurrency projects from its platform — and, in the same
vote, code written mostly by AI, naming Claude and Codex. (This repository, built with both,
would be banned twice.) On a Monero community podcast,
someone asked the obvious question — *"can we just store it on BSV?"* — and nobody in the room
had an answer.

This is the answer. A git repository's complete history — every commit, branch, and tag — written
into Bitcoin SV transactions as plain data, reconstructible by anyone with a node, clonable with
the git you already have. Deleting it would require erasing a proof-of-work blockchain from every
machine on Earth that holds a copy. Hosting platforms have policies. Mined blocks don't.

The first repository ever published in this format is [the format's own specification](./SPEC.md).
The second is **the complete history of Monero** — 13,241 commits, 8,463 refs, 257 MB — published
as a labeled, claimable, unsigned mirror. Total cost: about six dollars, once.

## How it works, in one breath

The **publisher** packs a repo with `git bundle` (git's own portable format), slices it into
~10 MB chunks, and writes each chunk into a transaction. Two small signed records join them on
chain: an **artifact manifest** (the table of contents — every chunk's hash, plus the hash of the
whole) and a **ref manifest** (which state is current, signed by the repo key). The **reader**
reverses it from nothing but a transaction source: walk one address, collect the records, verify
every signature and every hash, refuse anything that doesn't check out — and hand you a `.bundle`
file that stock git clones. That's the whole trick. Git objects were always content-addressed and
immutable; they were waiting for a ledger with the same properties.

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

Any address-history + raw-transaction source works — the two shown are public examples, not
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

## The claim mechanism — why "unsigned mirror" matters

Anyone can mirror a repository they don't own; the format says so honestly. A mirror publishes
with `role: "unsigned-mirror"` and `claimable: true` — a label, visible forever, that says *the
project itself has not signed this.* The instructions for claiming are written **into the chain
records themselves**: a maintainer proves control of the project's canonical domain, publishes a
signed claim attestation on chain, and from that moment the repository's ref chain is theirs —
permanently, under a first-claim-per-key law with deterministic fork resolution. No permission
from us, no deadline, and it works even if every server we run is gone. Their code, their claim.

**Claiming is one command** (`claim.mjs`, in this repo):

```
node claim.mjs --repo-id <the repo address> --key-file maintainer-key.json \
  --domain yourproject.org --history-url '<tpl>' --tx-url '<tpl>'
```

Dry-run by default: it walks the repository with the real reader (complete-or-refuse), derives
the current tip itself — you cannot cite a stale one — and prints the exact
`/.well-known/bgit` file you must host at your canonical domain. With that file live, add
`--broadcast --funding <txid>:<vout>:<sats> --bridge <endpoint>`: the verb fetches and receipts
your evidence, re-checks it and re-walks the chain immediately before sending, and refuses —
by name — every situation that would waste your satoshis (already claimed, chain moved,
evidence missing, funding that isn't yours, ambiguous mined order). Every txid reports PENDING;
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

The reader has its own origin discipline: it was implemented by someone given *only the spec
text*, and every place they had to guess became a formal finding — [AUDIT.md](./AUDIT.md) lists
all 13, each dispositioned. Two became normative security law. If you implement your own reader
(please do), start there.

Run the vectors yourself: `npm test` — 22 pins covering signature vectors verified across two
independent implementations, every rejection class, fork races at every height, claim replay,
version-coexistence, and an end-to-end publish→reconstruct→clone loop.

## Designed for our own death

Every prior attempt at this died — six of them, 2014 to 2021, none of technical impossibility.
The closest ancestor put "GitHub on BSV" live in 2019; its bytes are still on chain today, but
the reader died with the company, so nobody can get them out. This design treats that graveyard
as a spec:

- **The reader is open and the format documented to genesis** — a stranger with a node rebuilds
  everything with zero contact with us.
- **The spec is published on chain in its own format** — the knowledge survives every website.
- **Version byte from byte zero, and a read-old-forever rule** — v2 may add, but a conforming
  reader reads v1 until the heat death of the universe. Format migrations that orphan old repos
  are the death this design exists to refuse.

## Honest limits, stated before you find them

- **This protects the artifact, not the author.** Writing costs money on a transparent chain. If
  you need anonymous authorship, git over Tor beats us and we won't pretend otherwise — but the
  writer and the author don't have to be the same person, and a throwaway key can mirror anything.
- **Permanence means erasure-resistance while one archival copy exists** — and anyone may run
  one. That is a different (and better) failure mode than a platform, where one policy decision
  deletes the canonical copy. It is not magic.
- **Signatures cannot prove freshness.** A frozen ref chain is undetectable from one source;
  read from several.
- No shallow clones, no LFS-scale binaries, no issue tracker, no pull requests. This is the
  layer that can't be killed, not the social layer. Bring your own social layer.

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

## License

MIT. The format belongs to everyone; a format with an owner is a platform wearing a costume.

Built by [Indelible](https://indelible.one) — sovereign, permanent AI memory and storage on BSV —
with Claude (Anthropic) and Codex (OpenAI) as the design-and-review pair. The coordination wire,
the reviews, and this repository's own history are all, of course, on chain.
