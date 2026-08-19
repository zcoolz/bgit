# Build a second reader

**We are asking someone to write an independent implementation of the bgit reader, and we will help you do it.**

This is not a courtesy invitation. It closes the most honest weakness this project has.

Right now, `reader.mjs` in this repository is the only known implementation. Every claim we make about permanence and censorship resistance is true only in the sense that *our* code can rebuild these repositories from the chain. If our reader is the only reader, then in practice you are still depending on us, and we have said so in public rather than waiting for someone to point it out.

A second implementation ends that. Not a fork of ours, and not a port. Something written from the spec by someone who owes us nothing, that reads the same bytes off the chain and produces the same repository.

The spec was written to make this possible. Section 6 of [SPEC.md](SPEC.md) is normative and self-contained, and the reader in this repo was deliberately written *from the spec alone* as an audit of it — that exercise found thirteen ambiguities, all of which are now closed in the text you'll be reading.

---

## What "done" looks like

You are done when your implementation, given only a repo address and public chain data, produces a git bundle whose SHA-256 matches ours exactly, and `git clone` works on it.

Not "close." Byte-identical. There is no partial credit and there shouldn't be.

**Why this is the test and not the vectors.** A reasonable question about any conformance suite is where its expected answers come from. If they were produced by the reference implementation, then a second reader passing them proves conformance to *that implementation*, not to the thing it is supposed to read — the suite quietly inherits the exact property this guide exists to avoid. So here is the honest hierarchy of evidence, weakest to strongest. Some of the positive vectors are our publisher building a record and our reader accepting it; to that exact extent they measure agreement with us, not independent correctness, and you should treat them as smoke, not proof. The rejection vectors are stronger, because they encode *spec rules* — a high-S signature, a duplicate JSON key, bytes after the signature — each refused because [SPEC.md](SPEC.md) says refuse, checkable against the spec text without ever running our code. But the real oracle is neither: it is `git clone`. A bundle that clones into real Monero, 13,241 commits and all, has passed against Monero's own tooling, which has no stake in agreeing with us. That is the one check in the whole loop that cannot wear a second hat, because Monero wrote it, not us. Anchor your confidence there.

**Start small.** These are the three published repositories in increasing order of difficulty:

| Target | Size | repo_id | Bundle SHA-256 |
|---|---|---|---|
| **supercop** (start here) | 13 commits | `12msgniRtLfxZyv12WqvgGouNsfU1L5v22` | `cc650d95aa3a754259ba9fbdf68ccaf3c493f747b05aa519f5ccd9443d25b6fb` |
| **RandomX** | 534 commits | `1BEG5i16hSAHRMKUAX9pimQcXyYHKRDXDV` | `1e3b446cd396b9b5c303aad9c055089297da6a5b323d678d9979a040e0a6a75e` |
| **Monero** | 13,241 commits, 257 MB, 28 parts | `1DjP78YzJEB7eXKYQ8gyoS4PE2fyzkAHYv` | `70462ee62fa951558514b8dee54fb265bb677f77ac0401d81c034221c08bb7ed` |

supercop is a single part and thirteen commits. If your reader handles it correctly you have already implemented the envelope parsing, the signature verification, the winner rule and the digest checks. Monero adds multi-part concatenation and scale, nothing conceptually new.

There is also a fourth target that is worth doing for its own sake: the **specification itself** is published on chain in its own format, at `19Zb3LTpheqZ3XDxJyPEuDcCPyd1re9tWo`. It is at sequence 2, because it has already updated itself in place. Reading the spec off the chain using a reader you built from the spec is a closed loop that we think is worth someone experiencing.

---

## What you need

**Read [SPEC.md](SPEC.md) §6 first.** It is the whole algorithm in six steps. Everything else in the spec is the detail those six steps depend on.

You need three things from the outside world, and the spec is deliberately agnostic about where they come from:

1. **Address history** — the transactions paying a given address, confirmed.
2. **Raw transactions** — the full hex, by txid.
3. **Ordering metadata** — enough to establish order *within* a block, not merely which block.

⚠️ **That third one is not optional and it is where a naive implementation breaks.** "Mined order" is insufficient on its own: two competing valid records can land in the same block, and a reader that has only block height cannot tell which one wins. It will silently pick one and believe it succeeded. Your implementation must either establish intra-block order from the source, or refuse with a typed ambiguity error and retry against a source that carries block data. Guessing here is how two readers disagree about which repository is real.

**Not every public API gives you all three.** Pick a source that supplies confirmed history, raw hex, *and* ordering metadata, and verify it does before you build on it. We do not want you using our infrastructure — the point of a second reader is that it does not depend on us. Our own independent reconstruction was done through third-party endpoints for exactly that reason, on a machine that had never held this code.

**Test vectors** are in [`bgit-vectors.test.mjs`](bgit-vectors.test.mjs). Thirty of them, covering every rejection class, fork races at every height, claim replay, and malformed input. You do not need to use our test harness — the vectors themselves are the value, and they encode the rules that are easy to get wrong. Read them by provenance, per the hierarchy above: the rejection vectors encode spec rules and are independently checkable against [SPEC.md](SPEC.md); the positive signature round-trips only prove agreement with our implementation; the end-to-end vector (publisher to reader to byte-identical bundle to `git clone`) is the one that anchors to Monero's own tooling. Passing all thirty is necessary and not sufficient — the clone is what counts.

---

## The traps that bit us

These are the mistakes we already made so you don't have to. Every one of them cost real time.

**`claim_how` must be ignored, not validated.** It is an optional invitation field. A strict implementation that rejects unknown fields would refuse every maintainer ref this format produces. We found this after publishing and pushed a spec update on chain to say so explicitly. If you are writing a strict parser, this is the field that will burn you.

**`OP_FALSE OP_RETURN`, not bare `OP_RETURN`.** The canonical BSV data output is `006a`, not `6a`. We verified this against a real node after getting it wrong.

**Strict DER, low-S, 33-byte compressed pubkeys.** Reject anything else. A signature that verifies under a permissive library but violates these rules is a non-conforming record, and treating it as valid is how two implementations disagree about which chain is real.

**Exactly one bgit output per transaction.** More than one and the entire transaction is non-conforming and must be ignored — not "take the first one."

**An empty walk proves nothing.** If your reader finds no records, that is not evidence the repository is absent. It may be your endpoint, your parsing, or ingest lag. Cross-check a second source before declaring anything missing, and say PENDING for anything unmined. Our own first clean-machine run refused honestly for exactly this reason — an index hadn't caught up yet — and that refusal was correct behaviour, not a bug.

**Block height field names differ between providers.** One returns `blockHeight`, another `blockheight`, another `height`. We shipped a confirmation check that read only one spelling and consequently reported NOT_SEEN for transactions that were demonstrably mined. It failed safe, which is why it took a while to notice.

**Complete or refuse, atomically.** Never hand back partial bytes. If any digest fails, refuse loudly and say which one, and do not leave a half-written artifact behind that a later run mistakes for a finished one. A reader that returns something plausible but wrong is worse than a reader that returns nothing.

**Same-block competitors are the one that will get you.** See the ordering note above. This is the failure mode most likely to survive your entire test suite and then produce a wrong answer in the wild, because the happy path never exercises it.

---

## If you are pointing an AI at this

A fair number of people will hand this to a coding assistant, and that is a legitimate way to build it. This section is written to be pasted directly into one.

> Build an independent implementation of the bgit v1 reader from the specification at `SPEC.md`, section 6, which is normative. Do not read or port `reader.mjs` — the entire point is that this implementation is independent, and consulting ours defeats it. Use `SPEC.md` and the test vectors in `bgit-vectors.test.mjs` only.
>
> The reader takes a Bitcoin SV address and produces a git bundle. It requires a data source that provides confirmed address history, raw transaction hex, and **intra-block ordering metadata** — block height alone is insufficient, because two competing valid records can occupy the same block, and the reader must either establish deterministic order within that block or return a typed ambiguity refusal rather than guessing. Not every public explorer API supplies all three; verify yours does before building on it. The reader must verify every signature over literal body bytes with strict DER and low-S, apply the winner rule including the genesis anchor and permanent fork resolution, verify the per-part SHA-256s, verify the whole-artifact SHA-256, and verify that the reconstructed ref digest matches both the artifact manifest and the winning ref manifest. On any mismatch it must refuse and say which check failed rather than returning bytes.
>
> Validate against `12msgniRtLfxZyv12WqvgGouNsfU1L5v22`, whose bundle must hash to `cc650d95aa3a754259ba9fbdf68ccaf3c493f747b05aa519f5ccd9443d25b6fb` and clone to a 13-commit repository. Then `1BEG5i16hSAHRMKUAX9pimQcXyYHKRDXDV` (534 commits). Then the full Monero mirror at `1DjP78YzJEB7eXKYQ8gyoS4PE2fyzkAHYv`, `70462ee62fa951558514b8dee54fb265bb677f77ac0401d81c034221c08bb7ed`, 269,600,118 bytes.
>
> **Reconstructing those three is the happy path and it is not sufficient.** Your implementation is not finished until it also demonstrably handles: dust-to-repo behaviour across every record type; JSON and size constraints enforced BEFORE any parse; authorization checked BEFORE fork comparison; two competing valid records in the SAME BLOCK, which must resolve by intra-block order or refuse with a typed ambiguity error rather than guessing; unknown record versions and types coexisting with known ones without influencing winner selection; and complete-or-refuse output that is atomic, leaving no partial artifact behind on failure. Most of the thirty test vectors are rejections for this reason — the failure cases are the specification.
>
> Read the "traps that bit us" section of `IMPLEMENTERS.md` before writing the parser. Those are known failure modes, not hypotheticals.

One caution, and it applies to humans equally. **A reader that produces the right hash for the wrong reason is not a working reader.** The failure cases matter more than the happy path, which is why the vectors are mostly rejections. Make your implementation refuse the malformed records before you celebrate it accepting the good ones.

---

## What happens when you finish

Tell us. `indeliblebsv@gmail.com`, or open an issue here.

We will run it, and we will say so publicly whether or not it agrees with ours.

**If your reader and ours disagree about any repository, that is a finding we want.** We will publish it, credited however you prefer and only with your consent — named, pseudonymous, or anonymous is entirely your call, and it would be a poor look for a project that talks this much about permanence to attach someone's name to something without asking.

And we will fix whichever side is proven wrong. That might be our reader, and it might equally be the spec text or your implementation — a disagreement identifies that something is wrong, not who. We are not going to promise in advance that we are the ones at fault, because that is not a real commitment, it is a posture.

A disagreement between two independent implementations is the most valuable bug report this project can receive, and the whole reason to want a second one.

If it agrees, then the honest limit in our README stops being a limit, and we will rewrite that section to say a second implementation exists and point at yours.

Either outcome is better than the situation today.

---

## The one thing we will not do

We will not pay you, and we are not going to pretend this is a bounty. This is an open format under MIT with a published spec and thirty test vectors, and the invitation is exactly what it looks like: we think the thing is worth checking, we cannot check it ourselves in the way that counts, and we would rather say so than let a single implementation quietly become the specification.

A format with one reader is a product. A format with two is a format.

*(That last line is a slogan, not a threshold. Two agreeing implementations are better evidence than one, and they do not by themselves establish permanence or censorship resistance — those rest on the data being mined and on someone choosing to keep a copy. The honest limits section of the [README](README.md) still stands unchanged.)*
