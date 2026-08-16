// bgit-vectors.test.mjs — the BGIT_WIRE_FORMAT_v1 §8 pin list as a node:test suite. No network.
//   node --test bgit/bgit-vectors.test.mjs     (or run the file directly)
//
// Pins, in §8 order: (1) cross-implementation signature vectors (exact v1.3 digest preimage
// "bgit1|" || VERSION || TYPE || body; publisher-signed records verified by the READER's
// independent path — two implementations, one truth) · (2) rejection vectors, each refused BY
// NAME · (3) fork-at-every-height winner selection incl. losing-descendant ineligibility +
// seq-gap rejection · (4) replayed CLAIM ATTESTATION (stale target_ref) · (5) unknown-v2-record
// coexistence · (6) adversarial multi-output → whole tx ignored · (7) THE E2E: publisher
// --local-out on a real git bundle → reader --local-in → byte-identical → git clone works.
// v1.3 round-two pins: (1c) a flipped TYPE byte fails the SIGNATURE itself · (9) unauthorized
// extensions rejected BEFORE fork selection · (10) claimant beats an unauthorized racer in any
// mined order · (11) same-block competing valid children → typed refusal, never source-order ·
// (12) missing dust rejected for ALL FOUR record types · (13) foreign-signed artifact manifest
// → refusal · (14) broadcast refuses fixture bytes that drift from the plan.
// Tests 1, 1c, 3, 7, 9 and 11 are BITE-PROVEN: a targeted break is applied to a COPY of the
// module (the break is verified to have landed — a red control that no-ops proves nothing) and
// the pinned regression is shown to actually occur, i.e. the green assertion is load-bearing.
import { test, after } from 'node:test'
import assert from 'node:assert'
import {
  mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync,
} from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
process.env.BGIT_SDK_DIR = process.env.BGIT_SDK_DIR || resolve(HERE, '..', 'mcp-server')

const pub = await import('./publisher.mjs')
const rdr = await import('./reader.mjs')
const sdk = pub.loadSdk()

const ROOT = mkdtempSync(join(tmpdir(), 'bgit-vectors-'))
after(() => { try { rmSync(ROOT, { recursive: true, force: true }) } catch {} })

// ---------------------------------------------------------------------------
// fixed vector key (deterministic) + fixed body — the §8.1 cross-run pin
// ---------------------------------------------------------------------------
const sha256 = (b) => createHash('sha256').update(b).digest()
const sha256hex = (b) => createHash('sha256').update(b).digest('hex')
const VECTOR_KEY = new sdk.PrivateKey(sha256hex(Buffer.from('bgit test vector key 1', 'ascii')), 16)
const VECTOR_BODY = Buffer.from('{"bgit":1,"x":2}', 'utf8')
// Pinned at authoring time from a live run (deterministic-k signing); any drift in the SDK's
// signing path or our preimage construction turns this red. REGENERATED for the v1.3 preimage
// SHA256("bgit1|" || 0x01 || 0x03(TYPE_REF) || body) — the v1.1 pin was 3045022100a099292e….
const PINNED_SIG_DER = '30440220313d5eb4ff8d5c1bdb23fd15ddbb2cc12d56c90ae64f861d1e9b2d5f4c07a7350220373a573fc53659947acfd8fbd6f5ab094847a402a86f7204291d984ea841eaad'
const PINNED_DIGEST = '17e7e70884b41040703d8f05f44466dc3fa15083941a8de1714558ce30f99d86'

const throwawayKey = sdk.PrivateKey.fromRandom()
const repoKey = throwawayKey
const repoAddr = repoKey.toAddress()
const repoScript = pub.p2pkhScript(repoAddr)

// ---------------------------------------------------------------------------
// fixture helpers
// ---------------------------------------------------------------------------
const txidOf = (raw) => Buffer.from(sha256(sha256(raw))).reverse().toString('hex')

// Hand-serialized minimal tx (reader never validates inputs — §6 walks outputs only).
function rawTx (outputs) {
  const parts = []
  const push = (b) => parts.push(Buffer.from(b))
  push([1, 0, 0, 0])                    // version
  push([1])                             // one input
  push(Buffer.alloc(32, 0x11))          // fake outpoint
  push([0, 0, 0, 0])                    // vout
  push([0])                             // empty unlocking script
  push([0xff, 0xff, 0xff, 0xff])        // sequence
  push(pub.encodeVarint(outputs.length))
  for (const o of outputs) {
    const v = Buffer.alloc(8); v.writeBigUInt64LE(BigInt(o.sats)); push(v)
    push(pub.encodeVarint(o.script.length)); push(o.script)
  }
  push([0, 0, 0, 0])                    // locktime
  return Buffer.concat(parts)
}

const FAKE64 = (n) => String(n).repeat(1).padStart(1, '0') && sha256hex(Buffer.from(`fake-${n}`))

function refTx ({ seq, prev, artifact, refsSha, role = 'unsigned-mirror', key = repoKey, paysRepo = true }) {
  const body = pub.buildRefBody({ repoId: repoAddr, seq, prev, artifactTxid: artifact, refsSha256: refsSha, role })
  const rec = pub.signedRecord(pub.TYPE_REF, body, key)
  const outs = [{ sats: 0, script: pub.recordScript(rec) }]
  if (paysRepo) outs.push({ sats: 10, script: repoScript })
  const raw = rawTx(outs)
  return { raw, txid: txidOf(raw) }
}

function claimTx ({ targetRef, maintainerKey, signerKey = maintainerKey, domain = 'getmonero.org', paysRepo = true }) {
  const body = Buffer.from(JSON.stringify({
    bgit: 1,
    repo_id: repoAddr,
    maintainer_pubkey: Buffer.from(maintainerKey.toPublicKey().encode(true)).toString('hex'),
    domain,
    role: 'maintainer',
    target_ref: targetRef,
  }), 'utf8')
  const rec = pub.signedRecord(pub.TYPE_CLAIM, body, signerKey)
  const outs = [{ sats: 0, script: pub.recordScript(rec) }]
  if (paysRepo) outs.push({ sats: 10, script: repoScript })
  const raw = rawTx(outs)
  return { raw, txid: txidOf(raw) }
}

const asWalk = (txs) => txs.map((t) => ({ raw: t.raw, mined: true }))
// height-aware walk entries (the v1.3 same-block law needs per-tx heights)
const asWalkH = (txs) => txs.map((t) => ({ raw: t.raw, mined: true, height: t.height ?? null }))

// git repo → bundle
let repoN = 0
function makeRepoBundle ({ commits = 3, filler = 0 } = {}) {
  const dir = join(ROOT, `repo-${++repoN}`)
  mkdirSync(dir, { recursive: true })
  const g = (args, cwd = dir) => {
    const r = spawnSync('git', args, { cwd, encoding: 'utf8' })
    assert.strictEqual(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`)
    return r.stdout
  }
  g(['init', '-q'])
  g(['config', 'user.email', 'bgit@test'])
  g(['config', 'user.name', 'bgit'])
  for (let i = 1; i <= commits; i++) {
    writeFileSync(join(dir, `f${i}.txt`), `commit ${i}\n${'x'.repeat(filler)}\n`)
    g(['add', '.'])
    g(['commit', '-qm', `commit ${i}`])
  }
  const bundlePath = join(ROOT, `repo-${repoN}.bundle`)
  g(['bundle', 'create', bundlePath, '--all'])
  const head = g(['rev-parse', 'HEAD']).trim()
  return { dir, bundlePath, head }
}

function runCli (script, args, opts = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8',
    env: { ...process.env, BGIT_SDK_DIR: process.env.BGIT_SDK_DIR },
    maxBuffer: 1024 * 1024 * 1024,
    ...opts,
  })
}

// ---------- broken-copy factory (red-control law: verify the break landed) ----------
let brokenN = 0
function makeBrokenCopy (modulePath, target, replacement) {
  const src = readFileSync(modulePath, 'utf8')
  assert.ok(src.includes(target), `bite target present in module source: ${JSON.stringify(target.slice(0, 70))}`)
  assert.strictEqual(src.indexOf(target), src.lastIndexOf(target), 'bite target is unique in the module source')
  let broken = src.replace(target, replacement)
  assert.notStrictEqual(broken, src, 'the break actually landed (a silent no-op replace proves nothing)')
  // the copy lives in tmp — repoint relative sibling imports at the REAL modules
  broken = broken.replace(/from '\.\/(reader|publisher|claim)\.mjs'/g, (_, m) => `from '${pathToFileURL(join(HERE, `${m}.mjs`)).href}'`)
  const out = join(ROOT, `broken-${++brokenN}-${modulePath.endsWith('reader.mjs') ? 'reader' : 'publisher'}.mjs`)
  writeFileSync(out, broken)
  return out
}

// envelope surgery helpers (test 2). v1.3 preimage by default; `legacyPreimage` signs the OLD
// v1.1 body-only preimage (used to demonstrate the type-confusion attack the v1.3 change kills).
function craftEnvelope ({ body, key = VECTOR_KEY, sigDer = null, pubkeyBytes = null, trailing = null, version = 0x01, type = pub.TYPE_REF, legacyPreimage = false }) {
  const msg = legacyPreimage
    ? Buffer.concat([Buffer.from('bgit1|', 'ascii'), body])
    : Buffer.concat([Buffer.from('bgit1|', 'ascii'), Buffer.from([version, type]), body])
  const der = sigDer ?? Buffer.from(key.sign(Array.from(msg)).toDER())
  const pk = pubkeyBytes ?? Buffer.from(key.toPublicKey().encode(true))
  const parts = [pub.encodeVarint(body.length), body, Buffer.from([pk.length]), pk, pub.encodeVarint(der.length), der]
  if (trailing) parts.push(trailing)
  return Buffer.concat(parts)
}
const CURVE_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
function derDecode (der) {
  let o = 2
  const readInt = () => { const len = der[o + 1]; const b = der.subarray(o + 2, o + 2 + len); o += 2 + len; return BigInt('0x' + Buffer.from(b).toString('hex')) }
  return { r: readInt(), s: readInt() }
}
function derEncode (r, s, { padR = false } = {}) {
  const intBytes = (v, pad) => {
    let hex = v.toString(16); if (hex.length % 2) hex = '0' + hex
    let b = Buffer.from(hex, 'hex')
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b])
    if (pad) b = Buffer.concat([Buffer.from([0]), b]) // deliberately non-minimal
    return b
  }
  const rb = intBytes(r, padR); const sb = intBytes(s, false)
  return Buffer.concat([Buffer.from([0x30, 4 + rb.length + sb.length, 0x02, rb.length]), rb, Buffer.from([0x02, sb.length]), sb])
}

// ===========================================================================
// §8.1 — signature vectors (two implementations, one truth) + BITE
// ===========================================================================
test('1. signature vectors: exact v1.3 preimage, cross-implementation verify, pinned DER', () => {
  // exact digest preimage (v1.3): "bgit1|" (6 ASCII bytes) || VERSION_BYTE || TYPE_BYTE || body
  const preimage = Buffer.concat([Buffer.from('bgit1|', 'ascii'), Buffer.from([0x01, pub.TYPE_REF]), VECTOR_BODY])
  assert.strictEqual(pub.SIGN_PREFIX, 'bgit1|')
  assert.strictEqual(preimage.length, 6 + 2 + VECTOR_BODY.length)
  assert.strictEqual(sha256hex(preimage), PINNED_DIGEST, 'pinned digest over the exact preimage bytes')

  // deterministic signing + the pinned literal
  const s1 = Buffer.from(VECTOR_KEY.sign(Array.from(preimage)).toDER()).toString('hex')
  const s2 = Buffer.from(VECTOR_KEY.sign(Array.from(preimage)).toDER()).toString('hex')
  assert.strictEqual(s1, s2, 'signing is deterministic (pin would flake otherwise)')
  assert.strictEqual(s1, PINNED_SIG_DER, 'pinned signature vector (fixed key + fixed body bytes + bound header bytes)')

  // publisher-built record verifies in the READER's independent path
  const record = pub.signedRecord(pub.TYPE_REF, VECTOR_BODY, VECTOR_KEY)
  assert.strictEqual(record[0], 0x01); assert.strictEqual(record[1], pub.TYPE_REF)
  const v = rdr.validateSignedRecord(record.subarray(2), { version: record[0], type: record[1] })
  assert.strictEqual(v.ok, true, `reader verifies publisher record: ${v.code || ''}`)
  assert.ok(v.body.equals(VECTOR_BODY), 'reader extracted the LITERAL body bytes')
  assert.strictEqual(v.sig, PINNED_SIG_DER)

  // the header bytes are IN the preimage: the same sig over the v1.1 preimage (prefix||body)
  // must NOT verify, and neither must sha256(body) alone
  for (const [what, buf] of [['v1.1 preimage (no version/type bytes)', Buffer.concat([Buffer.from('bgit1|', 'ascii'), VECTOR_BODY])], ['bare body', VECTOR_BODY]]) {
    const ok = sdk.ECDSA.verify(
      new sdk.BigNumber(sha256hex(buf), 16),
      sdk.Signature.fromDER(Array.from(Buffer.from(PINNED_SIG_DER, 'hex'))),
      VECTOR_KEY.toPublicKey(),
    )
    assert.strictEqual(ok, false, `${what} must not verify — the digest differs`)
  }
})

test('1b. BITE: publisher signing with a wrong prefix is REFUSED by the reader', async () => {
  const brokenPath = makeBrokenCopy(join(HERE, 'publisher.mjs'), "const SIGN_PREFIX = 'bgit1|'", "const SIGN_PREFIX = 'bgit2|'")
  const broken = await import(pathToFileURL(brokenPath).href)
  const record = broken.signedRecord(broken.TYPE_REF, VECTOR_BODY, VECTOR_KEY)
  const v = rdr.validateSignedRecord(record.subarray(2), { version: record[0], type: record[1] })
  assert.strictEqual(v.ok, false, 'RED: reader must refuse a record signed under a different domain prefix')
  assert.strictEqual(v.code, 'SIG_INVALID')
})

test('1c. PIN (v1.3 A2): a flipped TYPE byte fails the SIGNATURE itself + BITE: the v1.1 preimage accepted it', async () => {
  // intact reader: the type byte is cryptographically bound — reinterpretation dies in the
  // signature, BEFORE any typed-body validation could be consulted
  const record = pub.signedRecord(pub.TYPE_REF, VECTOR_BODY, VECTOR_KEY)
  const flipped = Buffer.from(record); flipped[1] = pub.TYPE_CLAIM
  const v = rdr.validateSignedRecord(flipped.subarray(2), { version: flipped[0], type: flipped[1] })
  assert.strictEqual(v.ok, false, 'a signed REF re-labelled as CLAIM must fail')
  assert.strictEqual(v.code, 'SIG_INVALID')
  // and the same envelope with its TRUE type still verifies (the flip is what broke it)
  const vTrue = rdr.validateSignedRecord(record.subarray(2), { version: record[0], type: record[1] })
  assert.strictEqual(vTrue.ok, true)

  // BITE: a reader on the v1.1 body-only preimage accepts the SAME envelope under BOTH types —
  // the exact type-confusion the v1.3 preimage kills. The break is a real regression to v1.1.
  const brokenPath = makeBrokenCopy(join(HERE, 'reader.mjs'),
    'Buffer.concat([SIGN_PREFIX, Buffer.from([version, type]), body])',
    'Buffer.concat([SIGN_PREFIX, body])')
  const broken = await import(pathToFileURL(brokenPath).href)
  const legacyEnv = craftEnvelope({ body: VECTOR_BODY, legacyPreimage: true })
  const asRef = broken.validateSignedRecord(legacyEnv, { version: 0x01, type: pub.TYPE_REF })
  const asClaim = broken.validateSignedRecord(legacyEnv, { version: 0x01, type: pub.TYPE_CLAIM })
  assert.strictEqual(asRef.ok, true, 'RED: the v1.1 reader verifies the legacy envelope as a REF')
  assert.strictEqual(asClaim.ok, true, 'RED: …and the SAME bytes as a CLAIM — one signature, two meanings')
  // the intact reader refuses the legacy-signed envelope entirely (sign-what-you-ship, one preimage)
  const intact = rdr.validateSignedRecord(legacyEnv, { version: 0x01, type: pub.TYPE_REF })
  assert.strictEqual(intact.ok, false)
  assert.strictEqual(intact.code, 'SIG_INVALID')
})

// ===========================================================================
// §8.2 — rejection vectors, each refused BY NAME
// ===========================================================================
test('2. rejection vectors', () => {
  const expect = (env, code, what) => {
    const v = rdr.validateSignedRecord(env, { version: 0x01, type: pub.TYPE_REF })
    assert.strictEqual(v.ok, false, `${what} must be refused`)
    assert.strictEqual(v.code, code, `${what} → ${code} (got ${v.code}: ${v.detail || ''})`)
  }
  expect(craftEnvelope({ body: Buffer.from('{"bgit":1,"a":1,"a":2}') }), 'DUPLICATE_KEY', 'duplicate top-level key')
  expect(craftEnvelope({ body: Buffer.from('{"bgit":1,"o":{"x":1,"x":2}}') }), 'DUPLICATE_KEY', 'duplicate nested key')
  expect(craftEnvelope({ body: Buffer.from('{"a\\u0062":1,"ab":2}') }), 'DUPLICATE_KEY', 'duplicate key via unicode escape')
  expect(craftEnvelope({ body: Buffer.from('{"n":1.5}') }), 'NON_INTEGER_NUMBER', 'float')
  expect(craftEnvelope({ body: Buffer.from('{"n":1e3}') }), 'NON_INTEGER_NUMBER', 'exponent')
  expect(craftEnvelope({ body: Buffer.from('{"n":9007199254740992}') }), 'INTEGER_OUT_OF_RANGE', '2^53 (first non-exact integer)')
  expect(craftEnvelope({ body: Buffer.alloc(rdr.MAX_SIGNED_BODY + 1, 0x61) }), 'OVERSIZE_BODY', 'oversize body (bound enforced BEFORE JSON parse)')
  expect(craftEnvelope({ body: Buffer.from([0x7b, 0xff, 0x7d]) }), 'INVALID_UTF8', 'invalid UTF-8')
  expect(craftEnvelope({ body: VECTOR_BODY, trailing: Buffer.from([0xde, 0xad]) }), 'TRAILING_BYTES', 'bytes after the signature')

  // signature strictness surgery
  const goodDer = Buffer.from(PINNED_SIG_DER, 'hex')
  const { r, s } = derDecode(goodDer)
  expect(craftEnvelope({ body: VECTOR_BODY, sigDer: derEncode(r, CURVE_N - s) }), 'HIGH_S', 'high-S (still a valid ECDSA pair — must be refused on strictness alone)')
  expect(craftEnvelope({ body: VECTOR_BODY, sigDer: derEncode(r, s, { padR: true }) }), 'NON_STRICT_DER', 'non-minimal DER integer padding')

  // pubkey shape
  const uncompressed = Buffer.from(VECTOR_KEY.toPublicKey().encode(false))
  assert.strictEqual(uncompressed.length, 65)
  expect(craftEnvelope({ body: VECTOR_BODY, pubkeyBytes: uncompressed }), 'PUBKEY_NOT_COMPRESSED', 'uncompressed 65-byte pubkey')
  const badPrefix = Buffer.from(VECTOR_KEY.toPublicKey().encode(true)); badPrefix[0] = 0x04
  expect(craftEnvelope({ body: VECTOR_BODY, pubkeyBytes: badPrefix }), 'PUBKEY_NOT_COMPRESSED', '33 bytes with prefix 0x04')

  // control: the untouched envelope passes (the expectations above are not vacuous)
  const ok = rdr.validateSignedRecord(craftEnvelope({ body: VECTOR_BODY }), { version: 0x01, type: pub.TYPE_REF })
  assert.strictEqual(ok.ok, true, 'control: a clean envelope verifies')
})

// ===========================================================================
// §8.3 — fork-at-every-height winner selection + BITE
// ===========================================================================
function buildForkFixture (order = 'B-first') {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1, role: 'genesis' })
  const B = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'fork-B' })
  const C = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'fork-C' })
  const D = refTx({ seq: 3, prev: C.txid, artifact: A1, refsSha: D1, role: 'child-of-C' })
  const E = refTx({ seq: 3, prev: B.txid, artifact: A1, refsSha: D1, role: 'child-of-B' })
  const txs = order === 'B-first' ? [G, B, C, D, E] : [G, C, B, D, E]
  return { G, B, C, D, E, walk: asWalk(txs) }
}

test('3. winner rule: forks at every height, losing-descendant ineligibility, seq gaps, later genesis void', () => {
  // B mined before C → B wins seq 2; D (child of losing C) permanently ineligible even though
  // it was mined BEFORE E; E extends the surviving chain.
  const f = buildForkFixture('B-first')
  const col = rdr.collectRecords(f.walk, repoAddr)
  assert.strictEqual(col.refs.length, 5)
  const res = rdr.resolveChain(col.refs)
  assert.strictEqual(res.tip.txid, f.E.txid, 'tip = E (child of the first-mined fork winner)')
  assert.deepStrictEqual(res.chain.map((r) => r.txid), [f.G.txid, f.B.txid, f.E.txid])
  assert.deepStrictEqual(res.report.forkLosers.map((x) => x.txid), [f.C.txid])
  assert.deepStrictEqual(res.report.ineligibleDescendants, [f.D.txid], 'D is a descendant of the losing child — ineligible forever')

  // mined order flipped → C wins, D survives, E is the ineligible one
  const g = buildForkFixture('C-first')
  const res2 = rdr.resolveChain(rdr.collectRecords(g.walk, repoAddr).refs)
  assert.strictEqual(res2.tip.txid, g.D.txid, 'first-mined is a MINED-ORDER fact, not a tie-break preference')
  assert.deepStrictEqual(res2.report.ineligibleDescendants, [g.E.txid])

  // seq gap: a child citing the tip with seq+2 is rejected, tip unchanged
  const gap = refTx({ seq: 5, prev: f.E.txid, artifact: FAKE64(1), refsSha: FAKE64(2), role: 'gap' })
  const res3 = rdr.resolveChain(rdr.collectRecords([...f.walk, ...asWalk([gap])], repoAddr).refs)
  assert.strictEqual(res3.tip.txid, f.E.txid)
  assert.deepStrictEqual(res3.report.seqGaps.map((x) => x.txid), [gap.txid])

  // later "genesis" is void (§3.1) — and so are its descendants
  const G2 = refTx({ seq: 1, prev: null, artifact: FAKE64(3), refsSha: FAKE64(4), role: 'late-genesis' })
  const G2kid = refTx({ seq: 2, prev: G2.txid, artifact: FAKE64(3), refsSha: FAKE64(4), role: 'late-genesis-kid' })
  const res4 = rdr.resolveChain(rdr.collectRecords([...f.walk, ...asWalk([G2, G2kid])], repoAddr).refs)
  assert.strictEqual(res4.tip.txid, f.E.txid)
  assert.deepStrictEqual(res4.report.voidLaterGenesis, [G2.txid])
  // D (child of the losing fork C, still in this walk) AND the late-genesis kid are both ineligible.
  assert.deepStrictEqual(res4.report.ineligibleDescendants, [f.D.txid, G2kid.txid])
})

test('3b. BITE: a reader that walks in the wrong order resolves a different chain (mined order is the clock)', async () => {
  const brokenPath = makeBrokenCopy(join(HERE, 'reader.mjs'), '.sort((a, b) => a.minedIdx - b.minedIdx)', '.sort((a, b) => b.minedIdx - a.minedIdx)')
  const broken = await import(pathToFileURL(brokenPath).href)
  const f = buildForkFixture('B-first')
  const intact = rdr.resolveChain(rdr.collectRecords(f.walk, repoAddr).refs)
  const bent = broken.resolveChain(broken.collectRecords(f.walk, repoAddr).refs)
  assert.strictEqual(intact.tip.txid, f.E.txid)
  assert.strictEqual(bent.tip.txid, f.G.txid, 'RED: a reverse-order walk strands every child pre-genesis — the winner depends on the mined-order law')
  assert.notStrictEqual(bent.tip.txid, intact.tip.txid)
  // and test 3's green first-vs-second-mined pair (B-first ⇒ E wins, C-first ⇒ D wins) is the
  // direct proof that FIRST-mined — not last — is what the intact walk selects.
})

// ===========================================================================
// §8.4 — replayed CLAIM ATTESTATION (stale target_ref)
// ===========================================================================
test('4. claim attestation: stale target_ref rejected, current tip accepted, wrong signer rejected', () => {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 })
  const B = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'tip' })
  const maintainer = new sdk.PrivateKey(sha256hex(Buffer.from('bgit maintainer key', 'ascii')), 16)
  const stale = claimTx({ targetRef: G.txid, maintainerKey: maintainer })   // replayed: tip moved to B
  const fresh = claimTx({ targetRef: B.txid, maintainerKey: maintainer })
  const forged = claimTx({ targetRef: B.txid, maintainerKey: maintainer, signerKey: repoKey }) // envelope key ≠ maintainer_pubkey

  const col = rdr.collectRecords(asWalk([G, B, stale, fresh, forged]), repoAddr)
  assert.strictEqual(col.claims.length, 2, 'the forged claim never reaches evaluation')
  assert.ok(col.rejected.some((r) => r.txid === forged.txid && r.code === 'CLAIM_KEY_MISMATCH'), 'claim signed by a key other than maintainer_pubkey → CLAIM_KEY_MISMATCH')

  // v1.3: claims are evaluated INSIDE the winner-rule walk (their validity is temporal)
  const { claimResults: results } = rdr.resolveChain(col.refs, col.claims)
  const staleR = results.find((r) => r.txid === stale.txid)
  const freshR = results.find((r) => r.txid === fresh.txid)
  assert.strictEqual(staleR.status, 'REJECTED')
  assert.strictEqual(staleR.code, 'STALE_TARGET_REF', 're-presenting an old attestation against a newer tip binds nothing')
  assert.strictEqual(freshR.status, 'ACCEPTED')
  assert.strictEqual(freshR.target_ref, B.txid)
})

// ===========================================================================
// full-path fixtures for §8.5/§8.6/§8.7 — a REAL publisher run on a REAL bundle
// ===========================================================================
let fixtureCache = null
function realFixture () {
  if (fixtureCache) return fixtureCache
  const repo = makeRepoBundle({ commits: 4, filler: 600 })
  const outDir = join(ROOT, 'fixture-real')
  const r = runCli(join(HERE, 'publisher.mjs'), [
    '--bundle', repo.bundlePath, '--repo', 'test/real', '--key', repoKey.toWif(),
    '--part-bytes', '700', '--local-out', outDir,
  ])
  assert.strictEqual(r.status, 0, `publisher: ${r.stderr}`)
  const chain = JSON.parse(readFileSync(join(outDir, 'chain.json'), 'utf8'))
  assert.ok(chain.plan.parts >= 2, `multi-part fixture (got ${chain.plan.parts} parts)`)
  fixtureCache = { repo, outDir, chain, bundleSha: sha256hex(readFileSync(repo.bundlePath)) }
  return fixtureCache
}
async function readFixture (dir, out, extra = {}) {
  return rdr.runReader({ repoId: repoAddr, localIn: dir, out, quiet: true, ...extra })
}
function cloneChainDir (srcDir, destDir) {
  mkdirSync(destDir, { recursive: true })
  const chain = JSON.parse(readFileSync(join(srcDir, 'chain.json'), 'utf8'))
  for (const e of chain.entries) writeFileSync(join(destDir, e.file), readFileSync(join(srcDir, e.file)))
  return chain
}

// ===========================================================================
// §8.5 — unknown-v2-record coexistence
// ===========================================================================
test('5. v2/unknown records coexist: skipped, reported, and never influence the winner', async () => {
  const fx = realFixture()
  const dir = join(ROOT, 'fixture-salted')
  const chain = cloneChainDir(fx.outDir, dir)

  // version 0x02 record (whole-record version bump) + v1 reserved type 0x07 record
  const v2rec = Buffer.concat([Buffer.from([0x02, 0x03]), Buffer.from('a-v2-record-from-the-future')])
  const t7rec = Buffer.concat([Buffer.from([0x01, 0x07]), Buffer.from('a-reserved-type-record')])
  const salt1 = rawTx([{ sats: 0, script: pub.recordScript(v2rec) }, { sats: 10, script: repoScript }])
  const salt2 = rawTx([{ sats: 0, script: pub.recordScript(t7rec) }, { sats: 10, script: repoScript }])
  writeFileSync(join(dir, 'salt1.hex'), salt1.toString('hex'))
  writeFileSync(join(dir, 'salt2.hex'), salt2.toString('hex'))
  // salt them into the MIDDLE of the mined order
  chain.entries.splice(1, 0, { txid: txidOf(salt1), file: 'salt1.hex', role: 'salt-v2' })
  chain.entries.splice(3, 0, { txid: txidOf(salt2), file: 'salt2.hex', role: 'salt-t7' })
  writeFileSync(join(dir, 'chain.json'), JSON.stringify(chain, null, 2))

  const out = join(ROOT, 'out-salted.bundle')
  const res = await readFixture(dir, out)
  assert.strictEqual(res.ok, true)
  assert.strictEqual(sha256hex(readFileSync(out)), fx.bundleSha, 'v1 path resolves byte-identical with future records present')
  assert.strictEqual(res.skipped.length, 2, 'both unknown records reported as skipped')
  assert.deepStrictEqual(new Set(res.skipped.map((s) => s.code)), new Set(['UNKNOWN_VERSION', 'UNKNOWN_TYPE']))
  assert.strictEqual(res.tip.txid, fx.chain.plan.ref_manifest_txid, 'winner selection untouched by skipped records')
})

// ===========================================================================
// §8.6 — adversarial multi-output: the whole tx is ignored
// ===========================================================================
test('6. a tx with two bgit outputs is ignored entirely — even when one carries a valid seq=2 ref', async () => {
  const fx = realFixture()
  const dir = join(ROOT, 'fixture-multiout')
  const chain = cloneChainDir(fx.outDir, dir)

  // a VALID, correctly signed seq=2 REF MANIFEST continuing the real chain — but smuggled in a
  // tx that carries a second bgit output. §1: the whole transaction is non-conforming.
  const body = pub.buildRefBody({
    repoId: repoAddr, seq: 2, prev: fx.chain.plan.ref_manifest_txid,
    artifactTxid: fx.chain.plan.artifact_manifest_txid, refsSha256: fx.chain.plan.bundle_refs_sha256,
    role: 'smuggled',
  })
  const rec = pub.signedRecord(pub.TYPE_REF, body, repoKey)
  const junk = Buffer.concat([Buffer.from([0x01, 0x03]), Buffer.from('second-output-junk')])
  const evil = rawTx([
    { sats: 0, script: pub.recordScript(rec) },
    { sats: 0, script: pub.recordScript(junk) },
    { sats: 10, script: repoScript },
  ])
  writeFileSync(join(dir, 'evil.hex'), evil.toString('hex'))
  chain.entries.push({ txid: txidOf(evil), file: 'evil.hex', role: 'evil-multiout' })
  writeFileSync(join(dir, 'chain.json'), JSON.stringify(chain, null, 2))

  const out = join(ROOT, 'out-multiout.bundle')
  const res = await readFixture(dir, out)
  assert.strictEqual(res.ok, true)
  assert.strictEqual(res.tip.seq, 1, 'the smuggled seq=2 never entered winner selection')
  assert.strictEqual(res.tip.txid, fx.chain.plan.ref_manifest_txid)
  assert.strictEqual(res.ignoredMultiOutput.length, 1)
  assert.strictEqual(res.ignoredMultiOutput[0].txid, txidOf(evil))
  assert.strictEqual(sha256hex(readFileSync(out)), fx.bundleSha)

  // control: the SAME record in a clean single-output tx DOES advance the tip to seq 2
  const dir2 = join(ROOT, 'fixture-multiout-control')
  const chain2 = cloneChainDir(fx.outDir, dir2)
  const clean = rawTx([{ sats: 0, script: pub.recordScript(rec) }, { sats: 10, script: repoScript }])
  writeFileSync(join(dir2, 'clean.hex'), clean.toString('hex'))
  chain2.entries.push({ txid: txidOf(clean), file: 'clean.hex', role: 'clean-seq2' })
  writeFileSync(join(dir2, 'chain.json'), JSON.stringify(chain2, null, 2))
  const res2 = await readFixture(dir2, join(ROOT, 'out-multiout-control.bundle'))
  assert.strictEqual(res2.tip.seq, 2, 'control: single-output form of the same record is honored (the ignore is about the tx shape, not the record)')
})

// ===========================================================================
// §8.7 — THE E2E through the real CLIs + BITE
// ===========================================================================
test('7. e2e: publisher --local-out → reader --local-in → byte-identical → git clone works', () => {
  const fx = realFixture()
  const out = join(ROOT, 'out-e2e.bundle')
  const r = runCli(join(HERE, 'reader.mjs'), ['--repo-id', repoAddr, '--local-in', fx.outDir, '--out', out])
  assert.strictEqual(r.status, 0, `reader CLI: ${r.stderr}`)
  assert.ok(r.stdout.includes('VERIFIED'), 'reader prints its verification report')
  assert.strictEqual(sha256hex(readFileSync(out)), fx.bundleSha, 'reconstructed bundle is byte-identical to the original')

  // stock git accepts the reconstruction
  const cloneDir = join(ROOT, 'clone-e2e')
  const c = spawnSync('git', ['clone', '-q', out, cloneDir], { encoding: 'utf8' })
  assert.strictEqual(c.status, 0, `git clone from reconstructed bundle: ${c.stderr}`)
  const head = spawnSync('git', ['-C', cloneDir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim()
  assert.strictEqual(head, fx.repo.head, 'cloned HEAD equals the original repo HEAD')

  // plan report sanity
  assert.ok(fx.chain.plan.total_sats_needed > 0)
  assert.strictEqual(fx.chain.plan.tx_count, fx.chain.plan.parts + 2)
})

test('7b. BITE: a publisher that corrupts one part byte is caught by the reader (PART_SHA_MISMATCH)', () => {
  const brokenPath = makeBrokenCopy(
    join(HERE, 'publisher.mjs'),
    'const record = Buffer.concat([Buffer.from([FORMAT_VERSION, TYPE_PART]), chunk])',
    'const record = Buffer.concat([Buffer.from([FORMAT_VERSION, TYPE_PART]), (() => { const c = Buffer.from(chunk); c[0] ^= 0xff; return c })()])',
  )
  const repo = makeRepoBundle({ commits: 3, filler: 400 })
  const dir = join(ROOT, 'fixture-bitten')
  const p = runCli(brokenPath, ['--bundle', repo.bundlePath, '--repo', 'test/bitten', '--key', repoKey.toWif(), '--part-bytes', '700', '--local-out', dir])
  assert.strictEqual(p.status, 0, `broken publisher still runs green (it cannot know): ${p.stderr}`)
  const r = runCli(join(HERE, 'reader.mjs'), ['--repo-id', repoAddr, '--local-in', dir, '--out', join(ROOT, 'out-bitten.bundle')])
  assert.notStrictEqual(r.status, 0, 'RED: the reader must refuse the corrupted publication')
  assert.ok(r.stderr.includes('PART_SHA_MISMATCH'), `refusal names the check: ${r.stderr.slice(0, 300)}`)
  assert.ok(!existsSync(join(ROOT, 'out-bitten.bundle')), 'no partial artifact is left behind')
})

test('7c. publisher refuses a bundle that fails git bundle verify', () => {
  const junkPath = join(ROOT, 'not-a.bundle')
  writeFileSync(junkPath, 'this is not a git bundle\n')
  const r = runCli(join(HERE, 'publisher.mjs'), ['--bundle', junkPath, '--repo', 'x/y', '--key', repoKey.toWif()])
  assert.strictEqual(r.status, 2)
  assert.ok(r.stderr.includes('REFUSED_BUNDLE_VERIFY'), r.stderr.slice(0, 200))
})

test('8. reader refuses a walk with no valid genesis for the claimed repo-id', async () => {
  const fx = realFixture()
  const otherAddr = sdk.PrivateKey.fromRandom().toAddress()
  await assert.rejects(
    () => rdr.runReader({ repoId: otherAddr, localIn: fx.outDir, out: join(ROOT, 'nope.bundle'), quiet: true }),
    (e) => e.bgitCode === 'NO_GENESIS',
    'every record carries the wrong repo_id → rejected → NO_GENESIS refusal, not a fabricated read',
  )
})

// ===========================================================================
// v1.3 round-two pins
// ===========================================================================
test('9. PIN (A1): an unauthorized extension is rejected BEFORE fork selection — attacker mined first still loses + BITE', async () => {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const X = sdk.PrivateKey.fromRandom() // the squatter: valid signatures, no authority
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 })
  const AX = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'attacker-first', key: X })
  const AX3 = refTx({ seq: 3, prev: AX.txid, artifact: A1, refsSha: D1, role: 'attacker-child', key: X })
  const H = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'authorized-second' })
  const walk = asWalk([G, AX, AX3, H]) // attacker WINS the mined-order race
  const col = rdr.collectRecords(walk, repoAddr)
  assert.strictEqual(col.refs.length, 4, 'the attacker records are validly SIGNED — only the authorization law rejects them')
  const res = rdr.resolveChain(col.refs)
  assert.strictEqual(res.tip.txid, H.txid, 'the authorized child wins although mined second')
  assert.deepStrictEqual(res.report.unauthorized.map((u) => u.txid), [AX.txid])
  assert.deepStrictEqual(res.report.ineligibleDescendants, [AX3.txid], 'the attacker lineage is dead, not merely outranked')
  assert.strictEqual(res.report.forkLosers.length, 0, 'no fork ever existed — the attacker was invalid BEFORE fork comparison')

  // BITE: remove the authorization gate → the first-mined attacker chain wins the race
  const brokenPath = makeBrokenCopy(join(HERE, 'reader.mjs'),
    'const isAuthorized = (ev) => authState.has(ev.pubkey.toLowerCase())',
    'const isAuthorized = (ev) => true')
  const broken = await import(pathToFileURL(brokenPath).href)
  const bent = broken.resolveChain(broken.collectRecords(walk, repoAddr).refs)
  assert.strictEqual(bent.tip.txid, AX3.txid, 'RED: without the A1 law the squatter chain wins — the green assertion is load-bearing')
  assert.notStrictEqual(bent.tip.txid, res.tip.txid)
})

test('10. PIN: a valid claimant beats an unauthorized racer in ANY mined order; a late claim never retro-authorizes', () => {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const M = new sdk.PrivateKey(sha256hex(Buffer.from('bgit claimant key', 'ascii')), 16)
  const X = sdk.PrivateKey.fromRandom()
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 })
  const claim = claimTx({ targetRef: G.txid, maintainerKey: M })
  const AX = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'racer', key: X })
  const MR = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'maintainer', key: M })
  for (const [name, order] of [['attacker first', [G, claim, AX, MR]], ['claimant first', [G, claim, MR, AX]]]) {
    const col = rdr.collectRecords(asWalk(order), repoAddr)
    const res = rdr.resolveChain(col.refs, col.claims)
    assert.strictEqual(res.claimResults[0].status, 'ACCEPTED', `${name}: claim against the then-current tip is accepted`)
    assert.strictEqual(res.tip.txid, MR.txid, `${name}: the claimant's manifest is the tip regardless of mined order`)
    assert.deepStrictEqual(res.report.unauthorized.map((u) => u.txid), [AX.txid], `${name}: the racer is unauthorized either way`)
  }
  // without the claim, the maintainer key is just another stranger
  const col2 = rdr.collectRecords(asWalk([G, MR]), repoAddr)
  const res2 = rdr.resolveChain(col2.refs, col2.claims)
  assert.strictEqual(res2.tip.txid, G.txid)
  assert.deepStrictEqual(res2.report.unauthorized.map((u) => u.txid), [MR.txid])
  // "mined EARLIER" is literal: a claim mined AFTER the manifest cannot retroactively authorize it
  const col3 = rdr.collectRecords(asWalk([G, MR, claim]), repoAddr)
  const res3 = rdr.resolveChain(col3.refs, col3.claims)
  assert.strictEqual(res3.claimResults[0].status, 'ACCEPTED', 'the claim itself is fine (tip is still G)')
  assert.strictEqual(res3.tip.txid, G.txid, 'but the earlier-mined manifest stays dead')
})

test('11. PIN: same-block competing VALID children → typed refusal, never source-order + BITE', async () => {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 })
  const B = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'same-block-B' })
  const C = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'same-block-C' })
  const walk = asWalkH([{ ...G, height: 100 }, { ...B, height: 200 }, { ...C, height: 200 }])
  const col = rdr.collectRecords(walk, repoAddr)

  // no intra-block index → the fork is undecidable → refusal surface set
  const res = rdr.resolveChain(col.refs, [], { orderAuthoritative: false })
  assert.strictEqual(res.report.ambiguousSameBlock.length, 1)
  assert.deepStrictEqual(
    [res.report.ambiguousSameBlock[0].winner, res.report.ambiguousSameBlock[0].competitor],
    [B.txid, C.txid])
  // a source with a total order (fixture file order) resolves the same fork fine
  const resAuth = rdr.resolveChain(col.refs, [], { orderAuthoritative: true })
  assert.strictEqual(resAuth.report.ambiguousSameBlock.length, 0)
  assert.strictEqual(resAuth.tip.txid, B.txid)
  // different heights → no ambiguity even without an intra-block index
  const res2 = rdr.resolveChain(rdr.collectRecords(asWalkH([{ ...G, height: 100 }, { ...B, height: 200 }, { ...C, height: 201 }]), repoAddr).refs, [], { orderAuthoritative: false })
  assert.strictEqual(res2.report.ambiguousSameBlock.length, 0)
  assert.strictEqual(res2.tip.txid, B.txid)
  // an UNAUTHORIZED same-height competitor triggers NO refusal — it loses in any order
  const X = sdk.PrivateKey.fromRandom()
  const CX = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'attacker-same-block', key: X })
  const res3 = rdr.resolveChain(rdr.collectRecords(asWalkH([{ ...G, height: 100 }, { ...CX, height: 200 }, { ...B, height: 200 }]), repoAddr).refs, [], { orderAuthoritative: false })
  assert.strictEqual(res3.report.ambiguousSameBlock.length, 0, 'an attacker cannot manufacture a denial-of-resolution')
  assert.strictEqual(res3.tip.txid, B.txid)

  // runReader end: a height-only fixture with a same-block race → typed refusal, no artifact
  const fx = realFixture()
  const dir = join(ROOT, 'fixture-sameblock')
  const chain = cloneChainDir(fx.outDir, dir)
  const mk = (role) => {
    const body = pub.buildRefBody({ repoId: repoAddr, seq: 2, prev: fx.chain.plan.ref_manifest_txid, artifactTxid: fx.chain.plan.artifact_manifest_txid, refsSha256: fx.chain.plan.bundle_refs_sha256, role })
    return rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_REF, body, repoKey)) }, { sats: 10, script: repoScript }])
  }
  const t1 = mk('race-1'); const t2 = mk('race-2')
  writeFileSync(join(dir, 'race1.hex'), t1.toString('hex'))
  writeFileSync(join(dir, 'race2.hex'), t2.toString('hex'))
  chain.entries.push({ txid: txidOf(t1), file: 'race1.hex', role: 'race', height: 800001 })
  chain.entries.push({ txid: txidOf(t2), file: 'race2.hex', role: 'race', height: 800001 })
  chain.mined_order = 'height-only'
  writeFileSync(join(dir, 'chain.json'), JSON.stringify(chain, null, 2))
  await assert.rejects(
    () => rdr.runReader({ repoId: repoAddr, localIn: dir, out: join(ROOT, 'nope-sameblock.bundle'), quiet: true }),
    (e) => e.bgitCode === 'AMBIGUOUS_MINED_ORDER')
  assert.ok(!existsSync(join(ROOT, 'nope-sameblock.bundle')), 'no artifact emitted on an undecidable fork')

  // BITE: disable the tie check → the broken reader silently resolves by source order
  const brokenPath = makeBrokenCopy(join(HERE, 'reader.mjs'),
    'if (!orderAuthoritative && tie) {',
    'if (false && !orderAuthoritative && tie) {')
  const broken = await import(pathToFileURL(brokenPath).href)
  const bent = broken.resolveChain(broken.collectRecords(walk, repoAddr).refs, [], { orderAuthoritative: false })
  assert.strictEqual(bent.report.ambiguousSameBlock.length, 0, 'RED: the broken reader guesses by source order without refusing — the refusal is load-bearing')
  assert.strictEqual(bent.tip.txid, B.txid)
})

test('12. PIN (§5): missing dust → rejected for ALL FOUR record types', () => {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const partRec = Buffer.concat([Buffer.from([0x01, 0x01]), Buffer.from('part-bytes')])
  const artBody = pub.buildArtifactBody({
    repo: 't/t', artifactSha256: A1, artifactBytes: 10,
    parts: [{ txid: A1, sha256: A1, bytes: 10 }], bundleRefsSha256: D1,
    label: 'x', publishedAt: '2026-08-15T00:00:00Z',
  })
  const artRec = pub.signedRecord(pub.TYPE_ARTIFACT, artBody, repoKey)
  const noDustWalk = asWalk([
    { raw: rawTx([{ sats: 0, script: pub.recordScript(partRec) }]) },
    { raw: rawTx([{ sats: 0, script: pub.recordScript(artRec) }]) },
    refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1, paysRepo: false }),
    claimTx({ targetRef: A1, maintainerKey: repoKey, paysRepo: false }),
  ])
  const col = rdr.collectRecords(noDustWalk, repoAddr)
  const dustRejects = col.rejected.filter((r) => r.code === 'NOT_PAYING_REPO')
  assert.strictEqual(dustRejects.length, 4, 'every record type is rejected')
  assert.deepStrictEqual(new Set(dustRejects.map((r) => r.type)), new Set([0x01, 0x02, 0x03, 0x06]), 'PART, ARTIFACT, REF and CLAIM — no exceptions')
  assert.strictEqual(col.parts.size + col.artifacts.size + col.refs.length + col.claims.length, 0, 'nothing was collected')

  // control: the identical records WITH the dust output are all collected
  const dustWalk = asWalk([
    { raw: rawTx([{ sats: 0, script: pub.recordScript(partRec) }, { sats: 10, script: repoScript }]) },
    { raw: rawTx([{ sats: 0, script: pub.recordScript(artRec) }, { sats: 10, script: repoScript }]) },
    refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 }),
    claimTx({ targetRef: A1, maintainerKey: repoKey }),
  ])
  const col2 = rdr.collectRecords(dustWalk, repoAddr)
  assert.strictEqual(col2.parts.size, 1)
  assert.strictEqual(col2.artifacts.size, 1)
  assert.strictEqual(col2.refs.length, 1)
  assert.strictEqual(col2.claims.length, 1)
})

test('13. PIN (§2/0x02): a foreign-signed artifact manifest is REFUSED; a claimant-signed one after its claim is authorized', async () => {
  const fx = realFixture()

  // (a) refusal: same artifact BODY, re-signed by a stranger; ref rebuilt to cite it
  const dir = join(ROOT, 'fixture-foreignart')
  const chain = cloneChainDir(fx.outDir, dir)
  const artEntry = chain.entries.find((e) => e.role === 'artifact-manifest')
  const artRaw = Buffer.from(readFileSync(join(dir, artEntry.file), 'utf8').trim(), 'hex')
  const artRec = rdr.parseRawTx(artRaw).outputs.map((o) => rdr.classifyOutput(o.script)).find(Boolean).record
  const artV = rdr.validateSignedRecord(artRec.subarray(2), { version: artRec[0], type: artRec[1] })
  assert.strictEqual(artV.ok, true, 'fixture artifact extracts cleanly')
  const foreign = sdk.PrivateKey.fromRandom()
  const evilArt = rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_ARTIFACT, artV.body, foreign)) }, { sats: 10, script: repoScript }])
  const refBody = pub.buildRefBody({ repoId: repoAddr, seq: 1, prev: null, artifactTxid: txidOf(evilArt), refsSha256: fx.chain.plan.bundle_refs_sha256 })
  const newRef = rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_REF, refBody, repoKey)) }, { sats: 10, script: repoScript }])
  writeFileSync(join(dir, 'evil-art.hex'), evilArt.toString('hex'))
  writeFileSync(join(dir, 'new-ref.hex'), newRef.toString('hex'))
  artEntry.txid = txidOf(evilArt); artEntry.file = 'evil-art.hex'
  const refEntry = chain.entries.find((e) => e.role.startsWith('ref-manifest'))
  refEntry.txid = txidOf(newRef); refEntry.file = 'new-ref.hex'
  writeFileSync(join(dir, 'chain.json'), JSON.stringify(chain, null, 2))
  await assert.rejects(
    () => rdr.runReader({ repoId: repoAddr, localIn: dir, out: join(ROOT, 'nope-foreign.bundle'), quiet: true }),
    (e) => e.bgitCode === 'ARTIFACT_SIGNER_UNAUTHORIZED',
    'a validly-signed manifest under a key outside the ref-chain authority is a refusal, not a disclosure')
  assert.ok(!existsSync(join(ROOT, 'nope-foreign.bundle')))

  // (b) authorization is TEMPORAL: after an accepted claim, the claimant may sign the manifest
  const M = new sdk.PrivateKey(sha256hex(Buffer.from('bgit claimant key', 'ascii')), 16)
  const dir2 = join(ROOT, 'fixture-claimart')
  const chain2 = cloneChainDir(fx.outDir, dir2)
  const claim = claimTx({ targetRef: fx.chain.plan.ref_manifest_txid, maintainerKey: M })
  const mArt = rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_ARTIFACT, artV.body, M)) }, { sats: 10, script: repoScript }])
  const ref2Body = pub.buildRefBody({ repoId: repoAddr, seq: 2, prev: fx.chain.plan.ref_manifest_txid, artifactTxid: txidOf(mArt), refsSha256: fx.chain.plan.bundle_refs_sha256, role: 'maintainer' })
  const ref2 = rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_REF, ref2Body, M)) }, { sats: 10, script: repoScript }])
  for (const [f, raw] of [['claim.hex', claim.raw], ['m-art.hex', mArt], ['ref2.hex', ref2]]) writeFileSync(join(dir2, f), raw.toString('hex'))
  chain2.entries.push({ txid: claim.txid, file: 'claim.hex', role: 'claim' })
  chain2.entries.push({ txid: txidOf(mArt), file: 'm-art.hex', role: 'claimant-artifact' })
  chain2.entries.push({ txid: txidOf(ref2), file: 'ref2.hex', role: 'claimant-ref' })
  writeFileSync(join(dir2, 'chain.json'), JSON.stringify(chain2, null, 2))
  const out2 = join(ROOT, 'out-claimart.bundle')
  const res2 = await rdr.runReader({ repoId: repoAddr, localIn: dir2, out: out2, quiet: true })
  assert.strictEqual(res2.ok, true)
  assert.strictEqual(res2.tip.seq, 2, 'the claimant chain is the winner')
  assert.strictEqual(sha256hex(readFileSync(out2)), fx.bundleSha, 'and it serves the same verified bytes')
})

test('14. PIN: broadcast refuses fixture bytes that drift from the plan', () => {
  const fx = realFixture()
  const entry = fx.chain.entries.find((e) => e.role === 'artifact-manifest')

  // green: the intact file loads, and what loads re-hashes to the PLANNED txid
  const hex = pub.loadVerifiedTxHex(fx.outDir, entry)
  assert.strictEqual(txidOf(Buffer.from(hex, 'hex')), entry.txid)

  // red: one flipped nibble anywhere in the fixture file → typed refusal BY NAME, before any POST
  const dir = join(ROOT, 'fixture-mutated'); mkdirSync(dir, { recursive: true })
  const text = readFileSync(join(fx.outDir, entry.file), 'utf8')
  const idx = 120
  const mutated = text.slice(0, idx) + (text[idx] === '0' ? '1' : '0') + text.slice(idx + 1)
  assert.notStrictEqual(mutated, text, 'the mutation landed')
  writeFileSync(join(dir, entry.file), mutated)
  assert.throws(() => pub.loadVerifiedTxHex(dir, entry), /BROADCAST_BYTES_MISMATCH/)
  // non-hex junk refuses too (never Buffer.from() garbage into a broadcast)
  writeFileSync(join(dir, entry.file), 'zz not hex zz')
  assert.throws(() => pub.loadVerifiedTxHex(dir, entry), /BROADCAST_BYTES_MISMATCH/)

  // structural pin: the ONE broadcast call site is fed exclusively by the verifying loader
  const src = readFileSync(join(HERE, 'publisher.mjs'), 'utf8')
  assert.match(src, /let hex = loadVerifiedTxHex\(outDir, f\)/)
  assert.strictEqual((src.match(/await broadcastOne\(/g) || []).length, 1, 'one broadcast call site, fed by the verified loader')
})

// ===========================================================================
// round-three pin families (spec §3 rules 2-3, normative after wire fe593953)
// ===========================================================================
test('15. PIN (r3-a): the GENESIS AUTHORIZATION EXCEPTION — artifact mined BEFORE the seq=1 ref', async () => {
  // the real publication IS the shape: parts → artifact manifest → genesis ref, in that mined order
  const fx = realFixture()
  const src = rdr.readLocalTxs(fx.outDir)
  const col = rdr.collectRecords(src.txs, repoAddr)
  const res = rdr.resolveChain(col.refs, col.claims, { orderAuthoritative: src.orderAuthoritative })
  const artifact = col.artifacts.get(res.tip.artifact)
  assert.ok(artifact.minedIdx < res.tip.minedIdx, 'pre-genesis position confirmed: the artifact record precedes the seq=1 ref in mined order')
  // positive: the genesis key is authorized at that pre-genesis position — the explicit exception
  assert.ok(rdr.authorizedKeysAt(res.report, artifact.minedIdx).has(artifact.pubkey.toLowerCase()),
    'genesis key authorized at EVERY position of its chain, including before the genesis ref exists')

  // …and it is an EXCEPTION, not temporal retroactivity: a claimant's grant never reaches backwards
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const M = new sdk.PrivateKey(sha256hex(Buffer.from('bgit claimant key', 'ascii')), 16)
  const Mpub = Buffer.from(M.toPublicKey().encode(true)).toString('hex')
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 })
  const C = claimTx({ targetRef: G.txid, maintainerKey: M })
  const colU = rdr.collectRecords(asWalk([G, C]), repoAddr)
  const resU = rdr.resolveChain(colU.refs, colU.claims)
  const claimIdx = colU.claims[0].minedIdx
  assert.ok(rdr.authorizedKeysAt(resU.report, claimIdx).has(Mpub), 'claimant authorized FROM its claim')
  assert.ok(!rdr.authorizedKeysAt(resU.report, claimIdx - 1).has(Mpub), 'claimant NOT authorized before it — no retroactivity')

  // the refusal leg, at the same pre-genesis position: a FOREIGN-signed artifact refuses; the
  // GENESIS-signed twin walks PAST the auth gate (and dies later at parts, proving which gate bit)
  const artBody = pub.buildArtifactBody({
    repo: 't/pre-genesis', artifactSha256: A1, artifactBytes: 10,
    parts: [{ txid: FAKE64(9), sha256: A1, bytes: 10 }], bundleRefsSha256: D1,
    label: 'x', publishedAt: '2026-08-15T00:00:00Z',
  })
  const mkFixture = (signerKey, name) => {
    const artTx = rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_ARTIFACT, artBody, signerKey)) }, { sats: 10, script: repoScript }])
    const refBody = pub.buildRefBody({ repoId: repoAddr, seq: 1, prev: null, artifactTxid: txidOf(artTx), refsSha256: D1 })
    const refT = rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_REF, refBody, repoKey)) }, { sats: 10, script: repoScript }])
    const dir = join(ROOT, name); mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'art.hex'), artTx.toString('hex'))
    writeFileSync(join(dir, 'ref.hex'), refT.toString('hex'))
    writeFileSync(join(dir, 'chain.json'), JSON.stringify({ entries: [ // artifact BEFORE genesis
      { txid: txidOf(artTx), file: 'art.hex', role: 'artifact-manifest' },
      { txid: txidOf(refT), file: 'ref.hex', role: 'ref-manifest(seq=1)' },
    ] }))
    return dir
  }
  await assert.rejects(
    () => rdr.runReader({ repoId: repoAddr, localIn: mkFixture(sdk.PrivateKey.fromRandom(), 'fx15-foreign'), out: join(ROOT, 'nope15a.bundle'), quiet: true }),
    (e) => e.bgitCode === 'ARTIFACT_SIGNER_UNAUTHORIZED',
    'foreign key at the pre-genesis position → refused')
  await assert.rejects(
    () => rdr.runReader({ repoId: repoAddr, localIn: mkFixture(repoKey, 'fx15-genesis'), out: join(ROOT, 'nope15b.bundle'), quiet: true }),
    (e) => e.bgitCode === 'PART_NOT_FOUND',
    'genesis key at the SAME position → past the auth gate (fails later at the fictitious part — the discriminating pair)')
})

test('16. PIN (r3-b): same-block claim/ref positional dependency — the index decides; no index → refusal', async () => {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const M = new sdk.PrivateKey(sha256hex(Buffer.from('bgit claimant key', 'ascii')), 16)
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 })
  const C = claimTx({ targetRef: G.txid, maintainerKey: M })
  const MR = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'claimant-extend', key: M })
  const claimFirst = asWalkH([{ ...G, height: 100 }, { ...C, height: 200 }, { ...MR, height: 200 }])
  const refFirst = asWalkH([{ ...G, height: 100 }, { ...MR, height: 200 }, { ...C, height: 200 }])

  // WITH the intra-block index (authoritative order): claim@N then ref@N+1 → the ref is VALID
  const c1 = rdr.collectRecords(claimFirst, repoAddr)
  const r1 = rdr.resolveChain(c1.refs, c1.claims, { orderAuthoritative: true })
  assert.strictEqual(r1.tip.txid, MR.txid, 'authority begins at the claim — the same-block claimant ref extends')
  assert.strictEqual(r1.report.ambiguousSameBlock.length, 0, 'an index makes the order the answer')

  // WITH the index: ref@N then claim@N+1 → that ref is INVALID (authority had not begun)
  const c2 = rdr.collectRecords(refFirst, repoAddr)
  const r2 = rdr.resolveChain(c2.refs, c2.claims, { orderAuthoritative: true })
  assert.strictEqual(r2.tip.txid, G.txid)
  assert.deepStrictEqual(r2.report.unauthorized.map((u) => u.txid), [MR.txid])
  assert.strictEqual(r2.claimResults[0].status, 'ACCEPTED', 'the claim itself is fine either way')
  assert.strictEqual(r2.report.ambiguousSameBlock.length, 0)

  // NO index: the SAME records, EITHER observed order → typed ambiguity, never a source-order guess
  for (const [name, colX] of [['claim-first observed', c1], ['ref-first observed', c2]]) {
    const rX = rdr.resolveChain(colX.refs, colX.claims, { orderAuthoritative: false })
    assert.ok(rX.report.ambiguousSameBlock.some((a) => a.kind === 'claim-ref-order' && a.claim === C.txid && a.ref === MR.txid),
      `${name}: the claim/ref pair is flagged order-dependent`)
  }
  // different blocks, no index → no dependency; heights decide
  const cDiff = rdr.collectRecords(asWalkH([{ ...G, height: 100 }, { ...C, height: 200 }, { ...MR, height: 201 }]), repoAddr)
  const rDiff = rdr.resolveChain(cDiff.refs, cDiff.claims, { orderAuthoritative: false })
  assert.strictEqual(rDiff.report.ambiguousSameBlock.length, 0)
  assert.strictEqual(rDiff.tip.txid, MR.txid)

  // the claim-VERDICT race is positional too: a genesis-key ref advances the tip in the same
  // block as a would-be first-claim targeting the tip it replaces — accepted-if-first, stale-if-second
  const R2 = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'advance' })
  for (const order of [[G, R2, C], [G, C, R2]]) {
    const walk = asWalkH(order.map((t, i) => ({ ...t, height: i === 0 ? 100 : 200 })))
    const cV = rdr.collectRecords(walk, repoAddr)
    const rV = rdr.resolveChain(cV.refs, cV.claims, { orderAuthoritative: false })
    assert.ok(rV.report.ambiguousSameBlock.some((a) => a.kind === 'claim-ref-order' && a.claim === C.txid && a.ref === R2.txid),
      'the claim-verdict/tip-advance race is flagged in either observed order')
  }

  // runReader end: a height-only fixture with the claim+claimant-ref pair → typed refusal
  const fx = realFixture()
  const dir = join(ROOT, 'fixture-claimref-sameblock')
  const chain = cloneChainDir(fx.outDir, dir)
  const realClaim = claimTx({ targetRef: fx.chain.plan.ref_manifest_txid, maintainerKey: M })
  const ref2Body = pub.buildRefBody({ repoId: repoAddr, seq: 2, prev: fx.chain.plan.ref_manifest_txid, artifactTxid: fx.chain.plan.artifact_manifest_txid, refsSha256: fx.chain.plan.bundle_refs_sha256, role: 'maintainer' })
  const ref2 = rawTx([{ sats: 0, script: pub.recordScript(pub.signedRecord(pub.TYPE_REF, ref2Body, M)) }, { sats: 10, script: repoScript }])
  writeFileSync(join(dir, 'claim.hex'), realClaim.raw.toString('hex'))
  writeFileSync(join(dir, 'ref2.hex'), ref2.toString('hex'))
  chain.entries.push({ txid: realClaim.txid, file: 'claim.hex', role: 'claim', height: 800002 })
  chain.entries.push({ txid: txidOf(ref2), file: 'ref2.hex', role: 'claimant-ref', height: 800002 })
  chain.mined_order = 'height-only'
  writeFileSync(join(dir, 'chain.json'), JSON.stringify(chain, null, 2))
  await assert.rejects(
    () => rdr.runReader({ repoId: repoAddr, localIn: dir, out: join(ROOT, 'nope16.bundle'), quiet: true }),
    (e) => e.bgitCode === 'AMBIGUOUS_MINED_ORDER')
  assert.ok(!existsSync(join(ROOT, 'nope16.bundle')))
})

test('17. PIN (r3-c): FIRST-CLAIM PERMANENCE — repeat claims by an authorized key are authority NO-OPs', () => {
  const A1 = FAKE64(1); const D1 = FAKE64(2)
  const M = new sdk.PrivateKey(sha256hex(Buffer.from('bgit claimant key', 'ascii')), 16)
  const Mpub = Buffer.from(M.toPublicKey().encode(true)).toString('hex')
  const G = refTx({ seq: 1, prev: null, artifact: A1, refsSha: D1 })
  const C1 = claimTx({ targetRef: G.txid, maintainerKey: M })
  const R2 = refTx({ seq: 2, prev: G.txid, artifact: A1, refsSha: D1, role: 'maintainer', key: M })
  // repeats: a STALE re-claim (old target — cannot be made current), and a FRESH re-claim that
  // even tries to re-anchor with a different domain and role
  const staleRepeat = claimTx({ targetRef: G.txid, maintainerKey: M, domain: 'reanchor.example' })
  const freshRepeat = claimTx({ targetRef: R2.txid, maintainerKey: M, domain: 'reanchor.example' })

  const base = rdr.collectRecords(asWalk([G, C1, R2]), repoAddr)
  const resBase = rdr.resolveChain(base.refs, base.claims)
  const full = rdr.collectRecords(asWalk([G, C1, R2, staleRepeat, freshRepeat]), repoAddr)
  const resFull = rdr.resolveChain(full.refs, full.claims)

  // both repeats are validated RECORDS with verdicts…
  assert.strictEqual(full.claims.length, 3, 'all three claims collect (signature + fields valid)')
  assert.strictEqual(resFull.claimResults.find((r) => r.txid === staleRepeat.txid).status, 'REJECTED', 'a stale target cannot be made current')
  assert.strictEqual(resFull.claimResults.find((r) => r.txid === staleRepeat.txid).code, 'STALE_TARGET_REF')
  assert.strictEqual(resFull.claimResults.find((r) => r.txid === freshRepeat.txid).status, 'ACCEPTED', 'the fresh repeat validates as a record…')

  // …but AUTHORITY is byte-identical with and without them: one grant per key, ever, anchored
  // at the FIRST accepted claim — no refresh, no re-anchor, no role/domain change
  const grantsBase = resBase.report.authTimeline.filter((a) => a.pubkey === Mpub)
  const grantsFull = resFull.report.authTimeline.filter((a) => a.pubkey === Mpub)
  assert.strictEqual(grantsFull.length, 1, 'ONE grant per maintainer_pubkey, ever')
  assert.deepStrictEqual(grantsFull, grantsBase, 'authority state identical before/after the repeats')
  assert.strictEqual(grantsFull[0].source, C1.txid, 'permanently anchored at the FIRST accepted claim')
  assert.deepStrictEqual(resFull.report.authTimeline, resBase.report.authTimeline, 'the WHOLE authority timeline is unchanged')
  assert.deepStrictEqual(resFull.chain.map((r) => r.txid), resBase.chain.map((r) => r.txid), 'and the resolved chain is unchanged')
})

// ===========================================================================
// THE CLAIM VERB (claim.mjs) — gates V1–V4 per the codex-crypto verdict
// (wire b81a4643, BUILD-WITH-CHANGES, all changes folded). V4 = every vector
// above re-running untouched in this same file.
// ===========================================================================
const clm = await import('./claim.mjs')

test('18. CLAIM VERB V1: body byte-vector vs a hand-built second implementation; envelope verifies as 0x06', () => {
  const M = new sdk.PrivateKey(sha256hex(Buffer.from('bgit claim verb maintainer', 'ascii')), 16)
  const mp = Buffer.from(M.toPublicKey().encode(true)).toString('hex')
  const tgt = FAKE64(77)
  const body = clm.buildClaimBody({ repoId: repoAddr, maintainerPubkey: mp, domain: 'getmonero.org', targetRef: tgt })
  // second implementation: the literal JSON string in the spec's exact field order
  const hand = `{"bgit":1,"repo_id":"${repoAddr}","maintainer_pubkey":"${mp}","domain":"getmonero.org","role":"maintainer","target_ref":"${tgt}"}`
  assert.strictEqual(body.toString('utf8'), hand, 'claim body bytes match the hand-built spec sample exactly')
  const rec = pub.signedRecord(pub.TYPE_CLAIM, body, M)
  assert.strictEqual(rec[0], 0x01); assert.strictEqual(rec[1], pub.TYPE_CLAIM)
  const v = rdr.validateSignedRecord(rec.subarray(2), { version: rec[0], type: rec[1] })
  assert.strictEqual(v.ok, true, `reader verifies the verb-built 0x06: ${v.code || ''}`)
  assert.ok(v.body.equals(body), 'reader-validated 0x06 envelope carries the literal body bytes')
  const wk = clm.wellKnownExpected({ repoId: repoAddr, maintainerPubkey: mp, domain: 'getmonero.org' })
  assert.strictEqual(wk.url, 'https://getmonero.org/.well-known/bgit')
  const pj = JSON.parse(wk.content)
  assert.strictEqual(pj.repo_id, repoAddr)
  assert.strictEqual(pj.maintainer_pubkey, mp)
})

test('18b. CLAIM VERB V3 (pure lattice): genesis / already-authorized / unmined-tip refuse; domain law', () => {
  const snapBase = { tipMined: true, tipTxid: FAKE64(5), genesisPubkey: '02' + 'aa'.repeat(32), granted: new Set(['02' + 'bb'.repeat(32)]) }
  const freshKey = '02' + 'cc'.repeat(32)
  const codeOf = (fn) => { try { fn(); return null } catch (e) { return e.code } }
  assert.strictEqual(codeOf(() => clm.claimPreconditions(snapBase, snapBase.genesisPubkey)), 'GENESIS_NEEDS_NO_CLAIM')
  assert.strictEqual(codeOf(() => clm.claimPreconditions(snapBase, '02' + 'bb'.repeat(32))), 'ALREADY_AUTHORIZED')
  assert.strictEqual(codeOf(() => clm.claimPreconditions({ ...snapBase, tipMined: false }, freshKey)), 'TIP_UNMINED')
  assert.strictEqual(codeOf(() => clm.claimPreconditions(snapBase, freshKey)), null, 'a fresh key on a mined tip passes')
  for (const bad of ['GetMonero.org', 'https://x.com', 'x.com/path', 'localhost', 'a_b.com', '', 'x.', '.x'])
    assert.ok(!clm.validDomain(bad), `domain rejected: ${JSON.stringify(bad)}`)
  for (const ok of ['getmonero.org', 'wownero.org', 'a.b.c.example', 'xn--gckvb8fzb.com'])
    assert.ok(clm.validDomain(ok), `domain accepted: ${ok}`)
})

test('19. CLAIM VERB V2 (EXECUTION): claim built THROUGH THE VERB, real reader prefers the maintainer chain; mined-order law both ways', async () => {
  const fx = realFixture()
  // ground truth about the un-claimed fixture from the reader's own machinery
  const src = rdr.readLocalTxs(fx.outDir)
  const col = rdr.collectRecords(src.txs, repoAddr)
  const rc = rdr.resolveChain(col.refs, col.claims, { orderAuthoritative: src.orderAuthoritative })

  const B = new sdk.PrivateKey(sha256hex(Buffer.from('claim verb key B', 'ascii')), 16)
  const Bpub = Buffer.from(B.toPublicKey().encode(true)).toString('hex')
  const planDir = join(ROOT, 'claim-plan')
  const res = await clm.runClaim({ repoId: repoAddr, key: B.toWif(), domain: 'getmonero.org', localIn: fx.outDir, out: planDir, bridges: [] })
  assert.strictEqual(res.broadcast, false, 'fixture universe is dry-run only')
  assert.strictEqual(res.plan.target_ref, rc.tip.txid, 'target_ref = the reader-resolved mined tip, never hand-supplied')
  const planText = readFileSync(join(planDir, 'claim-plan.json'), 'utf8')
  assert.ok(!planText.includes(B.toWif()), 'no key material in the plan')
  assert.ok(existsSync(join(planDir, 'claim-record.hex')) && existsSync(join(planDir, 'well-known-expected.json')))

  // compose the verb's OWN record onto the chain (dust-to-repo per §5), then key B's maintainer ref
  const claimRaw = rawTx([{ sats: 0, script: pub.recordScript(res.record) }, { sats: 10, script: repoScript }])
  const claimTxid2 = txidOf(claimRaw)
  const mref = refTx({ seq: rc.tip.seq + 1, prev: rc.tip.txid, artifact: rc.tip.artifact, refsSha: rc.tip.refs_sha256, role: 'maintainer', key: B })

  const mkExtended = (name, order) => {
    const dir = join(ROOT, name)
    const chain = cloneChainDir(fx.outDir, dir)
    for (const [txid, raw, file] of order) {
      writeFileSync(join(dir, file), raw.toString('hex'))
      chain.entries.push({ txid, file })
    }
    writeFileSync(join(dir, 'chain.json'), JSON.stringify(chain, null, 2))
    return dir
  }

  // POSITIVE: claim mined BEFORE the maintainer ref (entry order = mined order, authoritative)
  const dirGood = mkExtended('fixture-claimed', [[claimTxid2, claimRaw, 'claim.hex'], [mref.txid, mref.raw, 'mref.hex']])
  const rep = await rdr.runReader({ repoId: repoAddr, localIn: dirGood, out: join(ROOT, 'out-claimed.bundle'), quiet: true })
  assert.strictEqual(rep.tip.txid, mref.txid, 'the REAL reader now serves the maintainer chain')
  assert.strictEqual(rep.tip.pubkey, Bpub, 'tip signed by the claimant key')
  assert.ok(rep.claims.some((c) => c.txid === claimTxid2 && c.status === 'ACCEPTED'), 'the verb-built claim is ACCEPTED by the reader')
  assert.strictEqual(sha256hex(readFileSync(join(ROOT, 'out-claimed.bundle'))), fx.bundleSha, 'the artifact still reconstructs byte-identical under the maintainer chain')

  // RED CONTROL: same records, maintainer ref mined BEFORE the claim — unauthorized at its time
  const dirBad = mkExtended('fixture-claim-red', [[mref.txid, mref.raw, 'mref.hex'], [claimTxid2, claimRaw, 'claim.hex']])
  const src2 = rdr.readLocalTxs(dirBad)
  const col2 = rdr.collectRecords(src2.txs, repoAddr)
  const rc2 = rdr.resolveChain(col2.refs, col2.claims, { orderAuthoritative: src2.orderAuthoritative })
  assert.strictEqual(rc2.tip.txid, rc.tip.txid, 'RED: the maintainer ref does NOT take the tip when mined before its claim')
  assert.ok(rc2.report.unauthorized.some((u) => u.txid === mref.txid), 'RED: the early ref is rejected as unauthorized — mined order is the law, not array luck')
})

test('20. CLAIM VERB V3 (through the verb): already-authorized, genesis, fixture-broadcast, no-genesis, bad-domain all refuse', async () => {
  const fx = realFixture()
  const B = new sdk.PrivateKey(sha256hex(Buffer.from('claim verb key B', 'ascii')), 16)
  const codeOf = async (p) => { try { await p; return null } catch (e) { return e.code } }
  // on the CLAIMED chain from vector 19, key B already holds the grant
  assert.strictEqual(await codeOf(clm.runClaim({ repoId: repoAddr, key: B.toWif(), domain: 'getmonero.org', localIn: join(ROOT, 'fixture-claimed') })), 'ALREADY_AUTHORIZED')
  // the genesis key needs no claim
  assert.strictEqual(await codeOf(clm.runClaim({ repoId: repoAddr, key: repoKey.toWif(), domain: 'getmonero.org', localIn: fx.outDir })), 'GENESIS_NEEDS_NO_CLAIM')
  // the fixture seam has no broadcast path, structurally
  assert.strictEqual(await codeOf(clm.runClaim({ repoId: repoAddr, key: B.toWif(), domain: 'getmonero.org', localIn: fx.outDir, broadcast: true, funding: `${FAKE64(1)}:0:100000`, bridges: ['http://127.0.0.1:1/x'] })), 'FIXTURE_CANNOT_BROADCAST')
  // an unverifiable repo is never claimed
  const emptyDir = join(ROOT, 'fixture-empty')
  mkdirSync(emptyDir, { recursive: true })
  writeFileSync(join(emptyDir, 'chain.json'), JSON.stringify({ entries: [] }))
  assert.strictEqual(await codeOf(clm.runClaim({ repoId: repoAddr, key: B.toWif(), domain: 'getmonero.org', localIn: emptyDir })), 'NO_GENESIS')
  // domain law at the door
  assert.strictEqual(await codeOf(clm.runClaim({ repoId: repoAddr, key: B.toWif(), domain: 'https://x.com', localIn: fx.outDir })), 'BAD_DOMAIN')
})

test('21. CLAIM VERB source pins: no tip override exists; evidence fetched twice before broadcast; no bypass flag; CLI refuses bare', () => {
  const srcText = readFileSync(join(HERE, 'claim.mjs'), 'utf8')
  assert.ok(!srcText.includes('--assume-tip'), 'PIN: no CLI tip override exists — target_ref derives from the walk, always')
  assert.ok(!/skip-evidence/i.test(srcText), 'PIN: no production evidence-bypass flag')
  const iEv1 = srcText.indexOf('const ev1 = await fetchEvidence')
  const iSnap2 = srcText.indexOf('const snap2 = await walkSnapshot')
  const iEv2 = srcText.indexOf('const ev2 = await fetchEvidence')
  const iBcast = srcText.indexOf('await broadcastOne(')
  assert.ok(iEv1 > 0 && iSnap2 > iEv1 && iEv2 > iSnap2 && iBcast > iEv2,
    'PIN: order is evidence, re-walk (CHAIN_MOVED), evidence re-check (EVIDENCE_LOST), broadcast')
  assert.ok(srcText.includes('EVIDENCE_MISSING') && srcText.includes('EVIDENCE_LOST') && srcText.includes('CHAIN_MOVED'))
  assert.ok(srcText.includes('FUNDING_NOT_OURS'), 'PIN: the funding outpoint must pay the claim key')
  const r = runCli(join(HERE, 'claim.mjs'), [])
  assert.notStrictEqual(r.status, 0, 'bare CLI refuses with usage')
})

// ===========================================================================
// PUBLISHER --continue (part 2) — gates G1–G5 per codex-crypto 7b7f878e
// (BUILD-WITH-CHANGES, all folded incl. the mid-publish REF race). G5 = every
// vector above re-running untouched.
// ===========================================================================

test('22. CONTINUE G1 (EXECUTION): genesis publishes seq=2 with a NEW bundle; real reader serves the new tip + new artifact; claim_how law', async () => {
  const fx = realFixture()
  const repo2 = makeRepoBundle({ commits: 6, filler: 500 })
  const repo2sha = sha256hex(readFileSync(repo2.bundlePath))
  const contDir = join(ROOT, 'continue-genesis')
  const r = runCli(join(HERE, 'publisher.mjs'), [
    '--bundle', repo2.bundlePath, '--repo', 'test/real', '--key', repoKey.toWif(),
    '--part-bytes', '700', '--local-out', contDir, '--continue', '--chain-in', fx.outDir,
  ])
  assert.strictEqual(r.status, 0, `continue publisher: ${r.stderr}`)
  const contChain = JSON.parse(readFileSync(join(contDir, 'chain.json'), 'utf8'))
  assert.strictEqual(contChain.plan.continues.from_seq, 1, 'plan discloses what it continues from')
  assert.strictEqual(contChain.plan.continues.role, 'unsigned-mirror', 'genesis inherits the validated tip role')

  // merge base + continuation into one walk (synthetic funding txs are non-records, ignored)
  const merged = join(ROOT, 'merged-genesis')
  const baseChain = cloneChainDir(fx.outDir, merged)
  for (const e of contChain.entries) {
    writeFileSync(join(merged, 'c-' + e.file), readFileSync(join(contDir, e.file)))
    baseChain.entries.push({ txid: e.txid, file: 'c-' + e.file })
  }
  writeFileSync(join(merged, 'chain.json'), JSON.stringify(baseChain, null, 2))
  const out2 = join(ROOT, 'out-continued.bundle')
  const rep = await rdr.runReader({ repoId: repoAddr, localIn: merged, out: out2, quiet: true })
  assert.strictEqual(rep.tip.seq, 2, 'the reader serves the continuation tip')
  assert.strictEqual(rep.tip.txid, contChain.plan.ref_manifest_txid)
  assert.strictEqual(sha256hex(readFileSync(out2)), repo2sha, 'the NEW bundle reconstructs byte-identical')

  // claim_how law (7b7f878e): invitation on unsigned mirrors ONLY
  const bodyU = JSON.parse(pub.buildRefBody({ repoId: repoAddr, seq: 2, prev: FAKE64(1), artifactTxid: FAKE64(2), refsSha256: FAKE64(3) }).toString('utf8'))
  assert.ok(bodyU.claim_how, 'unsigned-mirror refs carry the claim invitation')
  const bodyM = JSON.parse(pub.buildRefBody({ repoId: repoAddr, seq: 2, prev: FAKE64(1), artifactTxid: FAKE64(2), refsSha256: FAKE64(3), role: 'maintainer' }).toString('utf8'))
  assert.strictEqual(bodyM.claim_how, undefined, 'maintainer refs must not advertise an exercised invitation')
})

test('22b. CONTINUE G2 (EXECUTION): an accepted claimant continues as FORCED maintainer; role not selectable; unauthorized key refused pre-spend', async () => {
  const fx = realFixture()
  const B = new sdk.PrivateKey(sha256hex(Buffer.from('claim verb key B', 'ascii')), 16)
  const Bpub = Buffer.from(B.toPublicKey().encode(true)).toString('hex')
  const claimedDir = join(ROOT, 'fixture-claimed') // from vector 19: base + accepted claim + B's seq=2 maintainer ref
  const repo3 = makeRepoBundle({ commits: 2, filler: 300 })
  const repo3sha = sha256hex(readFileSync(repo3.bundlePath))
  const contDir = join(ROOT, 'continue-claimant')
  const r = runCli(join(HERE, 'publisher.mjs'), [
    '--bundle', repo3.bundlePath, '--repo', 'test/real', '--key', B.toWif(),
    '--part-bytes', '700', '--local-out', contDir, '--continue', '--chain-in', claimedDir, '--repo-id', repoAddr,
  ])
  assert.strictEqual(r.status, 0, `claimant continue: ${r.stderr}`)
  const contChain = JSON.parse(readFileSync(join(contDir, 'chain.json'), 'utf8'))
  assert.strictEqual(contChain.plan.continues.role, 'maintainer', 'claimant role is FORCED maintainer')
  assert.strictEqual(contChain.plan.continues.from_seq, 2)
  assert.strictEqual(contChain.plan.repo_id, repoAddr, 'repo_id stays the CHAIN address, not the claimant address')
  assert.notStrictEqual(contChain.plan.fund_address, repoAddr, 'the claimant funds from their OWN key')

  const merged = join(ROOT, 'merged-claimant')
  const baseChain = cloneChainDir(claimedDir, merged)
  for (const e of contChain.entries) {
    writeFileSync(join(merged, 'c-' + e.file), readFileSync(join(contDir, e.file)))
    baseChain.entries.push({ txid: e.txid, file: 'c-' + e.file })
  }
  writeFileSync(join(merged, 'chain.json'), JSON.stringify(baseChain, null, 2))
  const out3 = join(ROOT, 'out-claimant-continued.bundle')
  const rep = await rdr.runReader({ repoId: repoAddr, localIn: merged, out: out3, quiet: true })
  assert.strictEqual(rep.tip.seq, 3, 'maintainer chain extends')
  assert.strictEqual(rep.tip.pubkey, Bpub, 'tip signed by the claimant')
  assert.strictEqual(rep.tip.role, 'maintainer')
  assert.strictEqual(sha256hex(readFileSync(out3)), repo3sha, 'claimant update reconstructs byte-identical')

  // role is not selectable on a claimed chain
  const r2 = runCli(join(HERE, 'publisher.mjs'), [
    '--bundle', repo3.bundlePath, '--repo', 'test/real', '--key', B.toWif(),
    '--local-out', join(ROOT, 'x-role'), '--continue', '--chain-in', claimedDir, '--repo-id', repoAddr, '--role', 'tip',
  ])
  assert.notStrictEqual(r2.status, 0)
  assert.ok(/not selectable/.test(r2.stderr), `refusal names the law: ${r2.stderr.slice(0, 200)}`)

  // an unauthorized key refuses BEFORE any satoshi would move
  const C = new sdk.PrivateKey(sha256hex(Buffer.from('unauthorized key C', 'ascii')), 16)
  const r3 = runCli(join(HERE, 'publisher.mjs'), [
    '--bundle', repo3.bundlePath, '--repo', 'test/real', '--key', C.toWif(),
    '--local-out', join(ROOT, 'x-unauth'), '--continue', '--chain-in', fx.outDir, '--repo-id', repoAddr,
  ])
  assert.notStrictEqual(r3.status, 0)
  assert.ok(/UNAUTHORIZED_KEY/.test(r3.stderr), `refusal is typed: ${r3.stderr.slice(0, 200)}`)
})

test('23. CONTINUE G3/G4: unmined-tip walk refuses; seq/prev underivable by flag; broadcast motion-check order + retarget pinned in source', () => {
  const fx = realFixture()
  // a chain whose only ref is unmined cannot be continued (refuses in the walk, pre-spend)
  const dir = join(ROOT, 'fixture-unmined')
  const chain = cloneChainDir(fx.outDir, dir)
  chain.entries[chain.entries.length - 1].mined = false // the ref manifest
  writeFileSync(join(dir, 'chain.json'), JSON.stringify(chain, null, 2))
  const repo4 = makeRepoBundle({ commits: 2 })
  const r = runCli(join(HERE, 'publisher.mjs'), [
    '--bundle', repo4.bundlePath, '--repo', 'test/real', '--key', repoKey.toWif(),
    '--local-out', join(ROOT, 'x-unmined'), '--continue', '--chain-in', dir,
  ])
  assert.notStrictEqual(r.status, 0, 'an unmined tip is not a continuation base')
  assert.ok(/TIP_UNMINED|NO_GENESIS/.test(r.stderr), `typed refusal: ${r.stderr.slice(0, 200)}`)

  // G4: seq/prev derive from the walk — no flag can supply them
  const src = readFileSync(join(HERE, 'publisher.mjs'), 'utf8')
  assert.ok(!src.includes("'--seq'") && !src.includes("'--prev'"), 'PIN: no seq/prev overrides exist')

  // 7b7f878e ordering pins: motion check before the first POST; re-walk + retarget before the REF POST
  const iS2 = src.indexOf('const s2 = await walkSnapshot')
  const iS3 = src.indexOf('const s3 = await walkSnapshot')
  const iPost = src.indexOf('await broadcastOne(hex, bridges)')
  assert.ok(iS2 > 0 && iS3 > iS2 && iPost > iS3, 'PIN: snapshot#2 (pre-first-POST) and snapshot#3 (pre-REF) both precede the POST in the loop')
  assert.ok(src.includes('SUPERSEDED(retarget)') && src.includes('CHAIN_MOVED'), 'PIN: retarget-or-refuse exists, stranded data reported honestly')
  assert.ok(src.includes('FUNDING_NOT_OURS'), 'PIN: continue-broadcast verifies the funding pays the signing key')
})
