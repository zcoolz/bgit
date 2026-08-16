#!/usr/bin/env node
// bgit publisher — g-417 (THE MONERO MIRROR). Publishes a git bundle to BSV per
// BGIT_WIRE_FORMAT_v1.md (v1.1, FROZEN). DRY-RUN IS THE DEFAULT: without --broadcast this
// constructs every transaction fully, prints the funding plan, and (with --local-out) writes a
// local fixture chain the reader can consume with zero network. Broadcast is human-gated.
//
//   node publisher.mjs --bundle <path> --repo <name> --key-file <publisher-key.json>
//                      [--part-bytes 9900000] [--local-out <dir>] [--source-hint <url>]
//                      [--spec-txid <txid>] [--label <s>] [--published-at <iso>]
//                      [--broadcast --funding <txid>:<vout>:<sats> [--bridge <url>]...]
//   node publisher.mjs --confirm --state <publish-state.json> [--status-url <tpl>]
//
// --key-file reads {"wif": ...} (the publisher-key.json shape). The wif is used in-process and
// NEVER printed — no log line, no report field, no error message carries it. --key <WIF> exists
// for tests with throwaway keys; prefer --key-file (a raw WIF on argv leaks via shell history).
//
// UTXO chaining law (hard-won, non-negotiable): the transactions broadcast SEQUENTIALLY, each
// spending the previous transaction's change output, chained in memory — never re-queried.
// Only-mined honesty: broadcast reports every txid PENDING; only --confirm may print accepted.

import { createRequire } from 'node:module'
import { createHash } from 'node:crypto'
import {
  readFileSync, writeFileSync, mkdirSync, existsSync, rmSync, mkdtempSync, statSync,
} from 'node:fs'
import { join, resolve, dirname, isAbsolute } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
// ONE walker for reader, claim, and --continue (7b7f878e law); acyclic — reader imports nothing from here.
import { walkSnapshot, SOURCE_PRESETS } from './reader.mjs'

// ---------------------------------------------------------------------------
// constants (spec-pinned)
// ---------------------------------------------------------------------------
export const SIGN_PREFIX = 'bgit1|'                    // §3: digest = SHA256("bgit1|" || body)
export const PROTOCOL_TAG = Buffer.from('bgit', 'ascii') // §1 first pushdata
export const FORMAT_VERSION = 0x01
export const TYPE_PART = 0x01
export const TYPE_ARTIFACT = 0x02
export const TYPE_REF = 0x03
export const TYPE_CLAIM = 0x06

export const DEFAULT_PART_BYTES = 9_900_000            // §3 publisher policy for this publish
export const FEE_RATE_SAT_PER_KB = 150                 // proven-mineable floor
export const DUST_SATS = 10                            // §5 dust-on-every-tx
export const FINAL_CHANGE_SATS = 546                   // leftover change kept on the last tx
export const DEFAULT_BRIDGES = null // no default: a broadcast endpoint is EXPLICIT, always — tools must not default to anyone's infrastructure (2026-08-15 erratum: the old default was a stale placeholder hostname that resolves nowhere)
export const DEFAULT_STATUS_URL = null // no default: same law as DEFAULT_BRIDGES

// §3 claim_how, verbatim from the frozen spec.
export const CLAIM_HOW =
  "Publish a CLAIM ATTESTATION (0x06) binding this repo_id to your maintainer key and canonical domain, then a REF MANIFEST with role 'maintainer' citing the current tip in prev. Readers prefer the maintainer chain once its attestation verifies."

// ---------------------------------------------------------------------------
// SDK loader — resolves @bsv/sdk without this directory owning a node_modules.
// Candidates: $BGIT_SDK_DIR, this file's dir, ../mcp-server (the repo's copy), cwd, cwd/mcp-server.
// ---------------------------------------------------------------------------
let _sdk = null
export function loadSdk () {
  if (_sdk) return _sdk
  const here = dirname(fileURLToPath(import.meta.url))
  const candidates = [
    process.env.BGIT_SDK_DIR,
    here,
    resolve(here, '..', 'mcp-server'),
    process.cwd(),
    resolve(process.cwd(), 'mcp-server'),
  ].filter(Boolean)
  const errors = []
  for (const dir of candidates) {
    try {
      const req = createRequire(join(dir, '__bgit_resolve__.js'))
      _sdk = req('@bsv/sdk')
      return _sdk
    } catch (e) { errors.push(`${dir}: ${e.code || e.message}`) }
  }
  throw new Error(`@bsv/sdk not resolvable from any candidate dir (set BGIT_SDK_DIR):\n  ${errors.join('\n  ')}`)
}

// ---------------------------------------------------------------------------
// primitives
// ---------------------------------------------------------------------------
export const sha256 = (buf) => createHash('sha256').update(buf).digest()
export const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex')

// Bitcoin CompactSize varint, canonical (minimal) encoding.
// SPEC-AMBIGUITY: the spec says "varint" without defining it — CompactSize chosen (see README).
export function encodeVarint (n) {
  if (!Number.isInteger(n) || n < 0) throw new Error(`varint: bad length ${n}`)
  if (n < 0xfd) return Buffer.from([n])
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b }
  if (n <= 0xffffffff) { const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b }
  const b = Buffer.alloc(9); b[0] = 0xff; b.writeBigUInt64LE(BigInt(n), 1); return b
}

// Minimal-form script pushdata.
export function pushdata (buf) {
  const n = buf.length
  if (n <= 0x4b) return Buffer.concat([Buffer.from([n]), buf])
  if (n <= 0xff) return Buffer.concat([Buffer.from([0x4c, n]), buf])
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0x4d; b.writeUInt16LE(n, 1); return Buffer.concat([b, buf]) }
  const b = Buffer.alloc(5); b[0] = 0x4e; b.writeUInt32LE(n, 1); return Buffer.concat([b, buf])
}

// §1 output script: OP_FALSE OP_RETURN <push "bgit"> <push record>
export function recordScript (record) {
  return Buffer.concat([Buffer.from([0x00, 0x6a]), pushdata(PROTOCOL_TAG), pushdata(record)])
}

// §3 signed-body envelope record:
//   [version, type] || varint(body_len) || body || 0x21 || pubkey33 || varint(sig_len) || DER sig
// Signature (v1.3, round-two A2): secp256k1 ECDSA, strict DER, low-S, over
//   SHA256("bgit1|" || VERSION_BYTE || TYPE_BYTE || body_bytes)
// — the envelope's version and type bytes are cryptographically bound into the preimage, so a
// flipped type byte fails the signature itself instead of relying on typed-body validation.
export function signedRecord (type, bodyBytes, privKey) {
  const sdk = loadSdk()
  const msg = Buffer.concat([Buffer.from(SIGN_PREFIX, 'ascii'), Buffer.from([FORMAT_VERSION, type]), bodyBytes])
  const sig = privKey.sign(Array.from(msg))            // SDK: sha256 once internally, forceLowS default true
  const der = Buffer.from(sig.toDER())
  const pub = Buffer.from(privKey.toPublicKey().encode(true))
  if (pub.length !== 33 || (pub[0] !== 0x02 && pub[0] !== 0x03)) throw new Error('pubkey not 33-byte compressed')
  if (der[0] !== 0x30 || der.length > 72) throw new Error(`unexpected DER shape (len ${der.length})`)
  // self-check: verify before shipping (a signature nobody can verify must never leave here)
  const digest = sha256hex(msg)
  const ok = sdk.ECDSA.verify(new sdk.BigNumber(digest, 16), sdk.Signature.fromDER(Array.from(der)), privKey.toPublicKey())
  if (!ok) throw new Error('self-verify failed on freshly built signature')
  return Buffer.concat([
    Buffer.from([FORMAT_VERSION, type]),
    encodeVarint(bodyBytes.length), bodyBytes,
    Buffer.from([0x21]), pub,
    encodeVarint(der.length), der,
  ])
}

// §3 0x01 PART: raw bytes, no wrapper.
export function partRecord (chunk) {
  return Buffer.concat([Buffer.from([FORMAT_VERSION, TYPE_PART]), chunk])
}

export function p2pkhScript (address) {
  const sdk = loadSdk()
  return Buffer.from(new sdk.P2PKH().lock(address).toBinary())
}

// ---------------------------------------------------------------------------
// manifest bodies (§3) — literal bytes are what gets signed; field order follows the spec sample.
// ---------------------------------------------------------------------------
export function buildArtifactBody ({ repo, sourceHint, artifactSha256, artifactBytes, parts, bundleRefsSha256, label, specTxid, publishedAt }) {
  const body = { bgit: 1, kind: 'git-bundle', repo }
  if (sourceHint) body.source_hint = sourceHint
  body.artifact_sha256 = artifactSha256
  body.artifact_bytes = artifactBytes
  body.parts = parts // [{ txid, sha256, bytes }] — order IS concatenation order
  body.bundle_refs_sha256 = bundleRefsSha256
  body.label = label
  body.claimable = true
  if (specTxid) body.spec = specTxid
  body.published_at = publishedAt
  return Buffer.from(JSON.stringify(body), 'utf8')
}

export function buildRefBody ({ repoId, seq, prev, artifactTxid, refsSha256, role = 'unsigned-mirror', claimHow = CLAIM_HOW }) {
  const body = {
    bgit: 1,
    repo_id: repoId,
    seq,
    prev,
    artifact: artifactTxid,
    refs_sha256: refsSha256,
    role,
  }
  // 7b7f878e: claim_how ONLY on unsigned mirrors — a maintainer ref must not advertise an
  // invitation that has already been exercised. null claimHow omits the field entirely.
  if (claimHow != null && role === 'unsigned-mirror') body.claim_how = claimHow
  return Buffer.from(JSON.stringify(body), 'utf8')
}

// ---------------------------------------------------------------------------
// git helpers — `git bundle verify` requires a repository (probed); wrap in a throwaway repo.
// ---------------------------------------------------------------------------
function withTmpRepo (fn) {
  const dir = mkdtempSync(join(tmpdir(), 'bgit-git-'))
  try {
    const init = spawnSync('git', ['init', '-q', dir], { encoding: 'utf8' })
    if (init.status !== 0) throw new Error(`git init failed: ${init.stderr}`)
    return fn(dir)
  } finally {
    try { rmSync(dir, { recursive: true, force: true }) } catch {}
  }
}

export function gitBundleVerify (bundlePath) {
  const abs = resolve(bundlePath)
  return withTmpRepo((repo) => {
    const r = spawnSync('git', ['-C', repo, 'bundle', 'verify', abs], { encoding: 'utf8' })
    return { ok: r.status === 0, output: `${r.stdout || ''}${r.stderr || ''}`.trim() }
  })
}

// §4: list-heads → "<sha1> <refname>" lines → sort lexicographically by refname (bytewise) →
// join '\n' (no trailing newline) → sha256.
export function bundleRefsSha256 (bundlePath) {
  const abs = resolve(bundlePath)
  const r = spawnSync('git', ['bundle', 'list-heads', abs], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  if (r.status !== 0) throw new Error(`git bundle list-heads failed: ${(r.stderr || '').trim()}`)
  const lines = r.stdout.split(/\r?\n/).filter((l) => l.length > 0)
  const entries = lines.map((line) => {
    const sp = line.indexOf(' ')
    if (sp < 0) throw new Error(`unparseable list-heads line: ${JSON.stringify(line)}`)
    return { line, refname: line.slice(sp + 1) }
  })
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.refname, 'utf8'), Buffer.from(b.refname, 'utf8')))
  return sha256hex(Buffer.from(entries.map((e) => e.line).join('\n'), 'utf8'))
}

// ---------------------------------------------------------------------------
// transaction construction
// ---------------------------------------------------------------------------
const UNLOCK_EST_BYTES = 108 // 1+73 (max DER+sighash byte) + 1+33 (pubkey) — upper bound

// Exact serialized size of one bgit tx given its record length (inputs/outputs fixed shape).
export function estimateTxSize (recordLen) {
  const pdLen = (n) => (n <= 0x4b ? 1 : n <= 0xff ? 2 : n <= 0xffff ? 3 : 5) + n
  const opretScript = 2 + pdLen(PROTOCOL_TAG.length) + pdLen(recordLen)
  const varlen = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5)
  const outOpret = 8 + varlen(opretScript) + opretScript
  const outP2pkh = 8 + 1 + 25
  return 4 /* version */ + 1 /* in count */ +
    (32 + 4 + varlen(UNLOCK_EST_BYTES) + UNLOCK_EST_BYTES + 4) +
    1 /* out count */ + outOpret + outP2pkh + outP2pkh + 4 /* locktime */
}

export const feeFor = (sizeBytes) => Math.max(1, Math.ceil((sizeBytes * FEE_RATE_SAT_PER_KB) / 1000))

// Build + sign one chained tx: [0] OP_RETURN record · [1] DUST_SATS → repo address · [2] change.
// Exported for claim.mjs — ONE tx builder, no second implementation (single-source law).
export async function buildTx ({ sdk, privKey, repoAddress, record, prev, changeSats }) {
  const { Transaction, P2PKH, Script } = sdk
  const lock = new P2PKH().lock(privKey.toAddress())
  const repoLock = new P2PKH().lock(repoAddress)
  const tx = new Transaction()
  tx.addInput({
    sourceTXID: prev.txid,
    sourceOutputIndex: prev.vout,
    unlockingScriptTemplate: new P2PKH().unlock(privKey, 'all', false, prev.satoshis, prev.lockingScript),
    sequence: 0xffffffff,
  })
  tx.addOutput({ lockingScript: Script.fromBinary(Array.from(recordScript(record))), satoshis: 0 })
  tx.addOutput({ lockingScript: repoLock, satoshis: DUST_SATS })
  tx.addOutput({ lockingScript: lock, satoshis: changeSats })
  await tx.sign()
  const hex = tx.toHex()
  return {
    txid: tx.id('hex'),
    hex,
    size: hex.length / 2,
    next: { txid: tx.id('hex'), vout: 2, satoshis: changeSats, lockingScript: lock },
  }
}

// Synthetic funding tx for the dry-run fixture chain: spends a fake outpoint, pays the
// publisher address the full plan amount. NEVER broadcastable (its input does not exist).
export function buildSyntheticFunding ({ sdk, privKey, satoshis }) {
  const { Transaction, P2PKH, Script } = sdk
  const fakeOutpoint = sha256hex(Buffer.from('bgit synthetic funding outpoint', 'ascii'))
  const tx = new Transaction()
  tx.addInput({ sourceTXID: fakeOutpoint, sourceOutputIndex: 0, unlockingScript: Script.fromBinary([]), sequence: 0xffffffff })
  const lock = new P2PKH().lock(privKey.toAddress())
  tx.addOutput({ lockingScript: lock, satoshis })
  return { txid: tx.id('hex'), hex: tx.toHex(), next: { txid: tx.id('hex'), vout: 0, satoshis, lockingScript: lock } }
}

// ---------------------------------------------------------------------------
// the publish pipeline
// ---------------------------------------------------------------------------
export async function runPublisher (opts) {
  const sdk = loadSdk()
  const { PrivateKey } = sdk

  const bundlePath = resolve(opts.bundle)
  if (!existsSync(bundlePath)) throw new Error(`bundle not found: ${bundlePath}`)
  const partBytes = opts.partBytes ?? DEFAULT_PART_BYTES
  if (!Number.isInteger(partBytes) || partBytes < 1 || partBytes > 99_000_000) throw new Error(`--part-bytes out of range: ${partBytes}`)

  // gate: refuse a bundle git itself refuses
  const verify = gitBundleVerify(bundlePath)
  if (!verify.ok) throw new Error(`REFUSED_BUNDLE_VERIFY: git bundle verify failed:\n${verify.output}`)

  // Key resolution: --key-file (the publisher-key.json shape, field `wif`) or --key <WIF>.
  // The wif is used in-process only and never echoed — keep it OUT of every log/report/error.
  let wif = opts.key
  if (!wif && opts.keyFile) {
    const kfPath = resolve(opts.keyFile)
    let kf
    try { kf = JSON.parse(readFileSync(kfPath, 'utf8')) } catch (e) { throw new Error(`--key-file unreadable: ${kfPath} (${e.message})`) }
    if (typeof kf.wif !== 'string' || kf.wif.length === 0) throw new Error(`--key-file has no usable "wif" field: ${kfPath}`)
    wif = kf.wif
  }
  if (!wif) throw new Error('need --key-file <publisher-key.json> (or --key <WIF>)')
  const privKey = PrivateKey.fromWif(wif)
  const signerAddress = privKey.toAddress()
  // genesis mode: publisher key IS the repo key (task law). --continue: the repo_id may belong
  // to a chain the signer does not own the funding of (a claimant extends someone's mirror).
  const repoAddress = opts.continue ? (opts.repoId || signerAddress) : signerAddress
  const signerPubkey = Buffer.from(privKey.toPublicKey().encode(true)).toString('hex')

  // ---- --continue: every continuation value derives from ONE immutable walk (7b7f878e) ----
  let cont = null
  if (opts.continue) {
    const snapOpts = { repoId: repoAddress, localIn: opts.chainIn, historyUrl: opts.historyUrl, txUrl: opts.txUrl, source: opts.source }
    const snap = await walkSnapshot(snapOpts)
    if (!snap.tipMined) throw new Error('TIP_UNMINED: the current tip is not mined — a continuation binding an unmined tip can become a permanent fork loser; wait for burial')
    const isGenesis = signerPubkey === snap.genesisPubkey
    if (!isGenesis && !snap.granted.has(signerPubkey)) {
      throw new Error('UNAUTHORIZED_KEY: this key is neither the genesis key nor an accepted claimant on this chain — the reader would reject the ref; refusing before any satoshi moves')
    }
    // role law (7b7f878e): claimant → FORCED maintainer; genesis chooses (validated) or
    // inherits the tip's role only when that role is itself well-formed.
    const ROLE_RE = /^[a-z][a-z0-9-]{0,31}$/
    let contRole
    if (!isGenesis) {
      if (opts.role && opts.role !== 'maintainer') throw new Error('USAGE: an accepted claimant publishes as role "maintainer" — the role is not selectable on a claimed chain')
      contRole = 'maintainer'
    } else if (opts.role) {
      if (!ROLE_RE.test(opts.role)) throw new Error('USAGE: --role must be lowercase [a-z][a-z0-9-]{0,31}')
      contRole = opts.role
    } else {
      contRole = ROLE_RE.test(snap.tipRole || '') ? snap.tipRole : 'unsigned-mirror'
    }
    cont = { snap, snapOpts, isGenesis, role: contRole, seq: snap.tipSeq + 1, prevRef: snap.tipTxid }
    process.stderr.write(`[bgit] --continue: tip seq=${snap.tipSeq} ${snap.tipTxid.slice(0, 12)}… → publishing seq=${cont.seq} as role "${contRole}" (${isGenesis ? 'genesis key' : 'accepted claimant'})\n`)
  }
  const refsDigest = bundleRefsSha256(bundlePath)

  const bundle = readFileSync(bundlePath)
  const artifactSha = sha256hex(bundle)
  const nParts = Math.ceil(bundle.length / partBytes)

  // part plan (shas up front; txids appear as txs are built)
  const partPlan = []
  for (let i = 0; i < nParts; i++) {
    const chunk = bundle.subarray(i * partBytes, Math.min((i + 1) * partBytes, bundle.length))
    partPlan.push({ index: i, bytes: chunk.length, sha256: sha256hex(chunk) })
  }

  // ---- fee plan (exact sizes; unlock estimated at max → paid rate ≥ floor) ----
  const publishedAt = opts.publishedAt || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  const label = opts.label || 'UNSIGNED MIRROR'

  // Manifest record sizes depend on their JSON bodies; part txids are 64-hex placeholders for
  // sizing (identical length to the real ones, so the plan is exact).
  const placeholderParts = partPlan.map((p) => ({ txid: '0'.repeat(64), sha256: p.sha256, bytes: p.bytes }))
  const artifactBodySize = buildArtifactBody({
    repo: opts.repo, sourceHint: opts.sourceHint, artifactSha256: artifactSha, artifactBytes: bundle.length,
    parts: placeholderParts, bundleRefsSha256: refsDigest, label, specTxid: opts.specTxid, publishedAt,
  }).length
  const refBodySize = buildRefBody({
    repoId: repoAddress,
    seq: cont ? cont.seq : 1,
    prev: cont ? cont.prevRef : null,
    artifactTxid: '0'.repeat(64),
    refsSha256: refsDigest,
    role: cont ? cont.role : 'unsigned-mirror',
  }).length
  const envelopeOverhead = (bodyLen) => 2 + encodeVarint(bodyLen).length + 1 + 33 + 1 + 72 // header+varint+0x21+pub+varint+maxDER

  const recordLens = [
    ...partPlan.map((p) => 2 + p.bytes),
    envelopeOverhead(artifactBodySize) + artifactBodySize,
    envelopeOverhead(refBodySize) + refBodySize,
  ]
  const plannedTxs = recordLens.map((len) => { const size = estimateTxSize(len); return { size, fee: feeFor(size) } })
  const totalFee = plannedTxs.reduce((a, t) => a + t.fee, 0)
  const nTx = plannedTxs.length
  const totalSats = totalFee + DUST_SATS * nTx + FINAL_CHANGE_SATS

  const plan = {
    spec: 'BGIT_WIRE_FORMAT_v1 (v1.3)',
    repo: opts.repo,
    repo_id: repoAddress,
    fund_address: signerAddress, // genesis: == repo_id. --continue: the SIGNING key gets funded
    ...(cont ? { continues: { from_seq: cont.snap.tipSeq, prev_ref: cont.prevRef, role: cont.role, snapshot_digest: cont.snap.digest } } : {}),
    bundle: bundlePath,
    artifact_bytes: bundle.length,
    artifact_sha256: artifactSha,
    bundle_refs_sha256: refsDigest,
    part_bytes_policy: partBytes,
    parts: nParts,
    tx_count: nTx,
    fee_rate_sat_per_kb: FEE_RATE_SAT_PER_KB,
    total_fee_sats: totalFee,
    dust_sats_total: DUST_SATS * nTx,
    final_change_sats: FINAL_CHANGE_SATS,
    total_sats_needed: totalSats,
    published_at: publishedAt,
  }

  // ---- construct the full chain ----
  let prev
  const files = []
  const outDir = opts.localOut ? resolve(opts.localOut) : null
  if (outDir) mkdirSync(outDir, { recursive: true })
  const writeTx = (name, role, built) => {
    const entry = { txid: built.txid, role, size: built.size ?? built.hex.length / 2 }
    if (outDir) {
      const file = `${name}.hex`
      writeFileSync(join(outDir, file), built.hex)
      entry.file = file
    }
    files.push(entry)
    return entry
  }

  if (opts.broadcast) {
    if (!opts.funding) throw new Error('--broadcast requires --funding <txid>:<vout>:<sats> (a real P2PKH outpoint paying the publisher address)')
    const m = /^([0-9a-fA-F]{64}):(\d+):(\d+)$/.exec(opts.funding)
    if (!m) throw new Error('--funding must be <txid>:<vout>:<sats>')
    const { P2PKH } = sdk
    prev = { txid: m[1].toLowerCase(), vout: Number(m[2]), satoshis: Number(m[3]), lockingScript: new P2PKH().lock(privKey.toAddress()) }
    if (prev.satoshis < totalSats) throw new Error(`funding outpoint has ${prev.satoshis} sats; plan needs ${totalSats}`)
    if (opts.continue) {
      // 7b7f878e: the funding outpoint must PROVABLY pay the signing key — verified from the
      // source, never assumed (a claimant funds a continuation from their own coin).
      const txTpl = opts.txUrl || (opts.source && SOURCE_PRESETS[opts.source] ? SOURCE_PRESETS[opts.source].txUrl : null)
      if (!txTpl) throw new Error('USAGE: --continue --broadcast needs --tx-url (or --source) to verify the funding outpoint before signing')
      const fres = await fetch(txTpl.replace('{txid}', prev.txid), { signal: AbortSignal.timeout(60_000) })
      if (!fres.ok) throw new Error(`FUNDING_UNREADABLE: funding tx fetch → HTTP ${fres.status}`)
      const ftx = sdk.Transaction.fromHex((await fres.text()).trim())
      const fout = ftx.outputs[prev.vout]
      if (!fout) throw new Error(`FUNDING_BAD_OUTPOINT: funding tx has no output ${prev.vout}`)
      if (fout.satoshis !== prev.satoshis) throw new Error(`FUNDING_VALUE_MISMATCH: outpoint holds ${fout.satoshis} sats, --funding says ${prev.satoshis}`)
      if (fout.lockingScript.toHex() !== new P2PKH().lock(signerAddress).toHex()) throw new Error('FUNDING_NOT_OURS: the funding outpoint does not pay the signing key')
    }
  } else {
    const funding = buildSyntheticFunding({ sdk, privKey, satoshis: totalSats })
    writeTx('tx-000-funding', 'funding(synthetic)', { txid: funding.txid, hex: funding.hex, size: funding.hex.length / 2 })
    prev = funding.next
  }

  const chainRecords = [] // ordered mined-order surrogate for the fixture chain (records only)
  const partEntries = []
  let txIdx = 0
  process.stderr.write(`[bgit] building ${nTx} transactions (${nParts} parts + 2 manifests)…\n`)
  for (let i = 0; i < nParts; i++) {
    const chunk = bundle.subarray(i * partBytes, Math.min((i + 1) * partBytes, bundle.length))
    const record = Buffer.concat([Buffer.from([FORMAT_VERSION, TYPE_PART]), chunk])
    const planned = plannedTxs[txIdx]
    const changeSats = prev.satoshis - DUST_SATS - planned.fee
    const built = await buildTx({ sdk, privKey, repoAddress, record, prev, changeSats })
    const entry = writeTx(`tx-${String(txIdx + 1).padStart(3, '0')}-part-${i}`, `part[${i}]`, built)
    entry.fee = prev.satoshis - DUST_SATS - changeSats
    partEntries.push({ txid: built.txid, sha256: partPlan[i].sha256, bytes: partPlan[i].bytes })
    chainRecords.push(entry)
    prev = built.next
    txIdx++
    if ((i + 1) % 5 === 0 || i === nParts - 1) process.stderr.write(`[bgit]   parts ${i + 1}/${nParts}\n`)
  }

  const artifactBody = buildArtifactBody({
    repo: opts.repo, sourceHint: opts.sourceHint, artifactSha256: artifactSha, artifactBytes: bundle.length,
    parts: partEntries, bundleRefsSha256: refsDigest, label, specTxid: opts.specTxid, publishedAt,
  })
  {
    const record = signedRecord(TYPE_ARTIFACT, artifactBody, privKey)
    const planned = plannedTxs[txIdx]
    const changeSats = prev.satoshis - DUST_SATS - planned.fee
    const built = await buildTx({ sdk, privKey, repoAddress, record, prev, changeSats })
    const entry = writeTx(`tx-${String(txIdx + 1).padStart(3, '0')}-artifact`, 'artifact-manifest', built)
    entry.fee = prev.satoshis - DUST_SATS - changeSats
    chainRecords.push(entry)
    plan.artifact_manifest_txid = built.txid
    prev = built.next
    txIdx++
  }

  const refBody = buildRefBody({
    repoId: repoAddress,
    seq: cont ? cont.seq : 1,
    prev: cont ? cont.prevRef : null,
    artifactTxid: plan.artifact_manifest_txid,
    refsSha256: refsDigest,
    role: cont ? cont.role : 'unsigned-mirror',
  })
  let refTxPrev = null // captured for the 7b7f878e mid-publish retarget (rebuild spends the same outpoint)
  {
    const record = signedRecord(TYPE_REF, refBody, privKey)
    const planned = plannedTxs[txIdx]
    const changeSats = prev.satoshis - DUST_SATS - planned.fee
    refTxPrev = prev
    const built = await buildTx({ sdk, privKey, repoAddress, record, prev, changeSats })
    const entry = writeTx(`tx-${String(txIdx + 1).padStart(3, '0')}-ref`, `ref-manifest(seq=${cont ? cont.seq : 1})`, built)
    entry.fee = prev.satoshis - DUST_SATS - changeSats
    chainRecords.push(entry)
    plan.ref_manifest_txid = built.txid
    txIdx++
  }

  if (outDir) {
    const chainJson = {
      format: 'bgit-local-chain-v1',
      note: 'LOCAL FIXTURE CHAIN — file order in `entries` is the mined-order surrogate. Not a spec artifact.',
      repo_id: repoAddress,
      entries: files.map((f) => ({ txid: f.txid, file: f.file, role: f.role })),
      plan,
    }
    writeFileSync(join(outDir, 'chain.json'), JSON.stringify(chainJson, null, 2))
  }

  // ---- plan report ----
  const lines = []
  lines.push('=== bgit publish plan (DRY RUN' + (opts.broadcast ? ' → BROADCAST' : '') + ') ===')
  lines.push(`spec:               ${plan.spec}`)
  lines.push(`repo:               ${plan.repo}`)
  lines.push(`repo_id:            ${plan.repo_id}`)
  // the funding address is the SIGNING key's, which is NOT the repo address when a claimant
  // continues someone else's chain — printing one label for both would misdirect real money
  lines.push(`fund THIS address:  ${plan.fund_address}${plan.fund_address === plan.repo_id ? '' : '  (the signing key, not the repo)'}`)
  lines.push(`bundle:             ${plan.bundle}`)
  lines.push(`artifact bytes:     ${plan.artifact_bytes.toLocaleString('en-US')}`)
  lines.push(`artifact sha256:    ${plan.artifact_sha256}`)
  lines.push(`bundle_refs_sha256: ${plan.bundle_refs_sha256}`)
  lines.push(`parts:              ${plan.parts} × ≤${partBytes.toLocaleString('en-US')} bytes`)
  lines.push(`transactions:       ${plan.tx_count} (${plan.parts} PART + 1 ARTIFACT MANIFEST + 1 REF MANIFEST seq=${cont ? cont.seq : 1}${cont ? `, role ${cont.role}, continuing ${cont.prevRef.slice(0, 12)}…` : ''})`)
  lines.push(`fee rate:           ${FEE_RATE_SAT_PER_KB} sat/KB`)
  lines.push(`total fee:          ${plan.total_fee_sats.toLocaleString('en-US')} sats`)
  lines.push(`dust (${DUST_SATS}/tx):        ${plan.dust_sats_total.toLocaleString('en-US')} sats`)
  lines.push(`final change:       ${plan.final_change_sats} sats`)
  lines.push(`TOTAL SATS NEEDED:  ${plan.total_sats_needed.toLocaleString('en-US')} sats  (fund ${plan.fund_address})`)
  lines.push(`artifact manifest:  ${plan.artifact_manifest_txid}`)
  lines.push(`ref manifest tip:   ${plan.ref_manifest_txid}`)
  lines.push('--- per-tx ---')
  for (const f of files) lines.push(`  ${f.txid}  ${String(f.size).padStart(9)} B  fee=${String(f.fee ?? 0).padStart(9)}  ${f.role}`)
  if (outDir) lines.push(`local fixture chain: ${outDir} (chain.json + ${files.length} hex files)`)
  if (!opts.broadcast) lines.push('NOT BROADCAST. This was a dry run (the default). Broadcast is human-gated: --broadcast --funding …')
  const report = lines.join('\n')
  console.log(report)

  // ---- broadcast (guarded, sequential, chained) ----
  if (opts.broadcast) {
    const bridges = opts.bridges?.length ? opts.bridges : DEFAULT_BRIDGES
    if (!bridges || !bridges.length) { console.error("bgit publisher: --bridge is REQUIRED for --broadcast (no default endpoint exists, by design — a broadcast target is always explicit; examples in README)"); process.exit(2) }
    const statePath = opts.state ? resolve(opts.state) : join(outDir || process.cwd(), 'publish-state.json')
    const state = {
      repo_id: repoAddress, created_at: new Date().toISOString(), bridges,
      txs: files.filter((f) => !f.role.startsWith('funding')).map((f) => ({ txid: f.txid, role: f.role, status: 'UNSENT' })),
    }
    writeFileSync(statePath, JSON.stringify(state, null, 2)) // record intent BEFORE the first send
    const posted = []
    let motionChecked = false
    for (const f of files) {
      if (f.role.startsWith('funding')) continue
      if (!outDir) throw new Error('broadcast requires --local-out (the constructed hex is read back from the fixture dir)')
      if (cont && !motionChecked) {
        // 7b7f878e: motion check BEFORE the first satoshi moves
        const s2 = await walkSnapshot(cont.snapOpts)
        if (s2.digest !== cont.snap.digest) throw new Error(`CHAIN_MOVED: the chain changed between plan and broadcast (tip ${cont.snap.tipTxid.slice(0, 12)}… → ${s2.tipTxid.slice(0, 12)}…) — nothing was sent; re-run --continue for a fresh plan`)
        motionChecked = true
      }
      let hex = loadVerifiedTxHex(outDir, f) // v1.3: refuse on any drift between plan and bytes
      if (cont && f.role.startsWith('ref-manifest')) {
        // 7b7f878e REQUIRED CHANGE: the tip can move WHILE parts/artifact broadcast, leaving
        // this REF a permanent fork loser after the sats are spent. Re-walk immediately before
        // the REF's POST; retarget when still lawful, refuse (stranded-honest) when not.
        const s3 = await walkSnapshot(cont.snapOpts)
        if (s3.digest !== cont.snap.digest) {
          const stillAuthorized = cont.isGenesis ? s3.genesisPubkey === signerPubkey : s3.granted.has(signerPubkey)
          if (!s3.tipMined || !stillAuthorized) {
            throw new Error(`CHAIN_MOVED: the chain moved mid-publish and the continuation is no longer lawful (${!s3.tipMined ? 'the new tip is unmined' : 'this key is no longer authorized at the tip'}). Already-posted data txs are honest PENDING strands, reusable by a fresh --continue: ${posted.join(', ') || '(none)'}`)
          }
          process.stderr.write(`[bgit] chain moved mid-publish — retargeting REF: seq ${cont.seq}→${s3.tipSeq + 1}, prev ${cont.prevRef.slice(0, 12)}…→${s3.tipTxid.slice(0, 12)}…\n`)
          const newBody = buildRefBody({ repoId: repoAddress, seq: s3.tipSeq + 1, prev: s3.tipTxid, artifactTxid: plan.artifact_manifest_txid, refsSha256: refsDigest, role: cont.role })
          const newRecord = signedRecord(TYPE_REF, newBody, privKey)
          const newFee = feeFor(estimateTxSize(newRecord.length))
          const rebuilt = await buildTx({ sdk, privKey, repoAddress, record: newRecord, prev: refTxPrev, changeSats: refTxPrev.satoshis - DUST_SATS - newFee })
          writeFileSync(join(outDir, f.file), rebuilt.hex)
          const oldRow = state.txs.find((t) => t.txid === f.txid)
          oldRow.status = 'SUPERSEDED(retarget)'
          oldRow.superseded_by = rebuilt.txid
          state.txs.push({ txid: rebuilt.txid, role: `ref-manifest(seq=${s3.tipSeq + 1},retargeted)`, status: 'UNSENT' })
          f.txid = rebuilt.txid
          f.role = `ref-manifest(seq=${s3.tipSeq + 1},retargeted)`
          plan.ref_manifest_txid = rebuilt.txid
          writeFileSync(statePath, JSON.stringify(state, null, 2))
          hex = loadVerifiedTxHex(outDir, f) // the drift gate re-proves the REBUILT bytes too
        }
      }
      const r = await broadcastOne(hex, bridges)
      const row = state.txs.find((t) => t.txid === f.txid)
      row.status = 'PENDING' // relay ack is NOT acceptance — only --confirm may promote (only-mined law)
      row.relay = r
      posted.push(f.txid)
      writeFileSync(statePath, JSON.stringify(state, null, 2))
      console.log(`PENDING ${f.txid} (${f.role}) — relay ack from ${r.bridge}; acceptance unknown until mined`)
    }
    console.log(`state: ${statePath}\nEvery txid above is PENDING. Run --confirm to check for mined acceptance.`)
  }

  return { plan, files, outDir }
}

// v1.3 (round-two): hash-verify the EXACT bytes about to be broadcast against the plan,
// immediately before POST. The fixture files are mutable disk state; a file edited (or corrupted)
// between construction and send must REFUSE, never silently broadcast something the plan did not
// name. txid = reversed double-sha256 of the raw bytes — recomputed here, required equal.
export function loadVerifiedTxHex (dir, entry) {
  const hex = readFileSync(join(dir, entry.file), 'utf8').trim()
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`BROADCAST_BYTES_MISMATCH: ${entry.file} is not clean transaction hex — refusing to broadcast`)
  }
  const raw = Buffer.from(hex, 'hex')
  const actual = sha256(sha256(raw)).reverse().toString('hex')
  if (actual !== entry.txid) {
    throw new Error(`BROADCAST_BYTES_MISMATCH: ${entry.file} hashes to ${actual} but the plan says ${entry.txid} — the fixture changed after construction; refusing to broadcast`)
  }
  return hex
}

export async function broadcastOne (rawTxHex, bridges) {
  let lastErr = null
  for (const url of bridges) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawTx: rawTxHex }),
        signal: AbortSignal.timeout(120_000),
      })
      const text = await res.text().catch(() => '')
      if (res.ok) return { bridge: url, http: res.status, body: text.slice(0, 300) }
      if (res.status === 422) { // the network's verdict, terminal — never walk to the next bridge
        const err = new Error(`BROADCAST_VERDICT from ${url}: ${text.slice(0, 200)}`)
        err.terminal = true
        throw err
      }
      lastErr = new Error(`${url}: HTTP ${res.status} ${text.slice(0, 120)}`)
    } catch (e) {
      if (e.terminal) throw e
      lastErr = e
    }
  }
  throw lastErr || new Error('no bridge reachable')
}

// ---------------------------------------------------------------------------
// --confirm: the only path that may print "accepted" (only-mined-promotes)
// ---------------------------------------------------------------------------
export async function runConfirm (opts) {
  const statePath = resolve(opts.state || 'publish-state.json')
  const state = JSON.parse(readFileSync(statePath, 'utf8'))
  const tpl = opts.statusUrl || DEFAULT_STATUS_URL
  if (!tpl) { console.error("bgit publisher: --status-url is REQUIRED for --confirm (no default, by design; examples in README)"); process.exit(2) }
  let mined = 0; let pending = 0; let unknown = 0
  for (const t of state.txs) {
    const url = tpl.replace('{txid}', t.txid)
    let verdict = 'UNKNOWN'
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(30_000) })
      if (res.ok) {
        const s = await res.json()
        // Height field spellings differ per source and NONE of them are wrong: WhatsOnChain
        // says `blockheight`, our own bridge says `height`, others say `blockHeight`. Reading
        // only one spelling made this pass report NOT_SEEN for demonstrably mined transactions
        // (caught 2026-08-16 on the randomx/supercop publishes) — a verifier that cannot
        // recognise success is not a verifier. Unmined sources signal with 0, -1, or null;
        // only a positive integer is a burial.
        const raw = [s.blockHeight, s.blockheight, s.block_height, s.height]
          .find((v) => typeof v === 'number' && Number.isFinite(v))
        const h = typeof raw === 'number' && raw > 0 ? raw : null
        if (h !== null) { verdict = `MINED@${h}`; t.status = 'ACCEPTED'; t.blockHeight = h; mined++ } else if (s.inMempool || s.exists || s.confirmations === 0 || raw === -1 || raw === 0) { verdict = 'PENDING(mempool)'; pending++ } else { verdict = 'NOT_SEEN'; unknown++ }
      } else unknown++
    } catch { unknown++ }
    console.log(`${verdict.padEnd(16)} ${t.txid}  ${t.role}`)
  }
  writeFileSync(statePath, JSON.stringify(state, null, 2))
  console.log(`\naccepted(mined): ${mined} · pending: ${pending} · unknown/not-seen: ${unknown}`)
  if (unknown > 0) console.log('UNKNOWN is not "rejected" — an unreachable or blind source proves nothing; re-run and cross-check a second source.')
  return { mined, pending, unknown }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs (argv) {
  const o = { bridges: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    const next = () => { const v = argv[++i]; if (v === undefined) throw new Error(`missing value for ${a}`); return v }
    switch (a) {
      case '--bundle': o.bundle = next(); break
      case '--repo': o.repo = next(); break
      case '--key': o.key = next(); break
      case '--key-file': o.keyFile = next(); break
      case '--part-bytes': o.partBytes = Number(next()); break
      case '--local-out': o.localOut = next(); break
      case '--source-hint': o.sourceHint = next(); break
      case '--spec-txid': o.specTxid = next(); break
      case '--label': o.label = next(); break
      case '--published-at': o.publishedAt = next(); break
      case '--broadcast': o.broadcast = true; break
      case '--funding': o.funding = next(); break
      case '--bridge': o.bridges.push(next()); break
      case '--state': o.state = next(); break
      case '--continue': o.continue = true; break
      case '--repo-id': o.repoId = next(); break
      case '--chain-in': o.chainIn = next(); break
      case '--history-url': o.historyUrl = next(); break
      case '--tx-url': o.txUrl = next(); break
      case '--source': o.source = next(); break
      case '--role': o.role = next(); break
      case '--status-url': o.statusUrl = next(); break
      case '--confirm': o.confirm = true; break
      default: throw new Error(`unknown flag: ${a}`)
    }
  }
  return o
}

const isMain = (() => {
  try { return process.argv[1] && pathToFileURL(resolve(process.argv[1])).href.toLowerCase() === import.meta.url.toLowerCase() } catch { return false }
})()

if (isMain) {
  (async () => {
    const o = parseArgs(process.argv.slice(2))
    if (o.confirm) { await runConfirm(o); return }
    if (!o.bundle || !o.repo || (!o.key && !o.keyFile)) {
      console.error('usage: publisher.mjs --bundle <path> --repo <name> --key-file <publisher-key.json> [--part-bytes n] [--local-out dir] [--broadcast --funding txid:vout:sats] | --confirm --state <file>')
      process.exit(1)
    }
    await runPublisher(o)
  })().catch((e) => { console.error(`bgit publisher: ${e.message}`); process.exit(e.message?.startsWith('REFUSED') ? 2 : 1) })
}
