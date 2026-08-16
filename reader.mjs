#!/usr/bin/env node
// bgit reader — the independent reconstruction tool (BGIT_WIRE_FORMAT_v1.md §6, normative).
//
// DISCIPLINE: this file is a SPEC AUDIT. It is implemented from §6 + the §2/§3 record
// definitions ALONE, as a stranger who found the document would implement it. Every place the
// spec under-specifies, the choice made here is tagged `SPEC-AMBIGUITY[n]` and catalogued in
// README.md — those findings feed the round-two review. The only external machinery used is a
// secp256k1 library (ECDSA verify + base58check decode) and stock git, exactly as §0.2 permits.
//
//   node reader.mjs --repo-id <address> --local-in <dir>            --out <file.bundle>
//   node reader.mjs --repo-id <address> --source woc|indelible      --out <file.bundle>
//   node reader.mjs --repo-id <address> --history-url <tpl> --tx-url <tpl> --out <file.bundle>
//
// Any verification mismatch → loud typed refusal (`BGIT_REFUSED <CODE>`), non-zero exit,
// never a partial artifact (output is written to a .part temp and renamed only on full success).

import { createRequire } from 'node:module'
import { createHash } from 'node:crypto'
import {
  readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync, openSync, writeSync, closeSync,
  renameSync, unlinkSync,
} from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'

// ---------------------------------------------------------------------------
// constants from the spec
// ---------------------------------------------------------------------------
const SIGN_PREFIX = Buffer.from('bgit1|', 'ascii') // §3 v1.3: SHA256("bgit1|" || VERSION || TYPE || body_bytes)
const TAG = Buffer.from('bgit', 'ascii')           // §1
const V1 = 0x01
const T_PART = 0x01
const T_ARTIFACT = 0x02
const T_REF = 0x03
const T_CLAIM = 0x06
const KNOWN_TYPES = new Set([T_PART, T_ARTIFACT, T_REF, T_CLAIM])

// §3 says "parsers MUST enforce a size bound before parsing" but names no number.
// SPEC-AMBIGUITY[5]: bound chosen at 1 MiB for signed JSON bodies (real manifests are ~4 KB).
export const MAX_SIGNED_BODY = 1_048_576

// secp256k1 group order (for low-S and range checks — hand-rolled, not delegated to the lib).
const CURVE_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
const HALF_N = CURVE_N >> 1n

// Presets for the two documented public source families. Independence law (§0.2): neither is
// REQUIRED — any address-history + raw-tx source works via --history-url/--tx-url templates.
export const SOURCE_PRESETS = {
  woc: {
    historyUrl: 'https://api.whatsonchain.com/v1/bsv/main/address/{address}/history',
    txUrl: 'https://api.whatsonchain.com/v1/bsv/main/tx/{txid}/hex',
  },
  indelible: {
    historyUrl: null, // REQUIRED — pass any address-history source (examples in README)
    txUrl: null, // REQUIRED — pass any raw-tx source (examples in README)
  },
}

// ---------------------------------------------------------------------------
// crypto library loader (verify-only usage)
// ---------------------------------------------------------------------------
let _sdk = null
function loadSdk () {
  if (_sdk) return _sdk
  const here = dirname(fileURLToPath(import.meta.url))
  const candidates = [
    process.env.BGIT_SDK_DIR, here, resolve(here, '..', 'mcp-server'), process.cwd(), resolve(process.cwd(), 'mcp-server'),
  ].filter(Boolean)
  const errors = []
  for (const dir of candidates) {
    try { _sdk = createRequire(join(dir, '__bgit_resolve__.js'))('@bsv/sdk'); return _sdk } catch (e) { errors.push(`${dir}: ${e.code || e.message}`) }
  }
  throw new Error(`secp256k1 library (@bsv/sdk) not resolvable (set BGIT_SDK_DIR):\n  ${errors.join('\n  ')}`)
}

const sha256 = (buf) => createHash('sha256').update(buf).digest()
const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex')
const dsha256 = (buf) => sha256(sha256(buf))

// ---------------------------------------------------------------------------
// raw transaction parsing (standard BSV serialization; hand-rolled, bounds-checked)
// ---------------------------------------------------------------------------
class Cursor {
  constructor (buf) { this.buf = buf; this.o = 0 }
  need (n) { if (this.o + n > this.buf.length) throw new Error(`tx truncated at ${this.o}+${n}/${this.buf.length}`) }
  u32 () { this.need(4); const v = this.buf.readUInt32LE(this.o); this.o += 4; return v }
  u64 () { this.need(8); const v = this.buf.readBigUInt64LE(this.o); this.o += 8; return Number(v) }
  bytes (n) { this.need(n); const v = this.buf.subarray(this.o, this.o + n); this.o += n; return v }
  varint () {
    this.need(1); const b = this.buf[this.o++]
    if (b < 0xfd) return b
    if (b === 0xfd) { this.need(2); const v = this.buf.readUInt16LE(this.o); this.o += 2; return v }
    if (b === 0xfe) { this.need(4); const v = this.buf.readUInt32LE(this.o); this.o += 4; return v }
    this.need(8); const v = Number(this.buf.readBigUInt64LE(this.o)); this.o += 8; return v
  }
}

export function parseRawTx (buf) {
  const c = new Cursor(buf)
  const version = c.u32()
  const nIn = c.varint()
  const inputs = []
  for (let i = 0; i < nIn; i++) {
    const txid = Buffer.from(c.bytes(32)).reverse().toString('hex')
    const vout = c.u32()
    const slen = c.varint()
    c.bytes(slen)
    const sequence = c.u32()
    inputs.push({ txid, vout, sequence })
  }
  const nOut = c.varint()
  const outputs = []
  for (let i = 0; i < nOut; i++) {
    const satoshis = c.u64()
    const slen = c.varint()
    outputs.push({ satoshis, script: Buffer.from(c.bytes(slen)) })
  }
  const locktime = c.u32()
  if (c.o !== buf.length) throw new Error(`tx has ${buf.length - c.o} trailing bytes`)
  return { txid: Buffer.from(dsha256(buf)).reverse().toString('hex'), version, inputs, outputs, locktime }
}

// ---------------------------------------------------------------------------
// bgit output extraction (§1)
// ---------------------------------------------------------------------------
// Parse script pushdatas from an offset. Accepts all four explicit push forms (0x01–0x4b,
// PUSHDATA1/2/4) plus OP_0 as an empty push.
// SPEC-AMBIGUITY[2]: §1 never says whether non-minimal push encodings conform; read-old-forever
// (§0.1) argues for tolerance on read — all four forms are accepted regardless of minimality.
function readPushes (script, offset) {
  const pushes = []
  let o = offset
  while (o < script.length) {
    const op = script[o++]
    let len = null
    if (op === 0x00) { pushes.push(Buffer.alloc(0)); continue }
    if (op >= 0x01 && op <= 0x4b) len = op
    else if (op === 0x4c) { if (o + 1 > script.length) return null; len = script[o]; o += 1 }
    else if (op === 0x4d) { if (o + 2 > script.length) return null; len = script.readUInt16LE(o); o += 2 }
    else if (op === 0x4e) { if (o + 4 > script.length) return null; len = script.readUInt32LE(o); o += 4 }
    else return null // a non-push opcode inside an OP_RETURN payload → not the §1 shape
    if (o + len > script.length) return null
    pushes.push(script.subarray(o, o + len))
    o += len
  }
  return pushes
}

// Classify one output. Returns:
//   { tagged: true, record: Buffer }        — conforming §1 shape (exactly 2 pushes, tag first)
//   { tagged: true, record: null }          — first pushdata is `bgit` but shape malformed
//   null                                    — not a bgit-tagged OP_FALSE OP_RETURN output
// The multi-output counting rule (§1/§6.1) keys on `tagged`, NOT on full conformance — an
// adversary must not be able to smuggle a second bgit output past the count by malforming it.
export function classifyOutput (script) {
  if (script.length < 2 || script[0] !== 0x00 || script[1] !== 0x6a) return null
  const pushes = readPushes(script, 2)
  if (pushes === null || pushes.length === 0 || !pushes[0].equals(TAG)) {
    // Unparseable pushes: if the first decodable pushdata literally equals the tag we count it;
    // readPushes(null) means we could not even establish the first push — treat as untagged.
    return null
  }
  // SPEC-AMBIGUITY[3]: §1 shows exactly two pushdatas; extra pushes after the record are not
  // defined. Chosen: tagged-but-malformed (counts toward the multi-output rule, carries no record).
  if (pushes.length !== 2) return { tagged: true, record: null }
  return { tagged: true, record: Buffer.from(pushes[1]) }
}

// ---------------------------------------------------------------------------
// envelope + signature verification (§2, §3) — the independent verify path
// ---------------------------------------------------------------------------
// Canonical CompactSize varint read; rejects non-canonical encodings.
// SPEC-AMBIGUITY[1]: "varint" is undefined in the spec. Chosen: Bitcoin CompactSize, and
// non-canonical encodings are rejected (two encodings of one length = malleable records).
function readCanonicalVarint (buf, o) {
  if (o >= buf.length) return { err: 'BAD_VARINT' }
  const b = buf[o]
  if (b < 0xfd) return { value: b, size: 1 }
  if (b === 0xfd) {
    if (o + 3 > buf.length) return { err: 'BAD_VARINT' }
    const v = buf.readUInt16LE(o + 1)
    if (v < 0xfd) return { err: 'BAD_VARINT' }
    return { value: v, size: 3 }
  }
  if (b === 0xfe) {
    if (o + 5 > buf.length) return { err: 'BAD_VARINT' }
    const v = buf.readUInt32LE(o + 1)
    if (v <= 0xffff) return { err: 'BAD_VARINT' }
    return { value: v, size: 5 }
  }
  if (o + 9 > buf.length) return { err: 'BAD_VARINT' }
  const v = buf.readBigUInt64LE(o + 1)
  if (v <= 0xffffffffn || v > BigInt(Number.MAX_SAFE_INTEGER)) return { err: 'BAD_VARINT' }
  return { value: Number(v), size: 9 }
}

// Strict DER + low-S enforcement, hand-rolled per §3's explicit verification rules.
export function strictDerCheck (sig) {
  const fail = (code) => ({ ok: false, code })
  if (sig.length < 8 || sig.length > 72) return fail('NON_STRICT_DER')
  if (sig[0] !== 0x30) return fail('NON_STRICT_DER')
  if (sig[1] >= 0x80) return fail('NON_STRICT_DER')          // long-form length forbidden
  if (sig[1] !== sig.length - 2) return fail('NON_STRICT_DER')
  let o = 2
  const readInt = () => {
    if (o + 2 > sig.length || sig[o] !== 0x02) return null
    const len = sig[o + 1]
    if (len === 0 || len >= 0x80 || o + 2 + len > sig.length) return null
    const bytes = sig.subarray(o + 2, o + 2 + len)
    if (bytes[0] & 0x80) return null                          // negative → not a valid positive int
    if (len > 1 && bytes[0] === 0x00 && !(bytes[1] & 0x80)) return null // non-minimal padding
    o += 2 + len
    return BigInt('0x' + Buffer.from(bytes).toString('hex'))
  }
  const r = readInt(); if (r === null) return fail('NON_STRICT_DER')
  const s = readInt(); if (s === null) return fail('NON_STRICT_DER')
  if (o !== sig.length) return fail('NON_STRICT_DER')
  if (r <= 0n || r >= CURVE_N || s <= 0n || s >= CURVE_N) return fail('SIG_RANGE')
  if (s > HALF_N) return fail('HIGH_S')
  return { ok: true, r, s }
}

// ---------------------------------------------------------------------------
// strict JSON constraints (§3): UTF-8 only · duplicate keys REJECTED · integers only within
// 2^53−1. JSON.parse silently dedupes keys, so a scanning pass runs FIRST.
// SPEC-AMBIGUITY[6]: duplicate-key comparison is done on the ESCAPE-DECODED key at every
// nesting depth ("body" duplicates "body"); the spec does not say which representation.
// SPEC-AMBIGUITY[7]: the top level is required to be a JSON object (every §3 body is one).
// ---------------------------------------------------------------------------
export function scanStrictJson (bodyBuf) {
  let text
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bodyBuf) } catch { return { ok: false, code: 'INVALID_UTF8' } }
  const fail = (code, detail) => ({ ok: false, code, detail })
  let i = 0
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++ }
  const parseString = () => {
    // returns decoded string or null on malformed (JSON.parse will name it later)
    if (text[i] !== '"') return null
    i++
    let out = ''
    while (i < text.length) {
      const ch = text[i]
      if (ch === '"') { i++; return out }
      if (ch === '\\') {
        const e = text[i + 1]
        if (e === 'u') {
          const hex = text.slice(i + 2, i + 6)
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) return null
          out += String.fromCharCode(parseInt(hex, 16))
          i += 6
        } else {
          const map = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
          if (!(e in map)) return null
          out += map[e]
          i += 2
        }
      } else { out += ch; i++ }
    }
    return null
  }
  const parseNumber = () => {
    const start = i
    if (text[i] === '-') i++
    while (i < text.length && /[0-9]/.test(text[i])) i++
    const intEnd = i
    let fractional = false
    if (text[i] === '.') { fractional = true; i++; while (i < text.length && /[0-9]/.test(text[i])) i++ }
    if (text[i] === 'e' || text[i] === 'E') { fractional = true; i++; if (text[i] === '+' || text[i] === '-') i++; while (i < text.length && /[0-9]/.test(text[i])) i++ }
    const raw = text.slice(start, i)
    if (fractional) return { err: 'NON_INTEGER_NUMBER', raw }
    let big
    try { big = BigInt(text.slice(start, intEnd)) } catch { return { err: 'NON_INTEGER_NUMBER', raw } }
    if (big > 9007199254740991n || big < -9007199254740991n) return { err: 'INTEGER_OUT_OF_RANGE', raw }
    return { ok: true }
  }
  const parseValue = (depth) => {
    if (depth > 64) return fail('JSON_PARSE', 'nesting too deep')
    ws()
    const ch = text[i]
    if (ch === '{') {
      i++
      const seen = new Set()
      ws()
      if (text[i] === '}') { i++; return null }
      for (;;) {
        ws()
        const key = parseString()
        if (key === null) return fail('JSON_PARSE', 'bad object key')
        if (seen.has(key)) return fail('DUPLICATE_KEY', key)
        seen.add(key)
        ws()
        if (text[i] !== ':') return fail('JSON_PARSE', 'missing colon')
        i++
        const err = parseValue(depth + 1)
        if (err) return err
        ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === '}') { i++; return null }
        return fail('JSON_PARSE', 'bad object separator')
      }
    }
    if (ch === '[') {
      i++
      ws()
      if (text[i] === ']') { i++; return null }
      for (;;) {
        const err = parseValue(depth + 1)
        if (err) return err
        ws()
        if (text[i] === ',') { i++; continue }
        if (text[i] === ']') { i++; return null }
        return fail('JSON_PARSE', 'bad array separator')
      }
    }
    if (ch === '"') { return parseString() === null ? fail('JSON_PARSE', 'bad string') : null }
    if (ch === '-' || /[0-9]/.test(ch || '')) { const n = parseNumber(); return n.err ? fail(n.err, n.raw) : null }
    if (text.startsWith('true', i)) { i += 4; return null }
    if (text.startsWith('false', i)) { i += 5; return null }
    if (text.startsWith('null', i)) { i += 4; return null }
    return fail('JSON_PARSE', `unexpected ${JSON.stringify(ch)} at ${i}`)
  }
  ws()
  if (text[i] !== '{') return fail('BODY_NOT_OBJECT')
  const err = parseValue(0)
  if (err) return err
  ws()
  if (i !== text.length) return fail('JSON_PARSE', 'trailing content')
  let value
  try { value = JSON.parse(text) } catch (e) { return fail('JSON_PARSE', e.message) }
  return { ok: true, value }
}

// Full §2/§3 validation of one signed-envelope record body (bytes AFTER the 2-byte header).
// Order: envelope structure → size bound (BEFORE any JSON work) → pubkey/DER strictness →
// signature over the LITERAL extracted body bytes → JSON constraints → parse.
// v1.3 (A2): the preimage binds the OBSERVED envelope version and type bytes —
//   SHA256("bgit1|" || VERSION_BYTE || TYPE_BYTE || body_bytes)
// — so the caller MUST pass the version/type bytes exactly as extracted from the transaction.
// A flipped type byte now fails the signature itself; typed-body validation is defense in depth.
export function validateSignedRecord (envBuf, { version = 0x01, type, maxBody = MAX_SIGNED_BODY } = {}) {
  if (!Number.isInteger(type)) throw new Error('validateSignedRecord: the observed TYPE byte is required (v1.3 preimage binds it)')
  const fail = (code, detail) => ({ ok: false, code, detail })
  const vl = readCanonicalVarint(envBuf, 0)
  if (vl.err) return fail(vl.err)
  const bodyLen = vl.value
  if (bodyLen > maxBody) return fail('OVERSIZE_BODY', `${bodyLen} > ${maxBody}`) // before parsing anything
  let o = vl.size
  if (o + bodyLen > envBuf.length) return fail('BAD_VARINT', 'body_len exceeds record')
  const body = envBuf.subarray(o, o + bodyLen)
  o += bodyLen
  if (o >= envBuf.length || envBuf[o] !== 0x21) return fail('PUBKEY_NOT_COMPRESSED', `pubkey length prefix 0x${(envBuf[o] ?? 0).toString(16)}`)
  o += 1
  if (o + 33 > envBuf.length) return fail('PUBKEY_NOT_COMPRESSED', 'truncated pubkey')
  const pub = envBuf.subarray(o, o + 33)
  if (pub[0] !== 0x02 && pub[0] !== 0x03) return fail('PUBKEY_NOT_COMPRESSED', `prefix 0x${pub[0].toString(16)}`)
  o += 33
  const sl = readCanonicalVarint(envBuf, o)
  if (sl.err) return fail(sl.err, 'sig_len')
  o += sl.size
  if (o + sl.value > envBuf.length) return fail('BAD_VARINT', 'sig_len exceeds record')
  const sig = envBuf.subarray(o, o + sl.value)
  o += sl.value
  // SPEC-AMBIGUITY[4]: bytes after the signature are undefined; chosen: rejected (they are not
  // covered by the signature, so tolerating them makes records malleable in flight).
  if (o !== envBuf.length) return fail('TRAILING_BYTES', `${envBuf.length - o} bytes after signature`)

  const der = strictDerCheck(sig)
  if (!der.ok) return fail(der.code)

  // signature over the LITERAL body bytes (§3: never re-serialize to check), with the observed
  // version+type bytes bound into the preimage (v1.3)
  const sdk = loadSdk()
  const digest = sha256hex(Buffer.concat([SIGN_PREFIX, Buffer.from([version, type]), body]))
  let verified = false
  try {
    verified = sdk.ECDSA.verify(
      new sdk.BigNumber(digest, 16),
      sdk.Signature.fromDER(Array.from(sig)),
      sdk.PublicKey.fromString(Buffer.from(pub).toString('hex')),
    )
  } catch { verified = false }
  if (!verified) return fail('SIG_INVALID')

  const scan = scanStrictJson(body)
  if (!scan.ok) return fail(scan.code, scan.detail)
  return { ok: true, body: Buffer.from(body), json: scan.value, pubkey: Buffer.from(pub).toString('hex'), sig: Buffer.from(sig).toString('hex') }
}

// ---------------------------------------------------------------------------
// field validation per record type
// ---------------------------------------------------------------------------
const isHex64 = (v) => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v)
const lc = (v) => (typeof v === 'string' ? v.toLowerCase() : v)

// SPEC-AMBIGUITY[9]: every §3 body carries `"bgit": 1` but no rule says to check it. Chosen:
// required === 1 on typed records (it is the version pin inside the SIGNED bytes; the envelope
// version byte is outside the signature).
function checkRefFields (json, repoId) {
  if (json.bgit !== 1) return 'FIELD_INVALID:bgit'
  if (json.repo_id !== repoId) return 'REPO_ID_MISMATCH'
  if (!Number.isInteger(json.seq) || json.seq < 1) return 'FIELD_INVALID:seq'
  if (json.seq === 1 ? json.prev !== null : !isHex64(json.prev)) return 'FIELD_INVALID:prev' // §3 "null iff seq == 1"
  if (!isHex64(json.artifact)) return 'FIELD_INVALID:artifact'
  if (!isHex64(json.refs_sha256)) return 'FIELD_INVALID:refs_sha256'
  return null
}
function checkClaimFields (json, repoId, envelopePubkey) {
  if (json.bgit !== 1) return 'FIELD_INVALID:bgit'
  if (json.repo_id !== repoId) return 'REPO_ID_MISMATCH'
  if (typeof json.maintainer_pubkey !== 'string' || !/^[0-9a-fA-F]{66}$/.test(json.maintainer_pubkey)) return 'FIELD_INVALID:maintainer_pubkey'
  if (lc(json.maintainer_pubkey) !== lc(envelopePubkey)) return 'CLAIM_KEY_MISMATCH' // §3: "Signed by maintainer_pubkey"
  if (!isHex64(json.target_ref)) return 'FIELD_INVALID:target_ref'
  return null
}
function checkArtifactFields (json) {
  if (json.bgit !== 1) return 'FIELD_INVALID:bgit'
  if (!isHex64(json.artifact_sha256)) return 'FIELD_INVALID:artifact_sha256'
  if (!Number.isInteger(json.artifact_bytes) || json.artifact_bytes < 0) return 'FIELD_INVALID:artifact_bytes'
  if (!Array.isArray(json.parts) || json.parts.length === 0) return 'FIELD_INVALID:parts'
  for (const p of json.parts) {
    if (typeof p !== 'object' || p === null || !isHex64(p.txid) || !isHex64(p.sha256) || !Number.isInteger(p.bytes) || p.bytes < 0) return 'FIELD_INVALID:parts[]'
  }
  if (!isHex64(json.bundle_refs_sha256)) return 'FIELD_INVALID:bundle_refs_sha256'
  return null
}

// ---------------------------------------------------------------------------
// §6.1 — the walk: collect records from mined-ordered transactions
// ---------------------------------------------------------------------------
function p2pkhScriptFor (address) {
  const sdk = loadSdk()
  const dec = sdk.Utils.fromBase58Check(address)
  const h160 = Buffer.from(dec.data)
  if (h160.length !== 20) throw new Error(`repo-id does not decode to a 20-byte hash160: ${address}`)
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h160, Buffer.from([0x88, 0xac])])
}

export function collectRecords (txs, repoId) {
  const repoScript = p2pkhScriptFor(repoId)
  const paysRepo = (tx) => tx.outputs.some((out) => out.script.equals(repoScript) && out.satoshis >= 1)
  const out = {
    refs: [], claims: [], artifacts: new Map(), parts: new Map(),
    skipped: [], rejected: [], ignoredMultiOutput: [], nonRecordTxs: 0, pendingTxs: [],
  }
  let minedIdx = 0
  for (const { raw, mined = true, sourceTxid, height = null } of txs) {
    const h = typeof height === 'number' && height > 0 ? height : null
    let tx
    try { tx = parseRawTx(raw) } catch (e) { out.rejected.push({ txid: sourceTxid || '?', code: 'TX_UNPARSEABLE', detail: e.message }); continue }
    if (sourceTxid && lc(sourceTxid) !== tx.txid) {
      out.rejected.push({ txid: tx.txid, code: 'SOURCE_TXID_MISMATCH', detail: `source declared ${sourceTxid}` })
      continue
    }
    const tagged = []
    for (let vout = 0; vout < tx.outputs.length; vout++) {
      const c = classifyOutput(tx.outputs[vout].script)
      if (c) tagged.push({ vout, record: c.record })
    }
    if (tagged.length === 0) { out.nonRecordTxs++; continue }
    if (tagged.length > 1) { out.ignoredMultiOutput.push({ txid: tx.txid, code: 'MULTI_BGIT_OUTPUT', outputs: tagged.map((t) => t.vout) }); continue } // §6.1: whole tx ignored
    if (!mined) { out.pendingTxs.push(tx.txid) } // §3.5/§6.6: PENDING, never the tip
    const record = tagged[0].record
    if (record === null) { out.rejected.push({ txid: tx.txid, code: 'MALFORMED_OUTPUT' }); continue }
    if (record.length < 2) { out.rejected.push({ txid: tx.txid, code: 'MALFORMED_OUTPUT', detail: 'record shorter than the §2 header' }); continue }
    const version = record[0]
    const type = record[1]
    if (version !== V1) { out.skipped.push({ txid: tx.txid, code: 'UNKNOWN_VERSION', version }); continue }   // §2: skip, report, never error
    if (!KNOWN_TYPES.has(type)) { out.skipped.push({ txid: tx.txid, code: 'UNKNOWN_TYPE', type }); continue } // §2: reserved/unknown → skip
    if (!mined) continue // recorded PENDING above; an unmined record never enters selection

    // §5 (v1.3, round-two): dust-to-repo is ENFORCED on ALL FOUR record types — a bgit record in
    // a transaction paying nothing to the walked repo address is rejected, PART and ARTIFACT
    // included. (The earlier REF/CLAIM-only asymmetry — SPEC-AMBIGUITY[11] — was overturned by
    // the spec, cured here in the reader, not the law.) Unknown versions/types stay SKIPPED
    // above per §2's never-error rule; the dust law applies to conforming v1 records.
    if (!paysRepo(tx)) { out.rejected.push({ txid: tx.txid, code: 'NOT_PAYING_REPO', type }); minedIdx++; continue }

    if (type === T_PART) {
      out.parts.set(tx.txid, { txid: tx.txid, minedIdx, height: h, bytes: record.length - 2 }) // body re-read at reassembly
      minedIdx++
      continue
    }
    const env = validateSignedRecord(record.subarray(2), { version, type })
    if (!env.ok) { out.rejected.push({ txid: tx.txid, code: env.code, detail: env.detail, type }); minedIdx++; continue }
    if (type === T_REF) {
      const ferr = checkRefFields(env.json, repoId)
      if (ferr) { out.rejected.push({ txid: tx.txid, code: ferr, type }) } else {
        out.refs.push({
          txid: tx.txid, minedIdx, height: h, seq: env.json.seq, prev: env.json.prev === null ? null : lc(env.json.prev),
          artifact: lc(env.json.artifact), refs_sha256: lc(env.json.refs_sha256), role: env.json.role,
          pubkey: env.pubkey, json: env.json,
        })
      }
    } else if (type === T_ARTIFACT) {
      const ferr = checkArtifactFields(env.json)
      if (ferr) { out.rejected.push({ txid: tx.txid, code: ferr, type }) } else {
        out.artifacts.set(tx.txid, { txid: tx.txid, minedIdx, height: h, json: env.json, pubkey: env.pubkey })
      }
    } else if (type === T_CLAIM) {
      const ferr = checkClaimFields(env.json, repoId, env.pubkey)
      if (ferr) { out.rejected.push({ txid: tx.txid, code: ferr, type }) } else {
        out.claims.push({ txid: tx.txid, minedIdx, height: h, target_ref: lc(env.json.target_ref), json: env.json, pubkey: env.pubkey })
      }
    }
    minedIdx++
  }
  return out
}

// ---------------------------------------------------------------------------
// §3 THE WINNER RULE (v1.3) — deterministic chain resolution as a TEMPORAL mined-order walk.
//
// Round-two ruling (A1 integrated INTO resolution): authorization is part of chain VALIDITY,
// evaluated during the walk, BEFORE any fork comparison. A chain extension is valid only if
// signed by (a) the genesis manifest's pubkey, or (b) the maintainer_pubkey of a CLAIM
// ATTESTATION (0x06) mined EARLIER whose target_ref was the then-current winning tip. An
// unauthorized child is INVALID outright — it can never win a race, at any position, in any
// order. Claims are therefore evaluated IN the walk (their validity depends on the tip at their
// mined moment, and the authority they grant starts at that moment), not after it.
//
// Same-block law (v1.3): when two COMPETING VALID children of one parent sit at the same height
// and the source supplies no intra-block index, the reader REFUSES to resolve — source-order
// approximation of "first-mined" is a guess, and a forever-rule does not run on guesses.
// (An unauthorized competitor triggers no refusal: it loses deterministically in any order.)
// ---------------------------------------------------------------------------
export function resolveChain (refs, claims = [], { orderAuthoritative = true } = {}) {
  const report = {
    voidLaterGenesis: [], forkLosers: [], seqGaps: [], unauthorized: [],
    ineligibleDescendants: [], orphans: [], preGenesis: [],
    acceptedClaims: [], staleClaims: [],
    keyLineage: [], authTimeline: [], ambiguousSameBlock: [],
  }
  const claimResults = []
  const events = [
    ...refs.map((r) => ({ kind: 'ref', ...r })),
    ...claims.map((c) => ({ kind: 'claim', ...c })),
  ].sort((a, b) => a.minedIdx - b.minedIdx)

  const chain = []
  const onChain = new Set()
  const deadSet = new Set() // losers, unauthorized, gaps, void genesis, orphans — descendants ineligible
  const authState = new Map() // pubkey (lc hex) -> { fromMinedIdx, always, source, height }
  const isAuthorized = (ev) => authState.has(ev.pubkey.toLowerCase())
  let genesis = null

  // §3 rule 3 (round three): positional dependencies between a CLAIM and a REF sharing one
  // block. Collected during the walk; surfaced as ambiguity only when the source supplies no
  // intra-block index (with an index, the observed order IS the answer: height then index).
  const positionalDeps = []
  const depSeen = new Set()
  const flagDep = (claimTxid, refTxid, height) => {
    const k = `${claimTxid}|${refTxid}`
    if (!depSeen.has(k)) { depSeen.add(k); positionalDeps.push({ kind: 'claim-ref-order', claim: claimTxid, ref: refTxid, height }) }
  }
  const acceptedClaimDetails = [] // first-claims only: { txid, key, height, target_ref }
  const staleClaimDetails = []    // would-be first-claims only: { txid, height, target_ref }

  for (const ev of events) {
    if (ev.kind === 'claim') {
      const tip = chain.length ? chain[chain.length - 1] : null
      const key = ev.json.maintainer_pubkey.toLowerCase()
      if (!tip || ev.target_ref !== tip.txid) {
        // replay-proof by target_ref: an attestation against anything but the then-current tip binds nothing
        claimResults.push({ txid: ev.txid, status: 'REJECTED', code: 'STALE_TARGET_REF', detail: tip ? `target_ref ${ev.target_ref} != tip-as-of ${tip.txid}` : 'no mined tip precedes this claim' })
        report.staleClaims.push(ev.txid)
        if (!authState.has(key)) {
          // A would-be first-claim that is stale NOW may be order-dependent against a same-block
          // ref: if an admitted ref in THIS block replaced the tip this claim targets, the
          // claim-first ordering would have accepted it (§3 rule 3, round three).
          if (tip && ev.height != null) {
            const r = chain.find((x) => x.height != null && x.height === ev.height && x.prev === ev.target_ref)
            if (r) flagDep(ev.txid, r.txid, ev.height)
          }
          staleClaimDetails.push({ txid: ev.txid, height: ev.height ?? null, target_ref: ev.target_ref })
        }
      } else {
        claimResults.push({ txid: ev.txid, status: 'ACCEPTED', target_ref: ev.target_ref, maintainer_pubkey: ev.json.maintainer_pubkey, domain: ev.json.domain })
        report.acceptedClaims.push(ev.txid)
        // FIRST-CLAIM PERMANENCE (§3 rule 2, round three): only the first accepted claim per
        // maintainer_pubkey grants authority. A repeat by an already-authorized key is a
        // validated RECORD whose authority effect is a NO-OP — it cannot re-anchor, refresh,
        // change domain/role, or make a stale target current. (Its verdict is also therefore
        // never a positional dependency: authority is identical in either order.)
        if (!authState.has(key)) {
          authState.set(key, { fromMinedIdx: ev.minedIdx, always: false, source: ev.txid, height: ev.height ?? null })
          acceptedClaimDetails.push({ txid: ev.txid, key, height: ev.height ?? null, target_ref: ev.target_ref })
          if (ev.height != null) {
            // ref-first observed: a same-block candidate ref by this key was rejected
            // unauthorized, but would have been admitted under claim-first ordering
            for (const u of report.unauthorized) {
              if (u.branch === 'candidate' && u.seqOk && u.height != null && u.height === ev.height && u.pubkey.toLowerCase() === key) flagDep(ev.txid, u.txid, ev.height)
            }
            // the tip this claim targets was itself admitted in the SAME block — claim-first
            // ordering would have found a different tip and rejected the claim as stale
            if (tip.height != null && tip.height === ev.height) flagDep(ev.txid, tip.txid, ev.height)
          }
        }
      }
      continue
    }

    // REF MANIFEST
    if (ev.seq === 1 && ev.prev === null) {
      if (!genesis) {
        genesis = ev // §3.1 earliest-mined genesis; it DEFINES the chain's root authority
        chain.push(ev); onChain.add(ev.txid)
        authState.set(ev.pubkey.toLowerCase(), { fromMinedIdx: -1, always: true, source: 'genesis' })
      } else {
        report.voidLaterGenesis.push(ev.txid); deadSet.add(ev.txid)
      }
      continue
    }
    if (!genesis) { report.preGenesis.push(ev.txid); deadSet.add(ev.txid); continue }
    const tip = chain[chain.length - 1]
    if (ev.prev === tip.txid) {
      // candidate extension of the current tip — AUTHORIZATION FIRST, before any fork comparison
      if (!isAuthorized(ev)) { report.unauthorized.push({ txid: ev.txid, seq: ev.seq, pubkey: ev.pubkey, branch: 'candidate', seqOk: ev.seq === tip.seq + 1, height: ev.height ?? null }); deadSet.add(ev.txid); continue }
      if (ev.seq !== tip.seq + 1) { report.seqGaps.push({ txid: ev.txid, seq: ev.seq, expected: tip.seq + 1 }); deadSet.add(ev.txid); continue }
      // §3 rule 3 (round three): positional dependencies against same-block claims —
      if (ev.height != null) {
        // (i) this ref's ADMISSION uses authority born in the SAME block (claim-first observed)
        const grant = authState.get(ev.pubkey.toLowerCase())
        if (!grant.always && grant.height != null && grant.height === ev.height) flagDep(grant.source, ev.txid, ev.height)
        // (ii) an accepted first-claim in this block targeted the tip THIS ref replaces —
        // ref-first ordering would have made that claim stale
        for (const ac of acceptedClaimDetails) {
          if (ac.height != null && ac.height === ev.height && ac.target_ref === ev.prev) flagDep(ac.txid, ev.txid, ev.height)
        }
        // (iii) a stale would-be first-claim in this block targeted THIS ref — ref-first
        // ordering (this admission preceding the claim) would have accepted it
        for (const sc of staleClaimDetails) {
          if (sc.height != null && sc.height === ev.height && sc.target_ref === ev.txid) flagDep(sc.txid, ev.txid, ev.height)
        }
      }
      chain.push(ev); onChain.add(ev.txid) // first VALID child in mined order wins permanently
      continue
    }
    // (Late/superseded-parent and orphan refs need no positional-dependency scan: even with
    // authority they would be fork LOSERS, which never changes the resolved chain — and the
    // competing-children same-block check below already covers the loser-vs-winner tie.)
    if (onChain.has(ev.prev)) {
      // its parent already has a permanent first-mined winner (§3.3)
      const parent = chain.find((x) => x.txid === ev.prev)
      if (!isAuthorized(ev)) { report.unauthorized.push({ txid: ev.txid, seq: ev.seq, pubkey: ev.pubkey, branch: 'late', seqOk: parent ? ev.seq === parent.seq + 1 : false, height: ev.height ?? null }); deadSet.add(ev.txid) }
      else if (parent && ev.seq !== parent.seq + 1) { report.seqGaps.push({ txid: ev.txid, seq: ev.seq, expected: parent.seq + 1 }); deadSet.add(ev.txid) }
      else { report.forkLosers.push({ txid: ev.txid, seq: ev.seq, parent: ev.prev, height: ev.height ?? null }); deadSet.add(ev.txid) }
      continue
    }
    if (deadSet.has(ev.prev)) { report.ineligibleDescendants.push(ev.txid); deadSet.add(ev.txid); continue }
    report.orphans.push(ev.txid); deadSet.add(ev.txid)
  }

  // §3.3 same-block refusal: a VALID competitor (fork loser) sharing the winner's height, with no
  // intra-block index, means "first-mined" is undecidable — refuse rather than guess.
  for (let i = 1; i < chain.length; i++) {
    const winner = chain[i]
    const tie = report.forkLosers.find((l) => l.parent === winner.prev && l.height !== null && winner.height != null && l.height === winner.height)
    if (!orderAuthoritative && tie) {
      report.ambiguousSameBlock.push({ parent: winner.prev, winner: winner.txid, competitor: tie.txid, height: winner.height })
    }
  }
  if (genesis && genesis.height != null) {
    const gTie = report.voidLaterGenesis
      .map((t) => refs.find((r) => r.txid === t))
      .find((r) => r && r.height != null && r.height === genesis.height)
    if (!orderAuthoritative && gTie) report.ambiguousSameBlock.push({ parent: null, winner: genesis.txid, competitor: gTie.txid, height: genesis.height })
  }
  // §3 rule 3 (round three): claim/ref positional dependencies collected during the walk become
  // refusal surface ONLY when the source supplied no intra-block index — with one, the observed
  // order is height-then-index and IS the answer.
  if (!orderAuthoritative) report.ambiguousSameBlock.push(...positionalDeps)

  report.keyLineage = chain.map((r) => ({ seq: r.seq, txid: r.txid, pubkey: r.pubkey }))
  report.authTimeline = [...authState.entries()].map(([pubkey, a]) => ({ pubkey, ...a }))
  return { chain, tip: chain.length ? chain[chain.length - 1] : null, report, claimResults }
}

// The §3-rule-2 authorization set as of a mined position: the genesis key always (it IS the
// chain's identity — our own publication mines the artifact manifest BEFORE the genesis ref),
// claimant keys only from their claim's acceptance moment forward. Used for the v1.3 artifact-
// signer law (§2/0x02): a manifest signed outside this set is a REFUSAL, not a disclosure.
export function authorizedKeysAt (report, minedIdx) {
  return new Set(report.authTimeline.filter((a) => a.always || a.fromMinedIdx <= minedIdx).map((a) => a.pubkey))
}

// ---------------------------------------------------------------------------
// §4 refs digest (independent implementation, from the spec text alone)
// ---------------------------------------------------------------------------
export function refsDigestOfBundle (bundlePath) {
  const r = spawnSync('git', ['bundle', 'list-heads', resolve(bundlePath)], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  if (r.status !== 0) throw refusal('GIT_LISTHEADS_FAILED', (r.stderr || '').trim())
  const lines = r.stdout.split(/\r?\n/).filter((l) => l.length > 0)
  const entries = lines.map((line) => {
    const sp = line.indexOf(' ')
    if (sp < 0) throw refusal('GIT_LISTHEADS_FAILED', `unparseable line ${JSON.stringify(line)}`)
    return { line, refname: line.slice(sp + 1) }
  })
  // SPEC-AMBIGUITY[11]: "sort lexicographically by refname" — bytewise on UTF-8 chosen (locale
  // collation would split implementations).
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.refname, 'utf8'), Buffer.from(b.refname, 'utf8')))
  return sha256hex(Buffer.from(entries.map((e) => e.line).join('\n'), 'utf8'))
}

// ---------------------------------------------------------------------------
// sources
// ---------------------------------------------------------------------------
function refusal (code, detail) {
  const e = new Error(`BGIT_REFUSED ${code}${detail ? `: ${detail}` : ''}`)
  e.bgitCode = code
  e.code = code // the claim/continue dialect reads .code — one refusal shape, two spellings
  return e
}

export function readLocalTxs (dir) {
  const chainPath = join(resolve(dir), 'chain.json')
  if (!existsSync(chainPath)) throw refusal('SOURCE_UNREADABLE', `no chain.json in ${dir}`)
  const chain = JSON.parse(readFileSync(chainPath, 'utf8'))
  if (!Array.isArray(chain.entries)) throw refusal('SOURCE_UNREADABLE', 'chain.json has no entries[]')
  // Entry order is the mined-order surrogate and is AUTHORITATIVE (a fixture declares a total
  // order) unless the fixture says `"mined_order": "height-only"` — then only per-entry `height`
  // is trusted and same-height competitors are undecidable (the v1.3 same-block refusal applies).
  const orderAuthoritative = chain.mined_order !== 'height-only'
  const txs = chain.entries.map((e) => ({
    sourceTxid: e.txid,
    mined: e.mined !== false, // fixture entries are mined unless explicitly marked otherwise
    height: typeof e.height === 'number' ? e.height : null,
    raw: Buffer.from(readFileSync(join(resolve(dir), e.file), 'utf8').trim(), 'hex'),
  }))
  return { txs, orderAuthoritative }
}

async function fetchText (url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000) })
  if (!res.ok) throw refusal('SOURCE_UNREADABLE', `${url} → HTTP ${res.status}`)
  return res.text()
}

// Address history via template. Accepts the WoC shape ([{tx_hash,height}]), the bridge/a! shape
// ([{txid,height}] or {history:[...]}), normalizes to [{txid, height}].
// SPEC-AMBIGUITY[13]: §3.3 defines mined order as height THEN tx index within the block, but
// common address-history APIs expose no intra-block index. Chosen: sort by height; same-height
// ties keep source order, and same-height REF-manifest ties are DISCLOSED in the report.
export async function readNetworkTxs (historyUrl, txUrl, repoId) {
  const histText = await fetchText(historyUrl.replace('{address}', encodeURIComponent(repoId)))
  let hist
  try { hist = JSON.parse(histText) } catch { throw refusal('SOURCE_UNREADABLE', 'history response is not JSON') }
  if (!Array.isArray(hist)) hist = hist.history || hist.result || hist.txs
  if (!Array.isArray(hist)) throw refusal('SOURCE_UNREADABLE', 'unrecognized history shape')
  const rows = hist.map((h) => ({
    txid: lc(h.tx_hash || h.txid || h.hash),
    height: Number.isInteger(h.height) && h.height > 0 ? h.height : null,
  })).filter((r) => isHex64(r.txid))
  rows.sort((a, b) => {
    if (a.height === null && b.height === null) return 0
    if (a.height === null) return 1 // unmined last, PENDING
    if (b.height === null) return -1
    return a.height - b.height
  })
  const txs = []
  for (const r of rows) {
    const hex = (await fetchText(txUrl.replace('{txid}', r.txid))).trim()
    txs.push({ sourceTxid: r.txid, mined: r.height !== null, height: r.height, raw: Buffer.from(hex, 'hex') })
  }
  return txs
}

// ---------------------------------------------------------------------------
// walkSnapshot — ONE immutable read of a repo chain; every claim/continue
// decision derives from it (codex-crypto b81a4643 + 7b7f878e: tip role and
// grant PROVENANCE ride the digest, so authority changes count as motion).
// Consumers: claim.mjs (the claim verb) and publisher.mjs --continue.
// ---------------------------------------------------------------------------
export async function walkSnapshot ({ repoId, localIn, historyUrl, txUrl, source }) {
  let txs, orderAuthoritative
  if (localIn) {
    const src = readLocalTxs(resolve(localIn))
    txs = src.txs
    orderAuthoritative = src.orderAuthoritative
  } else {
    let h = historyUrl; let t = txUrl
    if (source) {
      const p = SOURCE_PRESETS[source]
      if (!p) throw refusal('USAGE', `unknown --source ${source} (have: ${Object.keys(SOURCE_PRESETS).join(', ')})`)
      h = h || p.historyUrl
      t = t || p.txUrl
    }
    if (!h || !t) throw refusal('USAGE', 'need --local-in OR (--history-url AND --tx-url) OR --source <preset>')
    txs = await readNetworkTxs(h, t, repoId)
    orderAuthoritative = false
  }
  const col = collectRecords(txs, repoId)
  const { chain, tip, report, claimResults } = resolveChain(col.refs, col.claims, { orderAuthoritative })
  if (!tip) throw refusal('NO_GENESIS', `no valid seq=1 REF MANIFEST for ${repoId} — a chain this walk cannot verify is a chain nothing may act on`)
  if (report.ambiguousSameBlock.length) {
    const a = report.ambiguousSameBlock[0]
    throw refusal('AMBIGUOUS_MINED_ORDER', `order-dependent verdict at height ${a.height} and this source has no intra-block index — re-read from a source with block data before acting`)
  }
  const granted = new Set(report.authTimeline.map((a) => a.pubkey))
  const genesisPubkey = report.keyLineage.length ? report.keyLineage[0].pubkey : (report.authTimeline.find((a) => a.always) || {}).pubkey
  const accepted = claimResults.filter((c) => c.status === 'ACCEPTED').map((c) => c.txid).sort()
  // provenance: genesis-vs-claimant distinction is part of the immutable state (7b7f878e)
  const provenance = report.authTimeline
    .map((a) => ({ pubkey: a.pubkey, always: !!a.always, source: a.source || null }))
    .sort((x, y) => (x.pubkey < y.pubkey ? -1 : 1))
  return {
    txCount: txs.length,
    tipTxid: tip.txid,
    tipSeq: tip.seq,
    tipRole: typeof tip.role === 'string' ? tip.role : null,
    tipPubkey: tip.pubkey || null,
    tipMined: tip.mined !== false,
    genesisPubkey,
    granted,
    acceptedClaims: accepted,
    digest: createHash('sha256').update(JSON.stringify({
      tip: tip.txid, tipRole: typeof tip.role === 'string' ? tip.role : null, provenance, accepted,
    })).digest('hex'),
  }
}

// ---------------------------------------------------------------------------
// §6.3–6.5 — reassembly + full verification
// ---------------------------------------------------------------------------
export async function runReader (opts) {
  const repoId = opts.repoId
  if (!repoId) throw refusal('USAGE', '--repo-id required')
  const outPath = resolve(opts.out || `bgit-${repoId}.bundle`)
  const checks = []
  const pass = (name, detail) => { checks.push(detail ? `${name} — ${detail}` : name); if (!opts.quiet) console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ''}`) }

  // ---- source ----
  let txs
  let localDir = null
  let sourceDesc
  let orderAuthoritative = false // network sources supply heights, never an intra-block index
  if (opts.localIn) {
    localDir = resolve(opts.localIn)
    const src = readLocalTxs(localDir)
    txs = src.txs
    orderAuthoritative = src.orderAuthoritative
    sourceDesc = `local fixture chain ${localDir} (file order = mined-order surrogate)`
  } else {
    let historyUrl = opts.historyUrl; let txUrl = opts.txUrl
    if (opts.source) {
      const p = SOURCE_PRESETS[opts.source]
      if (!p) throw refusal('USAGE', `unknown --source ${opts.source} (have: ${Object.keys(SOURCE_PRESETS).join(', ')})`)
      historyUrl = historyUrl || p.historyUrl
      txUrl = txUrl || p.txUrl
    }
    if (!historyUrl || !txUrl) throw refusal('USAGE', 'need --local-in OR (--history-url AND --tx-url) OR --source <preset>')
    txs = await readNetworkTxs(historyUrl, txUrl, repoId)
    sourceDesc = `history=${historyUrl} tx=${txUrl}`
  }
  pass('SOURCE_WALKED', `${txs.length} transactions from ${sourceDesc}`)

  // ---- §6.1/6.2 collect + winner ----
  const col = collectRecords(txs, repoId)
  if (col.ignoredMultiOutput.length) pass('MULTI_BGIT_TXS_IGNORED', col.ignoredMultiOutput.map((t) => t.txid).join(', '))
  if (col.skipped.length) pass('UNKNOWN_RECORDS_SKIPPED_NOT_ERRORED', `${col.skipped.length} (never influence winner selection)`)
  if (col.rejected.length) pass('INVALID_RECORDS_REJECTED', col.rejected.map((r) => `${r.txid.slice(0, 8)}…:${r.code}`).join(', '))
  pass('SIGNATURES_VERIFIED_STRICT', `${col.refs.length} REF + ${col.artifacts.size} ARTIFACT + ${col.claims.length} CLAIM records passed strict-DER/low-S/compressed-key/literal-bytes verification`)

  const { chain, tip, report: chainReport, claimResults } = resolveChain(col.refs, col.claims, { orderAuthoritative })
  if (!tip) throw refusal('NO_GENESIS', `no valid seq=1/prev=null REF MANIFEST found for ${repoId} in ${txs.length} txs (an empty walk from one source proves nothing — cross-check a second source)`)
  // v1.3 same-block law: competing VALID children in one block with no intra-block index —
  // "first-mined" is undecidable from this source; refuse rather than resolve by source order.
  if (chainReport.ambiguousSameBlock.length) {
    const a = chainReport.ambiguousSameBlock[0]
    const what = a.kind === 'claim-ref-order'
      ? `claim ${a.claim.slice(0, 12)}… and ref ${a.ref.slice(0, 12)}… have an order-dependent verdict`
      : `competing valid children ${a.winner.slice(0, 12)}… and ${a.competitor.slice(0, 12)}… race`
    throw refusal('AMBIGUOUS_MINED_ORDER', `${what} at height ${a.height} and this source has no intra-block index — re-read from a source with block data`)
  }
  pass('WINNER_RULE_APPLIED', `genesis ${chain[0].txid.slice(0, 12)}… → tip seq=${tip.seq} ${tip.txid.slice(0, 12)}…`)
  if (chainReport.unauthorized.length) pass('UNAUTHORIZED_EXTENSIONS_REJECTED', chainReport.unauthorized.map((u) => `${u.txid.slice(0, 12)}… (key ${u.pubkey.slice(0, 12)}…)`).join(', ') + ' — §3 rule 2: not the genesis key, no valid earlier claim; invalid BEFORE fork comparison')
  if (chainReport.forkLosers.length) pass('FORKS_RESOLVED_FIRST_MINED', chainReport.forkLosers.map((f) => f.txid.slice(0, 12) + '…').join(', '))
  if (chainReport.ineligibleDescendants.length) pass('LOSING_DESCENDANTS_INELIGIBLE', chainReport.ineligibleDescendants.map((t) => t.slice(0, 12) + '…').join(', '))
  if (chainReport.seqGaps.length) pass('SEQ_GAPS_REJECTED', chainReport.seqGaps.map((g) => `${g.txid.slice(0, 12)}…(seq ${g.seq}≠${g.expected})`).join(', '))
  const distinctKeys = new Set(chainReport.keyLineage.map((k) => k.pubkey))
  pass('AUTHORIZATION_LAW_ENFORCED', distinctKeys.size === 1
    ? `single authorized key ${[...distinctKeys][0].slice(0, 16)}… signs the whole chain`
    : `${distinctKeys.size} keys on the chain, every one authorized (genesis key or accepted claimant — §3 rule 2)`)

  for (const c of claimResults) pass(c.status === 'ACCEPTED' ? 'CLAIM_ATTESTATION_ACCEPTED' : 'CLAIM_ATTESTATION_REJECTED', `${c.txid.slice(0, 12)}… ${c.code || `binds tip ${c.target_ref.slice(0, 12)}…`}`)

  // ---- §6.3 the winning artifact manifest ----
  const artifact = col.artifacts.get(tip.artifact)
  if (!artifact) {
    if (col.rejected.some((r) => r.txid === tip.artifact)) throw refusal('NO_ARTIFACT_MANIFEST', `tip cites ${tip.artifact} which was REJECTED (${col.rejected.find((r) => r.txid === tip.artifact).code})`)
    if (col.skipped.some((s) => s.txid === tip.artifact)) throw refusal('ARTIFACT_TYPE_MISMATCH', `tip cites ${tip.artifact} which is not a v1 0x02 record`)
    if (col.parts.has(tip.artifact) || col.refs.some((r) => r.txid === tip.artifact)) throw refusal('ARTIFACT_TYPE_MISMATCH', `tip cites ${tip.artifact} which is not TYPE 0x02`)
    throw refusal('NO_ARTIFACT_MANIFEST', `tip cites ${tip.artifact} — not found in the walk`)
  }
  // v1.3 (§2/0x02): the artifact manifest's signer MUST be an authorized key of the ref chain at
  // the manifest's mined position — a mismatch is a REFUSAL, not a disclosure. The genesis key is
  // authorized at every position (a publication mines its artifact manifest before its genesis
  // ref); claimant keys only from their claim's acceptance moment.
  const artifactAuth = authorizedKeysAt(chainReport, artifact.minedIdx)
  if (!artifactAuth.has(artifact.pubkey.toLowerCase())) {
    throw refusal('ARTIFACT_SIGNER_UNAUTHORIZED', `artifact manifest ${artifact.txid.slice(0, 12)}… is signed by ${artifact.pubkey.slice(0, 16)}…, which is not an authorized key of this ref chain at its mined position`)
  }
  pass('ARTIFACT_MANIFEST_TYPE_AND_SIG_OK', `${artifact.txid.slice(0, 12)}… signed by ${artifact.pubkey.slice(0, 16)}… (authorized key of the ref chain)`)

  // early cross-check: the tip's refs_sha256 must equal the manifest's bundle_refs_sha256 (§3)
  if (tip.refs_sha256 !== lc(artifact.json.bundle_refs_sha256)) {
    throw refusal('REFS_DIGEST_CROSS_MISMATCH', `ref tip refs_sha256 ${tip.refs_sha256} != artifact bundle_refs_sha256 ${artifact.json.bundle_refs_sha256}`)
  }
  pass('REF_AND_ARTIFACT_DIGESTS_AGREE')

  // ---- §6.3 fetch/extract/verify each part in order; concatenate ----
  const partSrc = buildPartSource({ localDir, txs, opts })
  const repoScriptBuf = p2pkhScriptFor(repoId) // §5 v1.3: dust enforced on PART txs here too
  const tmpOut = `${outPath}.part`
  const fd = openSync(tmpOut, 'w')
  const whole = createHash('sha256')
  let totalBytes = 0
  try {
    let i = 0
    for (const p of artifact.json.parts) {
      const ptxid = lc(p.txid)
      const raw = await partSrc(ptxid)
      if (!raw) throw refusal('PART_NOT_FOUND', `parts[${i}] ${ptxid}`)
      const tx = parseRawTx(raw)
      if (tx.txid !== ptxid) throw refusal('PART_NOT_FOUND', `parts[${i}]: fetched tx hashes to ${tx.txid}, not ${ptxid}`)
      // §5 (v1.3): ALL record types pay the repo address — the reassembly path fetches by txid
      // (possibly outside the address walk), so the dust law is enforced here as well.
      if (!tx.outputs.some((o) => o.script.equals(repoScriptBuf) && o.satoshis >= 1)) {
        throw refusal('PART_NOT_PAYING_REPO', `parts[${i}] ${ptxid}: no output pays the repo address (§5, enforced on all four record types)`)
      }
      const tagged = tx.outputs.map((o) => classifyOutput(o.script)).filter(Boolean)
      if (tagged.length !== 1 || tagged[0].record === null) throw refusal('PART_NOT_PART', `parts[${i}] ${ptxid}: not exactly one well-formed bgit output`)
      const rec = tagged[0].record
      if (rec[0] !== V1 || rec[1] !== T_PART) throw refusal('PART_NOT_PART', `parts[${i}] ${ptxid}: record is v${rec[0]} type 0x${(rec[1] ?? 0).toString(16).padStart(2, '0')}, not v1 PART`)
      const body = rec.subarray(2)
      if (body.length !== p.bytes) throw refusal('PART_BYTES_MISMATCH', `parts[${i}] ${ptxid}: ${body.length} bytes, manifest says ${p.bytes}`)
      const got = sha256hex(body)
      if (got !== lc(p.sha256)) throw refusal('PART_SHA_MISMATCH', `parts[${i}] ${ptxid}: sha256 ${got} != manifest ${p.sha256}`)
      writeSync(fd, body)
      whole.update(body)
      totalBytes += body.length
      i++
    }
    pass('PARTS_VERIFIED', `${artifact.json.parts.length}/${artifact.json.parts.length} per-part sha256 + length OK`)

    // ---- §6.4 whole-artifact verification ----
    if (totalBytes !== artifact.json.artifact_bytes) throw refusal('ARTIFACT_BYTES_MISMATCH', `${totalBytes} != manifest artifact_bytes ${artifact.json.artifact_bytes}`)
    const wholeHex = whole.digest('hex')
    if (wholeHex !== lc(artifact.json.artifact_sha256)) throw refusal('ARTIFACT_SHA_MISMATCH', `${wholeHex} != manifest ${artifact.json.artifact_sha256}`)
    pass('ARTIFACT_SHA256_OK', `${wholeHex} over ${totalBytes.toLocaleString('en-US')} bytes`)
  } catch (e) {
    try { closeSync(fd) } catch {}
    try { unlinkSync(tmpOut) } catch {} // never hand over unverified bytes — no partial artifact
    throw e
  }
  closeSync(fd)

  // ---- §6.4 refs digest recomputed FROM THE RECONSTRUCTED BUNDLE, matched against BOTH ----
  let refsDigest
  try {
    refsDigest = refsDigestOfBundle(tmpOut)
  } catch (e) { try { unlinkSync(tmpOut) } catch {}; throw e }
  if (refsDigest !== lc(artifact.json.bundle_refs_sha256)) { try { unlinkSync(tmpOut) } catch {}; throw refusal('REFS_DIGEST_MISMATCH_ARTIFACT', `${refsDigest} != ${artifact.json.bundle_refs_sha256}`) }
  if (refsDigest !== tip.refs_sha256) { try { unlinkSync(tmpOut) } catch {}; throw refusal('REFS_DIGEST_MISMATCH_REF', `${refsDigest} != ${tip.refs_sha256}`) }
  pass('REFS_DIGEST_RECOMPUTED_AND_MATCHED_BOTH', refsDigest)

  renameSync(tmpOut, outPath)
  pass('ARTIFACT_WRITTEN', outPath)

  if (col.pendingTxs.length) pass('PENDING_DISCLOSED', `${col.pendingTxs.length} unmined tx(s) reported PENDING, never the tip`)
  pass('HONESTY_NOTE', opts.localIn
    ? 'local fixture = a single synthetic source; mined order is the file order; absence proves nothing'
    : 'a single source cannot prove absence or freshness (§6.6) — cross-check a second source; a stateful reader should also keep a high-water seq')

  const result = {
    ok: true,
    out: outPath,
    repo_id: repoId,
    tip: { txid: tip.txid, seq: tip.seq, role: tip.role, pubkey: tip.pubkey },
    chain: chainReport.keyLineage,
    artifact: { txid: artifact.txid, bytes: totalBytes, sha256: lc(artifact.json.artifact_sha256), repo: artifact.json.repo, label: artifact.json.label },
    refs_sha256: refsDigest,
    claims: claimResults,
    skipped: col.skipped,
    rejected: col.rejected,
    ignoredMultiOutput: col.ignoredMultiOutput,
    forkReport: chainReport,
    pending: col.pendingTxs,
    checks,
  }
  if (opts.report) writeFileSync(resolve(opts.report), JSON.stringify(result, null, 2))
  if (!opts.quiet) {
    console.log(`\n=== bgit reader: VERIFIED ===`)
    console.log(`repo_id: ${repoId}`)
    console.log(`tip:     seq=${tip.seq} ${tip.txid} (${tip.role})`)
    console.log(`bundle:  ${outPath} (${totalBytes.toLocaleString('en-US')} bytes, sha256 ${result.artifact.sha256})`)
    console.log(`clone:   git clone "${outPath}" <dir>`)
  }
  return result
}

function buildPartSource ({ localDir, txs }) {
  // §6.3 fetches parts BY TXID. Local mode: re-read the fixture file (no 257MB resident set);
  // network mode: the walk already fetched every repo-address tx — reuse those buffers, and only
  // a manifest citing a part OUTSIDE the address walk would need a direct fetch (disclosed).
  if (localDir) {
    const chain = JSON.parse(readFileSync(join(localDir, 'chain.json'), 'utf8'))
    const byTxid = new Map(chain.entries.map((e) => [lc(e.txid), e.file]))
    return async (txid) => {
      const file = byTxid.get(txid)
      if (!file) return null
      return Buffer.from(readFileSync(join(localDir, file), 'utf8').trim(), 'hex')
    }
  }
  const byTxid = new Map()
  for (const t of txs) { try { byTxid.set(parseRawTx(t.raw).txid, t.raw) } catch {} }
  return async (txid) => byTxid.get(txid) || null
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs (argv) {
  const o = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    const next = () => { const v = argv[++i]; if (v === undefined) throw new Error(`missing value for ${a}`); return v }
    switch (a) {
      case '--repo-id': o.repoId = next(); break
      case '--local-in': o.localIn = next(); break
      case '--history-url': o.historyUrl = next(); break
      case '--tx-url': o.txUrl = next(); break
      case '--source': o.source = next(); break
      case '--out': o.out = next(); break
      case '--report': o.report = next(); break
      case '--quiet': o.quiet = true; break
      default: throw new Error(`unknown flag: ${a}`)
    }
  }
  return o
}

const isMain = (() => {
  try { return process.argv[1] && pathToFileURL(resolve(process.argv[1])).href.toLowerCase() === import.meta.url.toLowerCase() } catch { return false }
})()

if (isMain) {
  runReader(parseArgs(process.argv.slice(2))).catch((e) => {
    console.error(e.bgitCode ? e.message : `bgit reader: ${e.message}`)
    process.exit(e.bgitCode ? 2 : 1)
  })
}
