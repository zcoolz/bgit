#!/usr/bin/env node
// claim.mjs — the CLAIM VERB: a maintainer claims a mirrored repository by publishing a
// 0x06 CLAIM ATTESTATION (BGIT_WIRE_FORMAT_v1.md §0x06, §3.6 first-claim permanence).
//
// Design: BGIT_CLAIM_VERB_DESIGN_2026-08-16.md · verdict BUILD-WITH-CHANGES
// (codex-crypto wire b81a4643, every change folded):
//   • 0x06-only. The maintainer's first REF MANIFEST is publisher part 2 — this verb PRINTS
//     the honest state ("no maintainer update exists yet") and the continuation step, never
//     fakes it.
//   • .well-known evidence is FETCHED by this verb, receipted (archiveable), and RE-CHECKED
//     immediately before broadcast. There is no production bypass flag; the fixture seam
//     (--local-in) has no broadcast path at all.
//   • already-claimed detection reads resolveChain's authTimeline (grants), never raw 0x06
//     scans — stale/repeated attestations are not grants.
//   • target_ref and claim state come from ONE immutable walk snapshot; a second walk runs
//     immediately pre-broadcast and ANY motion (tip, grants, accepted claims) refuses.
//   • fee math runs on the actual single-input tx shape; the funding outpoint's script must
//     pay the claim key's own address, verified from the source before signing.
//   • same-block ambiguous ordering refuses (v1.3 law), exactly as the reader refuses.
//   • plans/state/logs carry NO key material. The wif is read in-process and never echoed.
//
// Usage:
//   node claim.mjs --repo-id <address> --key-file <maintainer-key.json> --domain <domain>
//        (--local-in <fixture-dir> | --history-url <tpl> --tx-url <tpl> | --source <preset>)
//        [--out <plan-dir>]                              # dry-run is the DEFAULT
//        [--broadcast --funding <txid>:<vout>:<sats> --bridge <url>]
//   node claim.mjs --confirm --state <claim-state.json> --tx-url <tpl>   # only pass allowed to say ACCEPTED
//
// Endpoints are ALWAYS explicit (house law: no default endpoints anywhere in these tools).

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  loadSdk, sha256hex, signedRecord, TYPE_CLAIM, estimateTxSize, feeFor,
  DUST_SATS, FINAL_CHANGE_SATS, buildTx, broadcastOne,
} from './publisher.mjs'
import { walkSnapshot, SOURCE_PRESETS } from './reader.mjs'
export { walkSnapshot } // re-export: the tests and older callers reach it through the verb

void SOURCE_PRESETS // (presets are resolved inside walkSnapshot; kept imported for CLI help)

// ---------------------------------------------------------------------------
// typed refusals — every no is named
// ---------------------------------------------------------------------------
function refuse (code, msg) {
  const e = new Error(`${code}: ${msg}`)
  e.code = code
  return e
}

// lowercase DNS hostname, at least two labels, no scheme/path/port
export function validDomain (d) {
  return typeof d === 'string' &&
    /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)
}

// ---------------------------------------------------------------------------
// §0x06 body — field ORDER follows the spec sample verbatim; literal bytes get signed.
// ---------------------------------------------------------------------------
export function buildClaimBody ({ repoId, maintainerPubkey, domain, targetRef }) {
  const body = {
    bgit: 1,
    repo_id: repoId,
    maintainer_pubkey: maintainerPubkey,
    domain,
    role: 'maintainer',
    target_ref: targetRef,
  }
  return Buffer.from(JSON.stringify(body), 'utf8')
}

export function wellKnownExpected ({ repoId, maintainerPubkey, domain }) {
  return {
    url: `https://${domain}/.well-known/bgit`,
    content: JSON.stringify({ repo_id: repoId, maintainer_pubkey: maintainerPubkey }, null, 2),
  }
}

// (walkSnapshot lives in reader.mjs — ONE walker for reader, claim, and publisher --continue;
//  extracted per the 7b7f878e verdict so no consumer can drift from another.)

// pure precondition lattice — exported so the vector suite can attack it directly
export function claimPreconditions (snap, maintainerPubkey) {
  if (!snap.tipMined) throw refuse('TIP_UNMINED', `current tip ${snap.tipTxid.slice(0, 12)}… is not mined — a claim binding an unmined tip is stale on arrival (§0x06 replay law); wait for burial`)
  if (maintainerPubkey === snap.genesisPubkey) throw refuse('GENESIS_NEEDS_NO_CLAIM', 'this key already owns the chain from genesis — publish a REF MANIFEST, a claim would be void')
  if (snap.granted.has(maintainerPubkey)) throw refuse('ALREADY_AUTHORIZED', 'first-claim permanence (§3.6): this key already holds an accepted grant — a second claim binds nothing and wastes the sats')
}

// ---------------------------------------------------------------------------
// evidence — fetched, matched exactly, receipted. Never asserted.
// ---------------------------------------------------------------------------
export async function fetchEvidence ({ domain, repoId, maintainerPubkey }, fetchImpl = fetch) {
  const url = `https://${domain}/.well-known/bgit`
  const receipt = { url, fetched_at: new Date().toISOString(), http_status: null, body_sha256: null, matched: false, detail: null }
  let res
  try {
    res = await fetchImpl(url, { signal: AbortSignal.timeout(60_000), redirect: 'follow' })
  } catch (e) {
    receipt.detail = `fetch failed: ${e.message}`
    return receipt
  }
  receipt.http_status = res.status
  const text = (await res.text().catch(() => '')).slice(0, 65_536)
  receipt.body_sha256 = sha256hex(Buffer.from(text, 'utf8'))
  if (!res.ok) { receipt.detail = `HTTP ${res.status}`; return receipt }
  try {
    const j = JSON.parse(text)
    if (j.repo_id === repoId && j.maintainer_pubkey === maintainerPubkey) {
      receipt.matched = true
      receipt.detail = 'exact repo_id + maintainer_pubkey match'
    } else {
      receipt.detail = 'well-known file exists but repo_id/maintainer_pubkey do not match exactly'
    }
  } catch {
    receipt.detail = 'well-known body is not JSON'
  }
  return receipt
}

// ---------------------------------------------------------------------------
// the verb
// ---------------------------------------------------------------------------
export async function runClaim (opts) {
  const sdk = loadSdk()
  const { PrivateKey, P2PKH } = sdk

  if (!opts.repoId) throw refuse('USAGE', '--repo-id required')
  if (!validDomain(opts.domain || '')) throw refuse('BAD_DOMAIN', `--domain must be a bare lowercase hostname (got ${JSON.stringify(opts.domain || '')})`)

  // key — in-process only, never echoed anywhere
  let wif = opts.key
  if (!wif && opts.keyFile) {
    let kf
    try { kf = JSON.parse(readFileSync(resolve(opts.keyFile), 'utf8')) } catch (e) { throw refuse('KEY_UNREADABLE', `--key-file unreadable (${e.message})`) }
    if (typeof kf.wif !== 'string' || !kf.wif) throw refuse('KEY_UNREADABLE', '--key-file has no usable "wif" field')
    wif = kf.wif
  }
  if (!wif) throw refuse('USAGE', '--key-file <maintainer-key.json> (or --key) required')
  const privKey = PrivateKey.fromWif(wif)
  const maintainerPubkey = Buffer.from(privKey.toPublicKey().encode(true)).toString('hex')
  const maintainerAddress = privKey.toAddress()

  // ---- snapshot #1: the immutable walk every decision derives from ----
  const snap = await walkSnapshot(opts)
  claimPreconditions(snap, maintainerPubkey)
  const targetRef = snap.tipTxid // NEVER hand-supplied; there is deliberately no CLI override

  // ---- the record ----
  const body = buildClaimBody({ repoId: opts.repoId, maintainerPubkey, domain: opts.domain, targetRef })
  const record = signedRecord(TYPE_CLAIM, body, privKey)
  const wk = wellKnownExpected({ repoId: opts.repoId, maintainerPubkey, domain: opts.domain })

  // ---- fee math on the ACTUAL single-input tx shape ----
  const size = estimateTxSize(record.length)
  const fee = feeFor(size)
  const needed = fee + DUST_SATS + FINAL_CHANGE_SATS

  const plan = {
    verb: 'claim',
    repo_id: opts.repoId,
    domain: opts.domain,
    maintainer_pubkey: maintainerPubkey,
    maintainer_address: maintainerAddress,
    target_ref: targetRef,
    tip_seq: snap.tipSeq,
    walk: { tx_count: snap.txCount, snapshot_digest: snap.digest },
    record_bytes: record.length,
    est_tx_bytes: size,
    fee_sats: fee,
    min_funding_sats: needed,
    well_known: wk,
  }

  const lines = []
  const say = (s) => { lines.push(s); console.log(s) }
  say(`CLAIM PLAN — repo ${opts.repoId}`)
  say(`  maintainer key: ${maintainerPubkey.slice(0, 16)}… (address ${maintainerAddress})`)
  say(`  target_ref (current mined tip, seq ${snap.tipSeq}): ${targetRef}`)
  say(`  walk: ${snap.txCount} txs · snapshot ${snap.digest.slice(0, 16)}…`)
  say(`  record: ${record.length} B · est tx ${size} B · fee ${fee} sats · minimum funding ${needed} sats`)
  say('')
  say(`HOST THIS FIRST — https://${opts.domain}/.well-known/bgit :`)
  say(wk.content)
  say('')

  // ---- dry-run universe (default, and the ONLY universe for --local-in) ----
  if (!opts.broadcast) {
    if (opts.out) {
      const dir = resolve(opts.out)
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, 'claim-plan.json'), JSON.stringify(plan, null, 2))
      writeFileSync(join(dir, 'claim-record.hex'), record.toString('hex'))
      writeFileSync(join(dir, 'well-known-expected.json'), wk.content)
      say(`plan written: ${dir} (claim-plan.json · claim-record.hex · well-known-expected.json — no key material)`)
    }
    say('NOT BROADCAST. Dry run (the default). Broadcast is human-gated: --broadcast --funding <txid:vout:sats> --bridge <url>')
    return { plan, record, broadcast: false }
  }

  // ---- broadcast path (network sources only — the fixture seam has no broadcast) ----
  if (opts.localIn) throw refuse('FIXTURE_CANNOT_BROADCAST', 'the --local-in fixture seam is the test universe; broadcasting from it is structurally disabled')
  if (!opts.bridges || !opts.bridges.length) throw refuse('USAGE', '--broadcast requires --bridge <url> (endpoints are always explicit)')
  if (!opts.funding) throw refuse('USAGE', '--broadcast requires --funding <txid>:<vout>:<sats>')
  const m = /^([0-9a-fA-F]{64}):(\d+):(\d+)$/.exec(opts.funding)
  if (!m) throw refuse('USAGE', '--funding must be <txid>:<vout>:<sats>')
  const funding = { txid: m[1].toLowerCase(), vout: Number(m[2]), satoshis: Number(m[3]) }
  if (funding.satoshis < needed) throw refuse('INSUFFICIENT_FUNDING', `funding ${funding.satoshis} sats < required ${needed} (fee ${fee} + dust ${DUST_SATS} + minimum change ${FINAL_CHANGE_SATS})`)

  // funding outpoint verified FROM THE SOURCE: the script must pay the claim key itself
  if (!opts.txUrl && !opts.source) throw refuse('USAGE', 'broadcast needs --tx-url (or --source) to verify the funding outpoint before signing')
  const txUrlTpl = opts.txUrl || SOURCE_PRESETS[opts.source].txUrl
  const fres = await fetch(txUrlTpl.replace('{txid}', funding.txid), { signal: AbortSignal.timeout(60_000) })
  if (!fres.ok) throw refuse('FUNDING_UNREADABLE', `funding tx fetch → HTTP ${fres.status}`)
  const fhex = (await fres.text()).trim()
  const ftx = sdk.Transaction.fromHex(fhex)
  const fout = ftx.outputs[funding.vout]
  if (!fout) throw refuse('FUNDING_BAD_OUTPOINT', `funding tx has no output ${funding.vout}`)
  if (fout.satoshis !== funding.satoshis) throw refuse('FUNDING_VALUE_MISMATCH', `outpoint holds ${fout.satoshis} sats, --funding says ${funding.satoshis}`)
  const expectLock = new P2PKH().lock(maintainerAddress).toHex()
  if (fout.lockingScript.toHex() !== expectLock) throw refuse('FUNDING_NOT_OURS', 'funding outpoint does not pay the maintainer key — the claim must be funded by the key that signs it')

  // evidence: fetched + matched + receipted (check #1)
  const ev1 = await fetchEvidence({ domain: opts.domain, repoId: opts.repoId, maintainerPubkey })
  if (!ev1.matched) throw refuse('EVIDENCE_MISSING', `https://${opts.domain}/.well-known/bgit must be live and exactly matching BEFORE broadcast (${ev1.detail}). Host the printed file, archive proof, re-run.`)

  // snapshot #2: the chain must not have moved while we prepared
  const snap2 = await walkSnapshot(opts)
  if (snap2.digest !== snap.digest) throw refuse('CHAIN_MOVED', `the repo chain changed between plan and broadcast (tip ${snap.tipTxid.slice(0, 12)}… → ${snap2.tipTxid.slice(0, 12)}…, or claim state moved) — re-run to build a fresh claim`)

  // evidence re-check immediately before POST (check #2 — the decisive-time reading)
  const ev2 = await fetchEvidence({ domain: opts.domain, repoId: opts.repoId, maintainerPubkey })
  if (!ev2.matched) throw refuse('EVIDENCE_LOST', `the well-known file was live and is now not (${ev2.detail}) — refusing to broadcast a claim whose decisive-time evidence is absent`)

  const changeSats = funding.satoshis - DUST_SATS - fee
  const prev = { txid: funding.txid, vout: funding.vout, satoshis: funding.satoshis, lockingScript: new P2PKH().lock(maintainerAddress) }
  const built = await buildTx({ sdk, privKey, repoAddress: opts.repoId, record, prev, changeSats })

  // integrity: re-hash the exact bytes about to travel (the publisher's pre-send law)
  const sendHex = built.hex
  if (sha256hex(Buffer.from(sendHex, 'hex')) !== sha256hex(Buffer.from(built.hex, 'hex'))) throw refuse('DRIFT', 'bytes drifted between build and send')

  const state = {
    ...plan,
    txid: built.txid,
    tx_bytes: built.size,
    change_sats: changeSats,
    evidence: [ev1, ev2],
    snapshot2_digest: snap2.digest,
    broadcast_at: new Date().toISOString(),
    status: 'PENDING',
  }
  const statePath = resolve(opts.out || '.', 'claim-state.json')
  mkdirSync(resolve(opts.out || '.'), { recursive: true })
  writeFileSync(statePath, JSON.stringify(state, null, 2))

  const r = await broadcastOne(sendHex, opts.bridges)
  say(`broadcast → ${r.bridge} (HTTP ${r.http})`)
  say(`claim txid ${built.txid} — PENDING. Nothing is accepted until it is MINED: run --confirm --state ${statePath} --tx-url <tpl>`)
  say('')
  say('NEXT (after the claim is mined): no maintainer update exists yet — the repo still serves the')
  say('mirror chain. Continuation (publisher part 2, not yet built): publish a REF MANIFEST with role')
  say(`"maintainer", prev = ${targetRef.slice(0, 12)}…, signed by this same key.`)
  return { plan, state, broadcast: true, txid: built.txid }
}

// ---------------------------------------------------------------------------
// --confirm: the only pass allowed to say ACCEPTED (only-mined-promotes)
// ---------------------------------------------------------------------------
export async function runClaimConfirm (opts) {
  if (!opts.state) throw refuse('USAGE', '--confirm requires --state <claim-state.json>')
  const state = JSON.parse(readFileSync(resolve(opts.state), 'utf8'))
  if (!opts.repoId) opts.repoId = state.repo_id
  // mined = the claim txid appears in a fresh walk of the repo address with a height
  const snap = await walkSnapshot({ repoId: state.repo_id, historyUrl: opts.historyUrl, txUrl: opts.txUrl, source: opts.source, localIn: opts.localIn })
  const accepted = snap.acceptedClaims.includes(state.txid)
  if (accepted) {
    console.log(`ACCEPTED — claim ${state.txid} is mined and the reader accepts it (bound tip ${state.target_ref.slice(0, 12)}…).`)
    console.log('The key now holds a permanent grant (§3.6). Continuation: maintainer REF MANIFEST (publisher part 2).')
    state.status = 'ACCEPTED'
  } else {
    console.log(`PENDING — claim ${state.txid} is not yet an accepted, mined claim in the walk (${snap.txCount} txs read). A broadcast is not a burial; re-run later.`)
  }
  writeFileSync(resolve(opts.state), JSON.stringify(state, null, 2))
  return { accepted, state }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs (argv) {
  const o = { bridges: [] }
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    const next = () => argv[++i]
    switch (a) {
      case '--repo-id': o.repoId = next(); break
      case '--key-file': o.keyFile = next(); break
      case '--key': o.key = next(); break
      case '--domain': o.domain = next(); break
      case '--local-in': o.localIn = next(); break
      case '--history-url': o.historyUrl = next(); break
      case '--tx-url': o.txUrl = next(); break
      case '--source': o.source = next(); break
      case '--out': o.out = next(); break
      case '--broadcast': o.broadcast = true; break
      case '--funding': o.funding = next(); break
      case '--bridge': o.bridges.push(next()); break
      case '--confirm': o.confirm = true; break
      case '--state': o.state = next(); break
      default: throw refuse('USAGE', `unknown flag ${a}`)
    }
  }
  return o
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (isMain) {
  const o = parseArgs(process.argv)
  const run = o.confirm ? runClaimConfirm(o) : runClaim(o)
  run.catch((e) => { console.error(`✗ ${e.message}`); process.exit(1) })
}
