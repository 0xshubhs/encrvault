/**
 * Vault crypto. Runs in the browser for both encrypting and decrypting.
 * Any wallet can store records; each record can only be opened by the wallet that created it.
 *
 * Scheme
 *   1. The wallet signs unlockMessage(wallet) with personal_sign (ECDSA / secp256k1).
 *   2. ecrecover(signature) must equal that wallet, otherwise we stop.
 *   3. key = HKDF-SHA256(ikm = sig.r || sig.s, salt = KDF_SALT, info = wallet)
 *   4. Every field of every record is sealed separately with AES-256-GCM (random
 *      96-bit IV; record id + field name as associated data, so ciphertexts can't
 *      be swapped between fields or records).
 *
 * Wallets sign deterministically (RFC 6979), so the same wallet signing the same
 * message always yields the same signature, and therefore the same key. Nobody
 * without the private key can produce that signature, so nobody else can derive
 * the key. A different wallet derives a different key, and GCM rejects it.
 */
import {
  type Address,
  type Hex,
  isAddressEqual,
  numberToBytes,
  parseSignature,
  recoverMessageAddress,
} from 'viem'

const KDF_SALT = 'encr-vault/v1'
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const FIELD_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/
const TOKEN = /^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/ // base64url(12-byte IV).base64url(ct||tag)
const RECORD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/**
 * The exact text the wallet signs. Changing a single byte changes every key, and
 * data encrypted under the old message can no longer be opened.
 */
export function unlockMessage(wallet: Address): string {
  return [
    'Unlock encr vault',
    '',
    'Signing this message creates the key that encrypts and decrypts your data in this browser.',
    'It is not a transaction and costs no gas.',
    '',
    'Only sign this on the encr vault page.',
    '',
    `Wallet: ${wallet}`,
    'Key version: 1',
  ].join('\n')
}

export type PlainRecord = Record<string, unknown>

/**
 * One submitted entry. Only a random id and the field names are readable.
 * It deliberately says nothing about who owns it: a leaked file can't be tied to
 * any wallet. The owner finds their records by trying their key on all of them.
 */
export type EncryptedRecord = {
  id: string
  /** field name -> base64url(iv) + "." + base64url(ciphertext || tag) */
  fields: Record<string, string>
}

/** The JSON file the backend stores and serves. Contains no key, signature, or wallet address. */
export type VaultFile = {
  version: 3
  cipher: 'AES-256-GCM'
  kdf: 'HKDF-SHA256(signature r||s)'
  records: EncryptedRecord[]
}

export function emptyVault(): VaultFile {
  return { version: 3, cipher: 'AES-256-GCM', kdf: 'HKDF-SHA256(signature r||s)', records: [] }
}

export function isEncryptedRecord(value: unknown): value is EncryptedRecord {
  const r = value as EncryptedRecord | null
  if (!r || typeof r.id !== 'string' || !RECORD_ID.test(r.id)) return false
  if (!r.fields || typeof r.fields !== 'object' || Array.isArray(r.fields)) return false
  const entries = Object.entries(r.fields)
  return (
    entries.length > 0 &&
    entries.length <= 64 &&
    entries.every(([name, token]) => FIELD_NAME.test(name) && typeof token === 'string' && TOKEN.test(token))
  )
}

export function isVaultFile(value: unknown): value is VaultFile {
  const f = value as VaultFile | null
  return !!f && f.version === 3 && Array.isArray(f.records) && f.records.every(isEncryptedRecord)
}

/** Recovers the signer of the unlock message and requires it to be `wallet`. */
export async function verifyUnlockSignature(signature: Hex, wallet: Address): Promise<Address> {
  const signer = await recoverMessageAddress({ message: unlockMessage(wallet), signature })
  if (!isAddressEqual(signer, wallet)) {
    throw new Error(`Signature recovers to ${signer}, not ${wallet}.`)
  }
  return signer
}

/** Derives the AES-256-GCM key from a signature. Does not check who signed. */
export async function deriveKey(signature: Hex, wallet: Address): Promise<CryptoKey> {
  const { r, s } = parseSignature(signature)
  // Fold high-s to low-s so both forms of the same signature give the same key.
  let sValue = BigInt(s)
  if (sValue > SECP256K1_N / 2n) sValue = SECP256K1_N - sValue

  // Only r and s go in. v (27/28 vs 0/1) differs between wallets but carries no secret.
  const ikm = new Uint8Array(64)
  ikm.set(numberToBytes(BigInt(r), { size: 32 }), 0)
  ikm.set(numberToBytes(sValue, { size: 32 }), 32)

  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: utf8(KDF_SALT), info: utf8(wallet.toLowerCase()) },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: the raw key never leaves WebCrypto
    ['encrypt', 'decrypt'],
  )
}

/** ECDSA check, then key derivation. This is the only way the app obtains a key. */
export async function unlockKey(signature: Hex, wallet: Address): Promise<CryptoKey> {
  await verifyUnlockSignature(signature, wallet)
  return deriveKey(signature, wallet)
}

/** Encrypts one entry under a fresh random id. Only the holder of `key` can open it. */
export async function encryptRecord(record: PlainRecord, key: CryptoKey): Promise<EncryptedRecord> {
  const id = crypto.randomUUID()
  const fields: Record<string, string> = {}
  for (const [name, value] of Object.entries(record)) {
    if (!FIELD_NAME.test(name)) throw new Error(`Invalid field name "${name}".`)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad(id, name) },
      key,
      padded(JSON.stringify(value)),
    )
    fields[name] = `${toB64url(iv)}.${toB64url(new Uint8Array(sealed))}`
  }
  return { id, fields }
}

/**
 * Pads the plaintext with spaces up to a multiple of PAD_BLOCK bytes, so ciphertext
 * length doesn't reveal how long a name or address is. JSON.parse ignores trailing
 * whitespace, so decryption needs no change, and older unpadded records still open.
 */
const PAD_BLOCK = 64
function padded(text: string): Uint8Array<ArrayBuffer> {
  const bytes = utf8(text)
  const out = new Uint8Array(Math.max(PAD_BLOCK, Math.ceil(bytes.length / PAD_BLOCK) * PAD_BLOCK)).fill(0x20)
  out.set(bytes)
  return out
}

export type FieldResult = { ok: true; value: unknown } | { ok: false }

/**
 * Decrypts each field independently. Every field has its own IV and GCM tag, so
 * a modified field fails on its own and the rest still open. If at least one
 * field opens, the key is right and any failures mean those fields were tampered
 * with. If none open, it's (almost certainly) another wallet's record.
 */
export async function decryptFields(record: EncryptedRecord, key: CryptoKey): Promise<Record<string, FieldResult>> {
  const out: Record<string, FieldResult> = {}
  for (const [name, token] of Object.entries(record.fields)) {
    const [iv, data] = token.split('.')
    try {
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64url(iv), additionalData: aad(record.id, name) },
        key,
        fromB64url(data),
      )
      out[name] = { ok: true, value: JSON.parse(new TextDecoder().decode(plain)) }
    } catch {
      out[name] = { ok: false }
    }
  }
  return out
}

/** Strict version: every field must open, otherwise throws. */
export async function decryptRecord(record: EncryptedRecord, key: CryptoKey): Promise<PlainRecord> {
  const results = await decryptFields(record, key)
  const out: PlainRecord = {}
  for (const [name, r] of Object.entries(results)) {
    if (!r.ok) throw new Error(`Could not decrypt "${name}": this signature is not the key for this data.`)
    out[name] = r.value
  }
  return out
}

/**
 * Loose check for reading the store: the file is a v3 vault, but individual
 * records may be damaged. Callers check each record with isEncryptedRecord, so
 * one edited record doesn't make the rest unreadable.
 */
export function isVaultShape(value: unknown): value is { version: 3; records: unknown[] } {
  const f = value as { version?: unknown; records?: unknown } | null
  return !!f && f.version === 3 && Array.isArray(f.records)
}

// Ciphertext is bound to its record and field, so it can't be moved elsewhere.
// The owner is bound through the key itself (HKDF info = wallet address).
const aad = (id: string, field: string) => utf8(`${id}/${field}`)

function utf8(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>
}

function toB64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromB64url(text: string): Uint8Array<ArrayBuffer> {
  const bin = atob(text.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
