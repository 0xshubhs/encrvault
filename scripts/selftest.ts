/**
 * Tests the scheme end to end with throwaway wallets. Run: npm run selftest
 */
import assert from 'node:assert/strict'
import { type Hex, numberToHex, parseSignature } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import {
  decryptFields,
  decryptRecord,
  deriveKey,
  emptyVault,
  encryptRecord,
  isEncryptedRecord,
  isVaultFile,
  isVaultShape,
  unlockKey,
  unlockMessage,
} from '../src/lib/vault'

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

const aliceData = { fullName: 'Alice Test', email: 'alice@example.com', dateOfBirth: '1990-01-31' }
const bobData = { fullName: 'Bob Test', email: 'bob@example.com', dateOfBirth: '1985-07-04' }

const alice = privateKeyToAccount(generatePrivateKey())
const bob = privateKeyToAccount(generatePrivateKey())
const sign = (acct: typeof alice, forWallet = acct.address) => acct.signMessage({ message: unlockMessage(forWallet) })

async function rejects(fn: () => Promise<unknown>, pattern: RegExp, label: string) {
  await assert.rejects(fn, pattern)
  console.log(`✓ ${label}`)
}

// 1. Same wallet + same message -> same signature (what makes the key reproducible)
const aliceSig = await sign(alice)
assert.equal(await sign(alice), aliceSig)
console.log('✓ signatures are deterministic (RFC 6979)')

// 2. Each wallet encrypts its own record; a later session decrypts it again
const aliceKey = await unlockKey(aliceSig, alice.address)
const bobKey = await unlockKey(await sign(bob), bob.address)
const aliceRec = await encryptRecord(aliceData, aliceKey)
const bobRec = await encryptRecord(bobData, bobKey)
assert.deepEqual(await decryptRecord(aliceRec, await unlockKey(await sign(alice), alice.address)), aliceData)
assert.deepEqual(await decryptRecord(bobRec, bobKey), bobData)
console.log('✓ each wallet can encrypt and later decrypt its own record')

// 3. Wallets can't read each other's records
await rejects(() => decryptRecord(aliceRec, bobKey), /not the key/, "bob's key can't decrypt alice's record")
await rejects(() => decryptRecord(bobRec, aliceKey), /not the key/, "alice's key can't decrypt bob's record")

// 4. Bob can't pass as Alice: a signature over Alice's message by Bob fails the ECDSA check...
const bobAsAlice = await sign(bob, alice.address)
await rejects(() => unlockKey(bobAsAlice, alice.address), /not 0x/, "bob's signature fails ecrecover for alice")
// ...and even with that check skipped, the key he derives is wrong
const bypassKey = await deriveKey(bobAsAlice, alice.address)
await rejects(() => decryptRecord(aliceRec, bypassKey), /not the key/, 'check bypassed: still cannot decrypt')

// 5. Ciphertext length doesn't reveal value length (padding)
const short = await encryptRecord({ fullName: 'Al' }, aliceKey)
const long = await encryptRecord({ fullName: 'Alexandria Montgomery-Fitzwilliam III' }, aliceKey)
assert.equal(short.fields.fullName.length, long.fields.fullName.length)
assert.deepEqual(await decryptRecord(long, aliceKey), { fullName: 'Alexandria Montgomery-Fitzwilliam III' })
console.log('✓ short and long values produce the same ciphertext length')

// 5b. Records encrypted before padding existed still decrypt (same key, AAD, format)
{
  const id = crypto.randomUUID()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`${id}/fullName`) }, aliceKey, new TextEncoder().encode('"Old Record"'))
  const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64url')
  const legacy = { id, fields: { fullName: `${b64(iv)}.${b64(new Uint8Array(ct))}` } }
  assert.deepEqual(await decryptRecord(legacy, aliceKey), { fullName: 'Old Record' })
  console.log('✓ older unpadded records still decrypt')
}

// 6. Nothing readable in the stored file, and it passes validation
const file = { ...emptyVault(), records: [aliceRec, bobRec] }
assert.ok(isVaultFile(file))
const serialized = JSON.stringify(file)
for (const v of [...Object.values(aliceData), ...Object.values(bobData)]) assert.ok(!serialized.includes(v))
assert.ok(!serialized.includes(aliceSig.slice(2, 40)))
for (const a of [alice.address, bob.address]) assert.ok(!serialized.toLowerCase().includes(a.slice(2).toLowerCase()))
console.log('✓ stored file has no plaintext, no signature, and no wallet address')

// 7. Tampering and swapping are detected
const [iv, ct] = aliceRec.fields.fullName.split('.')
const tampered = { ...aliceRec, fields: { ...aliceRec.fields, fullName: `${iv}.${ct[0] === 'A' ? 'B' : 'A'}${ct.slice(1)}` } }
await rejects(() => decryptRecord(tampered, aliceKey), /not the key/, 'tampered ciphertext is rejected')
const swapped = { ...aliceRec, fields: { ...aliceRec.fields, fullName: aliceRec.fields.email, email: aliceRec.fields.fullName } }
await rejects(() => decryptRecord(swapped, aliceKey), /not the key/, 'swapped fields are rejected')
const aliceRec2 = await encryptRecord(aliceData, aliceKey)
const moved = { ...aliceRec2, fields: { ...aliceRec2.fields, fullName: aliceRec.fields.fullName } }
await rejects(() => decryptRecord(moved, aliceKey), /not the key/, 'ciphertext moved between records is rejected')

// 8. Wallet encoding quirks still give the same key: v as 0/1, and high-s form
const { r, s, yParity } = parseSignature(aliceSig)
const vZeroOne = `${r}${s.slice(2)}${numberToHex(yParity, { size: 1 }).slice(2)}` as Hex
assert.deepEqual(await decryptRecord(aliceRec, await unlockKey(vZeroOne, alice.address)), aliceData)
const highS = numberToHex(N - BigInt(s), { size: 32 })
const flippedV = numberToHex(yParity === 0 ? 28 : 27, { size: 1 })
const highSSig = `${r}${highS.slice(2)}${flippedV.slice(2)}` as Hex
assert.deepEqual(await decryptRecord(aliceRec, await unlockKey(highSSig, alice.address)), aliceData)
console.log('✓ v=0/1 and high-s encodings of the same signature give the same key')

// 9. Validator rejects junk the backend might receive
assert.ok(!isEncryptedRecord({ initialized: false }))
assert.ok(!isEncryptedRecord({ ...aliceRec, fields: { fullName: 'Plain Text Name' } }))
assert.ok(!isEncryptedRecord({ ...aliceRec, id: 'not-a-uuid' }))
assert.ok(!isEncryptedRecord({ ...aliceRec, fields: {} }))
console.log('✓ validator rejects non-ciphertext payloads')

// 10. Per-field decryption: tampering one field breaks only that field
{
  const [iv, ct] = aliceRec.fields.email.split('.')
  const oneBad = { ...aliceRec, fields: { ...aliceRec.fields, email: `${iv}.${ct[0] === 'A' ? 'B' : 'A'}${ct.slice(1)}` } }
  const res = await decryptFields(oneBad, aliceKey)
  assert.deepEqual(Object.keys(res).filter((k) => !res[k].ok), ['email'])
  assert.deepEqual(res.fullName, { ok: true, value: aliceData.fullName })
  assert.deepEqual(res.dateOfBirth, { ok: true, value: aliceData.dateOfBirth })
  console.log('✓ one tampered field fails alone; the other fields still decrypt')

  const wrong = await decryptFields(aliceRec, bobKey)
  assert.ok(Object.values(wrong).every((r) => !r.ok))
  console.log("✓ another wallet's key fails every field (shown as 'different wallet')")
}

// 11. A damaged record doesn't make the file unreadable
{
  const file = { ...emptyVault(), records: [aliceRec, { id: 'garbage', fields: 'x' }, bobRec] }
  assert.ok(!isVaultFile(file)) // strict check fails...
  assert.ok(isVaultShape(file)) // ...but the loose read still works
  assert.deepEqual(file.records.map((r) => isEncryptedRecord(r)), [true, false, true])
  console.log('✓ one damaged record is isolated; the rest stay readable')
}

console.log('\nAll checks passed.')
