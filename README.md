# Persona vault

A React (Vite) page where you type records in plain text. They're encrypted in
the browser, stored by the backend as ciphertext, and decrypted only in the
browser. Any wallet can submit records. Each record can only be decrypted by the
wallet that submitted it.

```bash
npm install
npm run dev        # http://localhost:5173
```

## Demo with several wallets

1. In MetaMask, pick **account A**, fill in the form, click **Encrypt & submit**, and sign.
2. Switch to **account B** and submit another record.
3. Every record shows up as random values (page, network tab, console, DOM).
4. Click **Decrypt** on a record. If it's yours it opens. If not, the card says it
   was encrypted by a different wallet. Switching accounts locks the page.

The page doesn't know who owns a record, because no owner is stored. It simply
tries your key, and other wallets' records fail because the key is wrong.

## What a breach of the backend gets

`records.json` holds, per record, a random `id` and `iv.ciphertext` per field.
It contains no signature, no key, no wallet address and no plaintext. Values are
padded to 64-byte blocks, so ciphertext length doesn't reveal how long a value is.
Only the field names and the number of records are visible.

## How the key works

1. The wallet `personal_sign`s an unlock message that includes its own address (ECDSA, secp256k1).
2. `ecrecover` must return that same address.
3. key = `HKDF-SHA256(signature r‖s, info = address)`, a non-extractable
   WebCrypto AES-256-GCM key held only in memory. The signature is discarded right away.

Wallets sign deterministically (RFC 6979), so a wallet always gets the same key.
Without its private key nobody can produce that signature. Record id + field
name are bound into each ciphertext, so values can't be swapped between fields
or records. `npm run selftest` checks all of this with throwaway wallets.

**Tampering.** Each field has its own IV and integrity tag and is decrypted on
its own. Editing one field marks just that field **Tampered** while the rest
still open. A record edited into an invalid format shows as damaged without
affecting the others. If no field opens, the record belongs to another wallet.
Deleting a whole field isn't detected; the record just shows fewer fields.

## Quantum

- **AES-256-GCM and SHA-256 are considered quantum-safe.** Grover's algorithm
  only halves their strength, which leaves ~128-bit security.
- **The wallet is the weak link.** secp256k1 ECDSA is breakable by Shor's
  algorithm on a large enough quantum computer, which doesn't exist today. An
  attacker would need the wallet's **public key**, which can't be computed from
  the address. But it becomes public as soon as the wallet sends any transaction
  on any chain, or a signature from it is published.
- So stolen ciphertext + address is safe for a wallet whose public key has never
  been exposed. For a wallet that has transacted, a future quantum attacker could
  recover the private key and then decrypt ("harvest now, decrypt later"). The
  same attacker could also take the wallet's funds.
- To be quantum-safe regardless, the key needs a second secret that isn't based on
  elliptic curves, such as a passphrase mixed into the key derivation.

## Things to know

- **The signature is the key.** Anyone who gets a wallet to sign this exact
  message, for example on a phishing page, can decrypt that wallet's records.
- **Whoever controls the page's code controls the data.** If the server that
  serves the JavaScript is breached, the attacker can ship code that reads what
  you type or decrypt. This applies to all in-browser encryption. Host the
  frontend separately from the data, over HTTPS, with integrity checks.
- **Lost wallet = lost data.** There is no backdoor or recovery.
- The backend exists only under `npm run dev`. It refuses other origins and
  anything that isn't well-formed ciphertext, and won't overwrite a store file it
  can't read. A breach can still **delete** records, so keep backups.
- Smart-contract wallets (Safe, ERC-4337) don't produce `ecrecover`-able
  signatures and won't work. MetaMask, Rabby, Rainbow, Coinbase Wallet (EOA) and
  Ledger do.

| File | |
|---|---|
| `src/lib/vault.ts` | all crypto + record format validation |
| `src/lib/wallet.ts` | wallet connect, sign, account switching |
| `src/App.tsx`, `src/PersonaForm.tsx`, `src/fields.ts` | UI |
| `vite.config.ts` | dev-only `POST /api/records.json` backend |
| `scripts/selftest.ts` | end-to-end checks with throwaway wallets |
# encrvault
