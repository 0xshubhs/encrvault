import { useCallback, useEffect, useRef, useState } from 'react'
import type { Address } from 'viem'
import {
  type EncryptedRecord,
  type FieldResult,
  type PlainRecord,
  decryptFields,
  encryptRecord,
  isEncryptedRecord,
  isVaultShape,
  unlockKey,
} from './lib/vault'
import { connectWallet, errorMessage, shortAddress, signUnlockMessage, watchAccounts } from './lib/wallet'
import { fieldLabel } from './fields'
import { PersonaForm } from './PersonaForm'

const API_URL = '/api/records.json'

/** `records` are unchecked: each is validated on its own, so one damaged record can't hide the rest. */
type Vault = { records: unknown[] }
type Load = { status: 'loading' } | { status: 'ready'; vault: Vault } | { status: 'error'; message: string }
type Session = { wallet: Address; key: CryptoKey }
/**
 * Records the current wallet has tried to open, by id. Missing = not tried yet.
 * ok: the key is right (at least one field opened); fields that failed were tampered with.
 */
type Opened = Record<string, { ok: true; fields: Record<string, FieldResult>; tampered: string[] } | { ok: false }>

const show = (v: unknown) => (typeof v === 'string' ? v || '—' : JSON.stringify(v))

export default function App() {
  const [load, setLoad] = useState<Load>({ status: 'loading' })
  const [unlockedAs, setUnlockedAs] = useState<Address | null>(null)
  const [opened, setOpened] = useState<Opened>({})
  const [busy, setBusy] = useState<string | null>(null) // 'submit' or a record id
  const [steps, setSteps] = useState<string[]>([])
  const [notice, setNotice] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [formKey, setFormKey] = useState(0)
  // Held in memory only while unlocked. The key is non-extractable and never stored or sent.
  const session = useRef<Session | null>(null)

  const fetchVault = useCallback(async (signal?: AbortSignal): Promise<Vault | null> => {
    try {
      const res = await fetch(API_URL, { cache: 'no-store', signal })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const body = await res.json()
      console.log(`[vault] GET ${API_URL} →`, body)
      if (!isVaultShape(body)) throw new Error('Unexpected file format.')
      setLoad({ status: 'ready', vault: body })
      return body
    } catch (e) {
      if (!signal?.aborted) setLoad({ status: 'error', message: errorMessage(e) })
      return null
    }
  }, [])

  useEffect(() => {
    const ctrl = new AbortController()
    fetchVault(ctrl.signal)
    return () => ctrl.abort()
  }, [fetchVault])

  const lock = useCallback(() => {
    session.current = null
    setUnlockedAs(null)
    setOpened({})
    setSteps([])
    setNotice(null)
    setError(null)
  }, [])

  // The key belongs to one wallet. Switching accounts in the wallet locks the page.
  useEffect(
    () =>
      watchAccounts(() => {
        if (!session.current) return
        lock()
        setNotice('Wallet switched, so the page locked. Decrypt again to use the new wallet.')
      }),
    [lock],
  )

  const step = (s: string) => setSteps((prev) => [...prev, s])

  // Reuses the unlocked key, or: connect → sign → ecrecover check → derive key.
  // The signature is dropped right after.
  async function getSession(): Promise<Session> {
    if (session.current) return session.current
    setSteps([])
    const wallet = await connectWallet()
    step(`Wallet connected: ${wallet}`)
    const signature = await signUnlockMessage(wallet)
    step('Unlock message signed (ECDSA, secp256k1)')
    const key = await unlockKey(signature, wallet)
    step(`ecrecover matches ${shortAddress(wallet)}. AES-256-GCM key derived from the signature.`)
    session.current = { wallet, key }
    setUnlockedAs(wallet)
    return session.current
  }

  async function run(tag: string, action: () => Promise<void>) {
    setBusy(tag)
    setError(null)
    setNotice(null)
    try {
      await action()
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(null)
    }
  }

  const decryptOne = (rec: EncryptedRecord, n: number) =>
    run(rec.id, async () => {
      const s = await getSession()
      const fields = await decryptFields(rec, s.key)
      const names = Object.keys(fields)
      const tampered = names.filter((name) => !fields[name].ok)

      if (tampered.length === names.length) {
        setOpened((o) => ({ ...o, [rec.id]: { ok: false } }))
        step(`Record #${n}: ${shortAddress(s.wallet)}’s key can’t open it. It was encrypted by a different wallet.`)
        return
      }
      setOpened((o) => ({ ...o, [rec.id]: { ok: true, fields, tampered } }))
      step(
        tampered.length
          ? `Record #${n}: ${names.length - tampered.length} field(s) decrypted. ${tampered.map(fieldLabel).join(', ')} failed the integrity check: modified after encryption.`
          : `Record #${n} decrypted in this browser.`,
      )
    })

  const hide = (id: string) =>
    setOpened((o) => {
      const { [id]: _, ...rest } = o
      return rest
    })

  const submit = (record: PlainRecord) =>
    run('submit', async () => {
      const s = await getSession()
      const encrypted = await encryptRecord(record, s.key)
      step(`${Object.keys(encrypted.fields).length} fields encrypted in this browser with ${shortAddress(s.wallet)}’s key`)
      console.log(`[vault] POST ${API_URL} (ciphertext only) →`, encrypted)

      const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(encrypted),
      })
      if (!res.ok) {
        const msg = (await res.json().catch(() => null))?.error
        throw new Error(msg ?? `Submit failed (HTTP ${res.status}). The backend runs only under npm run dev.`)
      }
      step(`Submitted to POST ${API_URL}. The backend received only ciphertext.`)
      setFormKey((k) => k + 1)
      await fetchVault()
      setNotice(`Saved encrypted. Only ${shortAddress(s.wallet)} can decrypt it.`)
    })

  const vault = load.status === 'ready' ? load.vault : null

  return (
    <main className="shell">
      <header className="head">
        <div>
          <h1>Persona vault</h1>
          <p className="sub">
            Records are encrypted in your browser with a key from your wallet’s signature. Any wallet can submit; only
            the wallet that submitted a record can decrypt it. Stored records don’t say which wallet they belong to.
          </p>
        </div>
        <span className={`badge ${unlockedAs ? 'is-open' : ''}`} title={unlockedAs ?? undefined}>
          {unlockedAs ? `Unlocked · ${shortAddress(unlockedAs)}` : 'Locked'}
        </span>
      </header>

      {unlockedAs && (
        <div className="session">
          <span>
            Key for <code title={unlockedAs}>{shortAddress(unlockedAs)}</code> is in memory. Switch accounts in your
            wallet to try another one.
          </span>
          <button className="secondary small" onClick={lock}>
            Lock
          </button>
        </div>
      )}

      <section className="section">
        <div className="section-head">
          <h2>New record</h2>
          <code className="meta">POST {API_URL}</code>
        </div>
        <p className="hint">
          Type in plain text.{' '}
          {unlockedAs
            ? `It will be encrypted with ${shortAddress(unlockedAs)}’s key (no new signature needed).`
            : 'It will be encrypted with the key of the wallet that signs.'}{' '}
          Only random-looking values reach the backend.
        </p>
        <PersonaForm key={formKey} busy={busy === 'submit'} onSubmit={submit} />
      </section>

      {(notice || error || steps.length > 0) && (
        <div className="status">
          {notice && <p className="notice">{notice}</p>}
          {error && (
            <p className="alert" role="alert">
              {error}
            </p>
          )}
          {steps.length > 0 && (
            <ol className="steps">
              {steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
          )}
        </div>
      )}

      <section className="section">
        <div className="section-head">
          <h2>Stored records {vault && <span className="count">{vault.records.length}</span>}</h2>
          <code className="meta">GET {API_URL}</code>
        </div>

        {load.status === 'loading' && <p className="muted">Loading…</p>}
        {load.status === 'error' && (
          <p className="alert" role="alert">
            Couldn’t load {API_URL}: {load.message}
          </p>
        )}
        {vault && vault.records.length === 0 && <p className="muted">Nothing stored yet.</p>}

        {vault?.records.map((rec, i) => {
          const n = i + 1
          if (!isEncryptedRecord(rec)) {
            return (
              <article className="record is-denied" key={`damaged-${i}`}>
                <div className="record-head">
                  <span>#{n} · damaged record</span>
                </div>
                <p className="denied">
                  This record was edited into an invalid format, so it can’t be read. The other records are unaffected.
                </p>
              </article>
            )
          }
          const view = opened[rec.id]
          return (
            <article className={`record ${view?.ok ? 'is-open' : view ? 'is-denied' : ''}`} key={rec.id}>
              <div className="record-head">
                <span>
                  #{n} · <code>{rec.id}</code>
                  {view?.ok && <span className="you">yours</span>}
                </span>
                {view?.ok ? (
                  <button className="secondary small" onClick={() => hide(rec.id)}>
                    Hide
                  </button>
                ) : (
                  <button className="small" onClick={() => decryptOne(rec, n)} disabled={busy !== null}>
                    {busy === rec.id ? 'Waiting for wallet…' : view ? 'Try again' : 'Decrypt'}
                  </button>
                )}
              </div>

              {view && !view.ok && unlockedAs && (
                <p className="denied">
                  Can’t decrypt with <code>{shortAddress(unlockedAs)}</code>. This record was encrypted by a different
                  wallet. Switch to that wallet in MetaMask and try again.
                </p>
              )}

              {view?.ok && view.tampered.length > 0 && (
                <p className="denied">
                  {view.tampered.length} field(s) were modified after encryption and can’t be trusted. The other fields
                  passed their integrity check.
                </p>
              )}

              <dl className="fields">
                {Object.entries(rec.fields).map(([key, token]) => {
                  const field = view?.ok ? view.fields[key] : undefined
                  return (
                    <div className="row" key={key}>
                      <dt className="label">{fieldLabel(key)}</dt>
                      <dd>
                        {field?.ok ? (
                          <span className="plain">{show(field.value)}</span>
                        ) : field ? (
                          <span className="tampered">Tampered: failed integrity check</span>
                        ) : (
                          <code className="cipher">{token}</code>
                        )}
                      </dd>
                    </div>
                  )
                })}
              </dl>
            </article>
          )
        })}

        {vault && vault.records.length > 0 && (
          <p className="meta footnote">AES-256-GCM · key = HKDF-SHA256(ECDSA signature) · decrypted only in this browser</p>
        )}
      </section>
    </main>
  )
}
