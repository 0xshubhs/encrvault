import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { type Plugin, defineConfig } from 'vite'
import { type EncryptedRecord, emptyVault, isEncryptedRecord, isVaultShape } from './src/lib/vault.ts'

const STORE = fileURLToPath(new URL('./public/api/records.json', import.meta.url))
const MAX_BODY = 64 * 1024
const MAX_RECORDS = 500

/**
 * Dev-only backend: POST /api/records.json appends one encrypted record.
 * GET is served by Vite as a normal public file.
 * It accepts only well-formed ciphertext and never sees plaintext, the signature or the key.
 * Records carry no owner. Only the key that encrypted a record can open it.
 */
function recordStore(): Plugin {
  let queue: Promise<unknown> = Promise.resolve() // one write at a time
  const fail = (status: number, message: string) => Object.assign(new Error(message), { status })

  async function append(record: EncryptedRecord): Promise<number> {
    let vault: unknown
    try {
      vault = JSON.parse(await readFile(STORE, 'utf8'))
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw fail(500, 'Store file is unreadable; not overwriting it.')
      vault = emptyVault() // first record ever
    }
    // Existing records are kept exactly as they are, even damaged ones; we only append.
    if (!isVaultShape(vault)) throw fail(500, 'Store file has an unexpected format; not overwriting it.')
    if (vault.records.some((r) => (r as EncryptedRecord | null)?.id === record.id)) throw fail(409, 'Duplicate record id.')
    if (vault.records.length >= MAX_RECORDS) throw fail(507, 'Store is full.')
    vault.records.push({ id: record.id, fields: record.fields }) // nothing else is stored
    await writeFile(STORE, JSON.stringify(vault, null, 2) + '\n')
    return vault.records.length
  }

  return {
    name: 'record-store',
    configureServer(server) {
      server.middlewares.use('/api/records.json', async (req, res, next) => {
        if (req.method !== 'POST') return next()
        const send = (status: number, body: object) => {
          res.statusCode = status
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(body))
        }

        // Same-origin JSON only, so another website open in your browser can't write here.
        const origin = req.headers.origin
        if (!origin || new URL(origin).host !== req.headers.host) return send(403, { error: 'Cross-origin write refused.' })
        if (!req.headers['content-type']?.startsWith('application/json')) return send(415, { error: 'Expected JSON.' })

        let body = ''
        for await (const chunk of req) {
          body += chunk
          if (body.length > MAX_BODY) return send(413, { error: 'Payload too large.' })
        }

        let record: unknown
        try {
          record = JSON.parse(body)
        } catch {
          return send(400, { error: 'Invalid JSON.' })
        }
        if (!isEncryptedRecord(record)) return send(400, { error: 'Not an encrypted record.' })

        const write = queue.then(() => append(record))
        queue = write.catch(() => {})
        try {
          send(201, { ok: true, count: await write })
        } catch (e) {
          send((e as { status?: number }).status ?? 500, { error: (e as Error).message })
        }
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), recordStore()],
})
