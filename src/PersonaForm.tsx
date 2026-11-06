import { useState } from 'react'
import { FIELDS } from './fields'
import type { PlainRecord } from './lib/vault'

type Props = {
  busy: boolean
  onSubmit: (record: PlainRecord) => void
}

/** Plain-text inputs. The parent remounts it (via `key`) to clear it after a submit. */
export function PersonaForm({ busy, onSubmit }: Props) {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(FIELDS.map((f) => [f.key, ''])),
  )

  return (
    <form
      className="form"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit(values)
      }}
    >
      {FIELDS.map((f) => (
        <label className="row" key={f.key}>
          <span className="label">{f.label}</span>
          <input
            type={f.type}
            value={values[f.key]}
            required={'required' in f && f.required}
            autoComplete="off"
            onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
          />
        </label>
      ))}
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? 'Working…' : 'Encrypt & submit'}
        </button>
      </div>
    </form>
  )
}
