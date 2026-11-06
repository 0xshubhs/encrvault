export const FIELDS = [
  { key: 'fullName', label: 'Full name', type: 'text', required: true },
  { key: 'email', label: 'Email', type: 'email' },
  { key: 'dateOfBirth', label: 'Date of birth', type: 'date' },
  { key: 'phone', label: 'Phone', type: 'tel' },
  { key: 'address', label: 'Address', type: 'text' },
  { key: 'nationality', label: 'Nationality', type: 'text' },
  { key: 'occupation', label: 'Occupation', type: 'text' },
] as const

// Known keys get their label; anything else: "bloodGroup" -> "Blood group"
export function fieldLabel(key: string): string {
  const known = FIELDS.find((f) => f.key === key)
  if (known) return known.label
  const words = key.replace(/([A-Z])/g, ' $1').toLowerCase()
  return words.charAt(0).toUpperCase() + words.slice(1)
}
