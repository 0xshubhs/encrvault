import { type Address, type Hex, getAddress, toHex } from 'viem'
import { unlockMessage } from './vault'

type Eip1193Provider = {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>
  on?(event: 'accountsChanged', listener: (accounts: string[]) => void): void
  removeListener?(event: 'accountsChanged', listener: (accounts: string[]) => void): void
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider
  }
}

function provider(): Eip1193Provider {
  if (typeof window === 'undefined' || !window.ethereum) {
    throw new Error('No browser wallet found. Install MetaMask (or another injected wallet) and reload.')
  }
  return window.ethereum
}

export const shortAddress = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`

/** Connects and returns the wallet's currently selected account. */
export async function connectWallet(): Promise<Address> {
  const accounts = (await provider().request({ method: 'eth_requestAccounts' })) as string[]
  if (!accounts[0]) throw new Error('No account selected in your wallet.')
  return getAddress(accounts[0])
}

/** Asks the wallet to personal_sign the unlock message for this account. */
export async function signUnlockMessage(account: Address): Promise<Hex> {
  return (await provider().request({
    method: 'personal_sign',
    params: [toHex(unlockMessage(account)), account],
  })) as Hex
}

/** Calls `onChange` when the user switches accounts in the wallet. Returns an unsubscribe. */
export function watchAccounts(onChange: () => void): () => void {
  const eth = typeof window !== 'undefined' ? window.ethereum : undefined
  if (!eth?.on) return () => {}
  eth.on('accountsChanged', onChange)
  return () => eth.removeListener?.('accountsChanged', onChange)
}

export function errorMessage(e: unknown): string {
  const err = e as { code?: number; message?: string } | null
  if (err?.code === 4001) return 'You rejected the request in your wallet.'
  if (err?.code === -32002) return 'Your wallet already has a pending request. Open it and respond.'
  return err?.message ?? String(e)
}
