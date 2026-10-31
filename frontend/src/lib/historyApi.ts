import type { VerdictLevel } from '@/store/useThreatStore'

// Mirrors ScanOut / IndicatorOut in src/api/routers/history.py; change both sides together.
export type IndicatorType = 'IP' | 'URL' | 'DOMAIN'

export interface Indicator {
  type: IndicatorType
  value: string
  malicious_flag: boolean
}

export interface Scan {
  id: number
  timestamp: string // ISO 8601, UTC
  subject: string | null
  sender: string | null
  final_verdict: VerdictLevel
  overall_risk: number // 0-100
  analyst_trace: string
  indicators: Indicator[]
}

const SCANS_URL = '/api/v1/history/scans'
const MAX_PAGE = 200 // history.py MAX_PAGE: the most rows the API returns per request

async function fetchPage(skip: number, limit: number, signal?: AbortSignal): Promise<Scan[]> {
  const response = await fetch(`${SCANS_URL}?skip=${skip}&limit=${limit}`, { signal })
  if (!response.ok) throw new Error(`History API answered ${response.status}`)
  return (await response.json()) as Scan[]
}

/** The newest scans, one page (the history log's view). */
export function fetchScans(signal: AbortSignal): Promise<Scan[]> {
  return fetchPage(0, 50, signal)
}

/** Every scan, newest first, paging through the API (stops at `cap` rows). */
export async function fetchAllScans(signal?: AbortSignal, cap = 10_000): Promise<Scan[]> {
  const scans: Scan[] = []
  while (scans.length < cap) {
    const page = await fetchPage(scans.length, MAX_PAGE, signal)
    scans.push(...page)
    if (page.length < MAX_PAGE) break
  }
  return scans.slice(0, cap)
}
