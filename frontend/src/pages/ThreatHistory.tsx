import { RefreshCw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { cn } from '@/lib/utils'
import type { VerdictLevel } from '@/store/useThreatStore'

// Mirrors ScanOut / IndicatorOut in src/api/routers/history.py; change both sides together.
type IndicatorType = 'IP' | 'URL' | 'DOMAIN'

interface Indicator {
  type: IndicatorType
  value: string
  malicious_flag: boolean
}

interface Scan {
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
const SHOWN_INDICATORS = 3

const VERDICT_BADGE: Record<VerdictLevel, string> = {
  BENIGN: 'bg-cyber-safe/20 text-cyber-safe border-cyber-safe',
  SUSPICIOUS: 'bg-cyber-warning/10 text-cyber-warning border-cyber-warning/60',
  PHISHING: 'bg-cyber-alert/10 text-cyber-alert border-cyber-alert/60',
  CRITICAL: 'bg-cyber-alert/20 text-cyber-alert border-cyber-alert',
}

function riskColor(risk: number): string {
  if (risk >= 75) return 'text-cyber-alert'
  if (risk >= 40) return 'text-cyber-warning'
  return 'text-cyber-safe'
}

async function fetchScans(signal: AbortSignal): Promise<Scan[]> {
  const response = await fetch(SCANS_URL, { signal })
  if (!response.ok) throw new Error(`History API answered ${response.status}`)
  return (await response.json()) as Scan[]
}

const timestampFormat =new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' })

function Indicators({ indicators }: { indicators: Indicator[] }) {
  if (indicators.length === 0) return <span className="text-stone-500">none</span>
  const hidden = indicators.length - SHOWN_INDICATORS
  return (
    <ul className="flex flex-wrap gap-1" title={indicators.map((i) => `${i.type}: ${i.value}`).join('\n')}>
      {indicators.slice(0, SHOWN_INDICATORS).map((indicator) => (
        <li
          key={`${indicator.type}:${indicator.value}`}
          className={cn(
            'max-w-[16rem] truncate rounded border px-1.5 py-0.5 font-mono text-[11px]',
            indicator.malicious_flag ? 'border-cyber-alert/50 text-cyber-alert' : 'border-glass-border text-stone-400',
          )}
        >
          <span className="text-stone-500">{indicator.type} </span>
          {indicator.value}
        </li>
      ))}
      {hidden > 0 && <li className="px-1 py-0.5 text-[11px] text-stone-500">+{hidden} more</li>}
    </ul>
  )
}

/** Past scans from the history API, newest first, with a manual refresh. */
export function ThreatHistory() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Bumped by the refresh button; each value runs the fetch effect once more.
  const [generation, setGeneration] = useState(0)

  useEffect(() => {
    // Cleanup aborts this request when a refresh supersedes it or the page unmounts,
    // so a slow response can never overwrite a fresher one.
    const controller = new AbortController()
    fetchScans(controller.signal).then(
      (fetched) => {
        setScans(fetched)
        setLoading(false)
      },
      (caught: unknown) => {
        if (controller.signal.aborted) return
        setError(caught instanceof Error ? caught.message : 'History could not be loaded')
        setLoading(false)
      },
    )
    return () => controller.abort()
  }, [generation])

  const refresh = () => {
    setLoading(true)
    setError(null)
    setGeneration((current) => current + 1)
  }

  return (
    <div className="glass-panel pointer-events-auto flex h-full w-full flex-col overflow-hidden p-6">
      <header className="mb-4 flex items-center justify-between border-b border-cyber-accent/40 pb-3 shadow-[0_8px_16px_-12px_rgba(240,171,252,0.45)]">
        <h1 className="font-mono text-lg uppercase tracking-[0.25em] text-white">
          Global Threat Intelligence Log
        </h1>
        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          aria-label="Refresh scan history"
          className="flex items-center gap-2 rounded-md border border-glass-border px-3 py-1.5 text-xs uppercase tracking-widest text-stone-300 transition-colors hover:border-cyber-accent/60 hover:text-cyber-accent disabled:opacity-50"
        >
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} aria-hidden="true" />
          Refresh
        </button>
      </header>

      {error && (
        <p role="alert" className="mb-3 rounded-md border border-cyber-alert/50 bg-cyber-alert/10 px-3 py-2 text-sm text-cyber-alert">
          {error}
        </p>
      )}

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-left text-sm">
          <thead className="sticky top-0 bg-cyber-bg/90 text-[10px] uppercase tracking-[0.2em] text-stone-400 backdrop-blur">
            <tr>
              <th className="px-3 py-2 font-normal">Timestamp</th>
              <th className="px-3 py-2 font-normal">Target subject</th>
              <th className="px-3 py-2 font-normal">Final verdict</th>
              <th className="px-3 py-2 text-right font-normal">Risk score</th>
              <th className="px-3 py-2 font-normal">Indicators</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id} className="border-b border-white/5 align-top transition-colors hover:bg-white/5">
                <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-stone-400">
                  {timestampFormat.format(new Date(scan.timestamp))}
                </td>
                <td className="max-w-md px-3 py-2">
                  <p className="truncate" title={scan.subject ?? undefined}>
                    {scan.subject ?? <span className="text-stone-500">(no subject)</span>}
                  </p>
                  {scan.sender && <p className="truncate text-xs text-stone-400">{scan.sender}</p>}
                </td>
                <td className="px-3 py-2">
                  <span
                    className={cn(
                      'inline-block rounded-md border px-2 py-1 font-mono text-xs',
                      VERDICT_BADGE[scan.final_verdict],
                    )}
                  >
                    {scan.final_verdict}
                  </span>
                </td>
                <td className={cn('px-3 py-2 text-right font-mono', riskColor(scan.overall_risk))}>
                  {scan.overall_risk}
                </td>
                <td className="px-3 py-2">
                  <Indicators indicators={scan.indicators} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && !error && scans.length === 0 && (
          <p className="py-10 text-center text-sm text-stone-400">No scans recorded yet. Analyse an email to start the log.</p>
        )}
      </div>
    </div>
  )
}
