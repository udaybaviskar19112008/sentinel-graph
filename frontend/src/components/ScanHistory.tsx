import { Download, RefreshCw, TriangleAlert } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { VerdictPill } from '@/components/VerdictCard'
import { downloadText, historyCsv } from '@/lib/exports'
import { fetchAllScans, fetchScans, type Indicator, type IndicatorType, type Scan } from '@/lib/historyApi'
import { cn } from '@/lib/utils'

const SHOWN_INDICATORS = 3
const SKELETON_ROWS = 6
const PAGE_SIZE = 50 // fetchScans asks for one page of this many

const TYPE_LABEL: Record<IndicatorType, string> = { IP: 'IP', URL: 'URL', DOMAIN: 'Domain' }

const pad = (n: number) => String(n).padStart(2, '0')

/** Local time in ISO order (2026-10-31 23:46), so the rows compare digit for digit. */
function isoLocal(timestamp: string): string {
  const d = new Date(timestamp)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function clock(d: Date): string {
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** Addresses and domains are identifiers, so they keep the monospace; a flagged one is the row's one red mark. */
function Indicators({ indicators }: { indicators: Indicator[] }) {
  if (indicators.length === 0) return <span className="text-muted">—</span>
  const hidden = indicators.length - SHOWN_INDICATORS
  return (
    <ul className="flex flex-wrap gap-1.5" title={indicators.map((i) => `${i.type}: ${i.value}`).join('\n')}>
      {indicators.slice(0, SHOWN_INDICATORS).map((indicator) => (
        <li
          key={`${indicator.type}:${indicator.value}`}
          className={cn(
            'max-w-[16rem] truncate rounded bg-raised px-1.5 py-0.5 font-mono text-body',
            indicator.malicious_flag ? 'text-negative' : 'text-ink',
          )}
        >
          <span className="font-sans text-muted">{TYPE_LABEL[indicator.type]} </span>
          {indicator.value}
        </li>
      ))}
      {hidden > 0 && <li className="py-0.5 text-small text-muted">+{hidden} more</li>}
    </ul>
  )
}

function Bar({ className }: { className: string }) {
  return <span className={cn('block h-3.5 rounded bg-raised', className)} aria-hidden="true" />
}

/**
 * Past scans from the history API, newest first, with a manual refresh and a CSV of every
 * saved scan. The language-model verdict column is what the history database stores.
 */
export function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [updated, setUpdated] = useState<Date | null>(null)
  const [exporting, setExporting] = useState<{ busy: boolean; message: string | null }>({ busy: false, message: null })
  // Bumped by the refresh button; each value runs the fetch effect once more.
  const [generation, setGeneration] = useState(0)

  useEffect(() => {
    // Cleanup aborts this request when a refresh supersedes it or the page unmounts,
    // so a slow response can never overwrite a fresher one.
    const controller = new AbortController()
    fetchScans(controller.signal).then(
      (fetched) => {
        setScans(fetched)
        setUpdated(new Date())
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

  const exportAll = async () => {
    setExporting({ busy: true, message: null })
    try {
      const all = await fetchAllScans()
      downloadText(historyCsv(all), 'sentinel-history.csv', 'text/csv;charset=utf-8')
      setExporting({ busy: false, message: `${all.length} scan${all.length === 1 ? '' : 's'} exported to sentinel-history.csv` })
    } catch (caught) {
      setExporting({ busy: false, message: caught instanceof Error ? caught.message : 'History could not be loaded' })
    }
  }

  // A refresh keeps the rows already on screen; only the first load shows the skeleton.
  const firstLoad = loading && scans.length === 0
  const count = firstLoad
    ? 'Loading the scan log…'
    : scans.length === 0
      ? 'No scans recorded yet.'
      : scans.length >= PAGE_SIZE
        ? `The ${scans.length} most recent scans, newest first; the CSV holds every saved scan.`
        : `${scans.length} scan${scans.length === 1 ? '' : 's'}, newest first.`

  return (
    <section className="border-t border-line py-8" aria-labelledby="scan-history-title">
      <header className="mb-4 flex flex-wrap items-end justify-between gap-x-8 gap-y-3">
        <div>
          <h2 id="scan-history-title" className="text-card font-medium text-ink">
            Scan history
          </h2>
          <p className="mt-1 text-body text-muted">{count}</p>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          {updated && <p className="text-small text-muted">Updated {clock(updated)}</p>}
          <button type="button" onClick={refresh} disabled={loading} className="btn btn-secondary">
            <RefreshCw className={cn('h-4 w-4', loading && 'motion-safe:animate-spin')} strokeWidth={1.75} aria-hidden="true" />
            Refresh
          </button>
          <button type="button" onClick={() => void exportAll()} disabled={exporting.busy} className="btn btn-secondary">
            <Download className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
            {exporting.busy ? 'Collecting…' : 'Download CSV'}
          </button>
        </div>
      </header>
      {exporting.message && (
        <p className="-mt-2 mb-3 text-small text-muted" role="status">
          {exporting.message}
        </p>
      )}

      <div className="card px-0 py-2">
        {error && (
          <p role="alert" className="flex items-start gap-2 px-5 py-3 text-body text-ink">
            <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-negative" aria-hidden="true" />
            <span>
              Couldn’t load the scan history ({error}).{' '}
              <button type="button" className="text-action" onClick={refresh}>
                Retry
              </button>
            </span>
          </p>
        )}

        <table className="hidden w-full border-collapse text-left text-body md:table">
          <thead className="sticky top-0 z-10 bg-surface text-small text-muted">
            <tr>
              <th className="h-[38px] border-b border-line pl-5 pr-3 font-normal">Email</th>
              <th className="border-b border-line px-3 font-normal">Verdict</th>
              <th className="border-b border-line px-3 text-right font-normal">Risk</th>
              <th className="border-b border-line px-3 font-normal">Indicators</th>
              <th className="border-b border-line pl-3 pr-5 text-right font-normal">Scanned</th>
            </tr>
          </thead>
          <tbody>
            {firstLoad &&
              Array.from({ length: SKELETON_ROWS }, (_, index) => (
                <tr key={index} className="border-b border-rule last:border-b-0">
                  <td className="py-3 pl-5 pr-3">
                    <Bar className="w-64" />
                    <Bar className="mt-1.5 w-40" />
                  </td>
                  <td className="px-3 py-3">
                    <Bar className="w-16" />
                  </td>
                  <td className="px-3 py-3">
                    <Bar className="ml-auto w-6" />
                  </td>
                  <td className="px-3 py-3">
                    <Bar className="w-72" />
                  </td>
                  <td className="py-3 pl-3 pr-5">
                    <Bar className="ml-auto w-28" />
                  </td>
                </tr>
              ))}
            {scans.map((scan) => (
              <tr key={scan.id} className="border-b border-rule align-top last:border-b-0">
                <td className="max-w-[22rem] py-3 pl-5 pr-3">
                  <p className="truncate text-ink" title={scan.subject ?? undefined}>
                    {scan.subject ?? <span className="text-muted">(no subject)</span>}
                  </p>
                  {scan.sender && <p className="truncate text-small text-muted">{scan.sender}</p>}
                </td>
                <td className="px-3 py-3">
                  <VerdictPill verdict={scan.final_verdict} />
                </td>
                <td className="px-3 py-3 text-right text-ink">{scan.overall_risk}</td>
                <td className="px-3 py-3">
                  <Indicators indicators={scan.indicators} />
                </td>
                <td className="whitespace-nowrap py-3 pl-3 pr-5 text-right text-muted">{isoLocal(scan.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Below 768px the table becomes two-line rows: the email and its risk, then the rest. */}
        <ul className="md:hidden">
          {firstLoad &&
            Array.from({ length: SKELETON_ROWS }, (_, index) => (
              <li key={index} className="border-b border-rule px-4 py-3 last:border-b-0">
                <Bar className="w-48" />
                <Bar className="mt-2 w-32" />
              </li>
            ))}
          {scans.map((scan) => (
            <li key={scan.id} className="border-b border-rule px-4 py-3 last:border-b-0">
              <p className="flex items-baseline justify-between gap-3">
                <span className="truncate text-ink">{scan.subject ?? '(no subject)'}</span>
                <span className="text-ink">{scan.overall_risk}</span>
              </p>
              <p className="mt-1 flex items-center gap-2 text-small text-muted">
                <VerdictPill verdict={scan.final_verdict} />
                <span className="truncate">{scan.sender ?? '—'}</span>
              </p>
              <p className="mt-1 text-small text-muted">
                {isoLocal(scan.timestamp)} · {scan.indicators.length} indicator{scan.indicators.length === 1 ? '' : 's'}
              </p>
            </li>
          ))}
        </ul>

        {!loading && !error && scans.length === 0 && (
          <p className="px-5 py-4 text-body text-muted">
            No scans recorded yet.{' '}
            <Link to="/" className="text-action">
              Analyse an email
            </Link>{' '}
            to start the log.
          </p>
        )}
      </div>
    </section>
  )
}
