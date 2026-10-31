import { Download, FileJson, FileSpreadsheet, History, type LucideIcon } from 'lucide-react'
import { useState } from 'react'
import { assessmentReport, downloadText, historyCsv, metricsCsv } from '@/lib/exports'
import { fetchAllScans } from '@/lib/historyApi'
import { useThreatStore } from '@/store/useThreatStore'

const SECTION_TITLE = 'text-[10px] uppercase tracking-[0.3em] text-stone-400'

/** A large export action: the download icon slides in and the title glows on hover or focus. */
function ExportButton({
  icon: Icon,
  title,
  description,
  onClick,
  disabled = false,
}: {
  icon: LucideIcon
  title: string
  description: string
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="group relative flex w-full cursor-pointer items-center gap-4 overflow-hidden rounded-lg border border-white/10 bg-white/5 px-6 py-3 text-left transition-all duration-300 hover:border-emerald-500 hover:bg-white/10 focus-visible:border-emerald-500 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-white/10 disabled:hover:bg-white/5"
    >
      <Icon className="h-6 w-6 shrink-0 text-stone-300 transition-colors duration-300 group-hover:text-emerald-400 group-focus-visible:text-emerald-400" aria-hidden="true" />
      <span className="min-w-0 flex-1">
        <span className="block text-sm text-white transition-[text-shadow] duration-300 group-hover:[text-shadow:0_0_14px_rgba(16,185,129,0.6)] group-focus-visible:[text-shadow:0_0_14px_rgba(16,185,129,0.6)]">
          {title}
        </span>
        <span className="block text-xs text-stone-400">{description}</span>
      </span>
      <Download
        className="h-4 w-4 shrink-0 -translate-x-3 text-emerald-400 opacity-0 transition-all duration-300 group-hover:translate-x-0 group-hover:opacity-100 group-focus-visible:translate-x-0 group-focus-visible:opacity-100"
        aria-hidden="true"
      />
    </button>
  )
}

/** Client-side exports: the current assessment as JSON and CSV, and the whole scan history as CSV. */
export function Reports() {
  const assessment = useThreatStore((s) => s.assessment)
  const details = useThreatStore((s) => s.details)
  const [history, setHistory] = useState<{ busy: boolean; message: string | null }>({ busy: false, message: null })
  const ready = assessment !== null && details !== null

  const exportJSON = () => {
    if (!assessment || !details) return
    downloadText(JSON.stringify(assessmentReport(assessment, details), null, 2), 'sentinel-report.json', 'application/json')
  }

  const exportCSV = () => {
    if (!assessment || !details) return
    downloadText(metricsCsv(assessment, details), 'sentinel-metrics.csv', 'text/csv;charset=utf-8')
  }

  const exportHistory = async () => {
    setHistory({ busy: true, message: null })
    try {
      const scans = await fetchAllScans()
      downloadText(historyCsv(scans), 'sentinel-history.csv', 'text/csv;charset=utf-8')
      setHistory({ busy: false, message: `${scans.length} scan${scans.length === 1 ? '' : 's'} exported` })
    } catch (caught) {
      setHistory({ busy: false, message: caught instanceof Error ? caught.message : 'History could not be loaded' })
    }
  }

  return (
    <div className="glass-panel h-full w-full overflow-y-auto p-8 text-stone-200">
      <h1 className="font-mono text-lg uppercase tracking-[0.25em] text-white">Reports &amp; export</h1>
      <p className="mt-1 text-sm text-stone-400">Files are generated in your browser; nothing is uploaded.</p>

      <section className="mt-8 max-w-2xl space-y-3" aria-label="Current scan">
        <p className={SECTION_TITLE}>Current scan</p>
        {ready ? (
          <p className="text-sm text-stone-300">
            <span className="text-white">{assessment.header_forensics.subject ?? '(no subject)'}</span> · risk{' '}
            <span className="font-mono text-white">{assessment.overall_risk}/100</span>
            {details.scanId !== null && <span className="text-stone-400"> · scan #{details.scanId}</span>}
          </p>
        ) : (
          <p className="text-sm text-stone-400">Analyse an email on the Live scan page to export its assessment.</p>
        )}
        <ExportButton
          icon={FileJson}
          title="Full report (JSON)"
          description="Assessment, SHAP attributions, the 12 feature values, model status and caveats · sentinel-report.json"
          onClick={exportJSON}
          disabled={!ready}
        />
        <ExportButton
          icon={FileSpreadsheet}
          title="Feature metrics (CSV)"
          description="One row: the 12 features the model scored, the risk and the verdict · sentinel-metrics.csv"
          onClick={exportCSV}
          disabled={!ready}
        />
      </section>

      <section className="mt-8 max-w-2xl space-y-3" aria-label="Scan history">
        <p className={SECTION_TITLE}>Scan history</p>
        <ExportButton
          icon={History}
          title={history.busy ? 'Collecting history…' : 'All saved scans (CSV)'}
          description="Every scan in the history database with its verdict, risk and indicators · sentinel-history.csv"
          onClick={() => void exportHistory()}
          disabled={history.busy}
        />
        {history.message && (
          <p className="text-xs text-stone-400" role="status">
            {history.message}
          </p>
        )}
      </section>

      <p className="mt-8 max-w-2xl text-xs leading-relaxed text-stone-500">
        Email subjects, senders and URLs are attacker-controlled. In the CSV files, any text cell that starts with =, +, −, @ or
        a tab is prefixed with an apostrophe, so a spreadsheet shows it as text instead of running it as a formula.
      </p>
    </div>
  )
}
