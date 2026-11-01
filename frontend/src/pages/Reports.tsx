import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ScanHistory } from '@/components/ScanHistory'
import { Screen } from '@/components/Screen'
import { assessmentReport, downloadText, metricsCsv } from '@/lib/exports'
import { useThreatStore } from '@/store/useThreatStore'

/** One export: what it holds on the left, the file it writes and its button on the right. */
function ExportRow({
  title,
  description,
  fileName,
  action,
}: {
  title: string
  description: string
  fileName: string
  action: ReactNode
}) {
  return (
    <li className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-rule px-5 py-4 first:border-t-0">
      <div className="min-w-0 flex-1 basis-64">
        <p className="font-medium text-ink">{title}</p>
        <p className="text-small text-muted">{description}</p>
      </div>
      <span className="font-mono text-small text-muted">{fileName}</span>
      {action}
    </li>
  )
}

/** What an export produces, shown beside the button that makes it: the file's own text. */
function FilePreview({ label, content }: { label: string; content: string }) {
  return (
    <li className="border-t border-rule px-5 py-4">
      <p className="text-small text-muted">{label}</p>
      <pre className="mt-2 overflow-x-auto rounded bg-raised px-3 py-2 font-mono text-small text-ink">{content.trimEnd()}</pre>
    </li>
  )
}

/** A settings-style row: the section's name and what it covers beside the panel that does it. */
function Section({ title, description, children }: { title: string; description: ReactNode; children: ReactNode }) {
  return (
    <section className="grid grid-cols-[minmax(0,1fr)] gap-x-12 gap-y-3 border-t border-line py-8 first:border-t-0 first:pt-0 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <div>
        <h2 className="text-card font-medium text-ink">{title}</h2>
        <div className="mt-1 text-body text-muted">{description}</div>
      </div>
      {children}
    </section>
  )
}

/**
 * Exports and history: the current assessment as JSON or CSV, then every saved scan, with
 * its own CSV. Files are built in the browser.
 */
export function Reports() {
  const assessment = useThreatStore((s) => s.assessment)
  const details = useThreatStore((s) => s.details)
  const ready = assessment !== null && details !== null

  const exportJSON = () => {
    if (!assessment || !details) return
    downloadText(JSON.stringify(assessmentReport(assessment, details), null, 2), 'sentinel-report.json', 'application/json')
  }

  const exportCSV = () => {
    if (!assessment || !details) return
    downloadText(metricsCsv(assessment, details), 'sentinel-metrics.csv', 'text/csv;charset=utf-8')
  }

  return (
    <Screen title="Reports" subline="Exports are built in this browser; nothing is uploaded.">
      <Section
        title="Current scan"
        description={
          ready ? (
            <>
              <span className="text-ink">{assessment.header_forensics.subject ?? '(no subject)'}</span>
              <br />
              Risk {assessment.overall_risk}/100{details.scanId !== null && ` · scan #${details.scanId}`}
            </>
          ) : (
            <>
              No scan yet.{' '}
              <Link to="/" className="text-action">
                Analyse an email
              </Link>{' '}
              to export its assessment.
            </>
          )
        }
      >
        <ul className="card p-0">
          <ExportRow
            title="Full report"
            description="Assessment, SHAP attributions, the 12 feature values, model status and caveats"
            fileName="sentinel-report.json"
            action={
              <button type="button" className="btn btn-primary" onClick={exportJSON} disabled={!ready}>
                Download JSON
              </button>
            }
          />
          <ExportRow
            title="Feature metrics"
            description="One row: the 12 features the model scored, the risk and the verdict"
            fileName="sentinel-metrics.csv"
            action={
              <button type="button" className="btn btn-secondary" onClick={exportCSV} disabled={!ready}>
                Download CSV
              </button>
            }
          />
          {ready && <FilePreview label="sentinel-metrics.csv as it will download" content={metricsCsv(assessment, details)} />}
        </ul>
      </Section>

      <ScanHistory />

      <Section title="Spreadsheet safety" description="Why some cells in the CSV files start with an apostrophe.">
        <p className="card text-body text-ink">
          Email subjects, senders and URLs are attacker-controlled. Any text cell that starts with =, +, −, @ or a tab is
          prefixed with an apostrophe, so a spreadsheet shows it as text instead of running it as a formula.
        </p>
      </Section>
    </Screen>
  )
}
