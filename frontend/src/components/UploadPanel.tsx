import { Check, Upload, X } from 'lucide-react'
import { useEmailPicker } from '@/components/Dropzone'
import { MAX_EMAIL_BYTES } from '@/lib/threatStream'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

// The stages a scan reports, in order, under the phase names its log lines carry (threatStream.describe).
const STAGES: [phase: string, label: string][] = [
  ['RECEIVED', 'Received'],
  ['TIER_1', 'Header forensics'],
  ['VISION', 'Sandbox'],
  ['TOPOLOGY', 'Route model'],
  ['SLM_VERDICT', 'Language model'],
  ['COMPLETE', 'Scored'],
]

/** Each stage the current scan has reported, read from the phase name in its log lines. */
function useStagesSeen(): { seen: Set<string>; error: string | null } {
  const logs = useThreatStore((s) => s.liveLogs)
  const error = logs.find((log) => log.startsWith('ERROR')) ?? null
  return { seen: new Set(logs.map((log) => log.split(' ')[1])), error: error && error.replace(/^ERROR\s+/, '') }
}

/**
 * The dashboard's primary action: one large target that opens the file picker (a file can
 * also be dropped anywhere in the window), then the scan's progress stage by stage.
 */
export function UploadPanel({ onFile, className }: { onFile: (file: File) => void; className?: string }) {
  const picker = useEmailPicker(onFile)
  const started = useThreatStore((s) => s.liveLogs.length > 0 || s.socketStatus === 'connecting')
  const { seen, error } = useStagesSeen()

  return (
    <section className={cn('card', className)} aria-labelledby="upload-title">
      <h2 id="upload-title" className="card-title">
        Analyse an email
      </h2>
      {picker.fileInput}
      <button
        type="button"
        onClick={picker.browse}
        className="group mt-4 flex w-full cursor-pointer flex-col items-center gap-1.5 rounded-md border border-dashed border-control px-6 py-7 text-center transition-colors hover:border-accent hover:bg-accent/5 focus-visible:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <Upload className="mb-1 h-7 w-7 text-muted transition-colors group-hover:text-accent" strokeWidth={1.5} aria-hidden="true" />
        <span className="text-body font-medium text-ink">Drop a raw email (.eml) anywhere</span>
        <span className="text-body text-muted">or click to choose a file</span>
        <span className="mt-1 text-small text-muted">.eml or .txt · up to {MAX_EMAIL_BYTES / 1024 / 1024} MB</span>
      </button>

      {started && (
        <ol className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1.5" aria-label="Scan progress">
          {STAGES.map(([phase, label]) => {
            const done = seen.has(phase)
            return (
              <li key={phase} className={cn('flex items-center gap-2 text-small', done ? 'text-ink' : 'text-muted')}>
                {done ? (
                  <Check className="h-3.5 w-3.5 shrink-0 text-positive" strokeWidth={2.5} aria-hidden="true" />
                ) : (
                  <span className="mx-[3px] h-2 w-2 shrink-0 rounded-full border border-control" aria-hidden="true" />
                )}
                {label}
                <span className="sr-only">{done ? ' (done)' : ' (pending)'}</span>
              </li>
            )
          })}
        </ol>
      )}
      {error && (
        <p className="mt-3 flex gap-2 text-small text-ink" role="alert">
          <X className="mt-px h-3.5 w-3.5 shrink-0 text-negative" strokeWidth={2.5} aria-hidden="true" />
          {error}
        </p>
      )}
    </section>
  )
}
