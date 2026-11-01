import { Upload } from 'lucide-react'
import { AnalystReasoning } from '@/components/AnalystReasoning'
import { ContentHeuristics } from '@/components/ContentHeuristics'
import { useEmailUpload } from '@/components/Dropzone'
import { PipelineLog } from '@/components/PipelineLog'
import { RouteGeography } from '@/components/RouteGeography'
import { Screen } from '@/components/Screen'
import { TopologyMap } from '@/components/TopologyMap'
import { VerdictCard } from '@/components/VerdictCard'
import { FEATURE_SPACE } from '@/lib/featureSpace'
import { cn } from '@/lib/utils'
import { type ShapContribution, type ThreatState, useThreatStore } from '@/store/useThreatStore'

const PHASE_LABEL: Record<string, string> = {
  IDLE: 'Ready',
  RECEIVED: 'Email received',
  TIER_1: 'Header forensics',
  VISION: 'Sandbox detonation',
  TOPOLOGY: 'Route model',
  SLM_REASONING: 'Language model',
  SLM_VERDICT: 'Language model',
  COMPLETE: 'Scan complete',
  ERROR: 'Scan failed',
}

const isRunning = (phase: string) => !['IDLE', 'COMPLETE', 'ERROR'].includes(phase)

// A scan has failed when the server said so, or when the stream dropped before any stage
// arrived: then the phase is still IDLE and the only trace is the newest log line.
const failure = (s: ThreatState): string | null =>
  s.liveLogs[0]?.startsWith('ERROR') ? s.liveLogs[0].replace(/^ERROR\s+/, '') : s.currentPhase === 'ERROR' ? '' : null

// The streamed panes (reasoning, log) end each side column: a fixed height when the blocks
// stack, then they grow so both columns end level, from two columns up to the console view.
const STREAM_PANE = 'h-60 md:h-auto md:min-h-[15rem] md:flex-1 xl:min-h-[8rem]'

function strongest(contributions: readonly ShapContribution[]): ShapContribution | null {
  return contributions.reduce<ShapContribution | null>(
    (best, c) => (best === null || Math.abs(c.impact) > Math.abs(best.impact) ? c : best),
    null,
  )
}

/** The line under the title: what this scan found, read first, next to the action it drives. */
function useFinding(): string {
  const phase = useThreatStore((s) => s.currentPhase)
  const risk = useThreatStore((s) => s.assessment?.overall_risk ?? null)
  const contributions = useThreatStore((s) => s.details?.contributions ?? null)
  const subject = useThreatStore((s) => s.headerFindings?.subject ?? s.assessment?.header_forensics.subject ?? null)
  const failed = useThreatStore(failure)

  if (failed !== null) return failed ? `The scan failed: ${failed}` : 'The scan failed.'
  const quoted = subject ? `“${subject}”` : 'The email'
  if (risk !== null && contributions !== null) {
    const top = strongest(contributions)
    if (!top) return `${quoted} scored ${risk}/100.`
    const label = FEATURE_SPACE.find((feature) => feature.name === top.feature_name)?.label ?? top.feature_name
    const toward = top.impact >= 0 ? 'phishing' : 'legitimate'
    return `${quoted}. Strongest evidence: ${label} (${top.percentage.toFixed(0)}% of the decision, toward ${toward}).`
  }
  if (isRunning(phase)) return subject ? `Analysing “${subject}”.` : 'Analysing the uploaded email.'
  return 'No email analysed in this session yet.'
}

function PhaseStamp() {
  const phase = useThreatStore((s) => s.currentPhase)
  const connecting = useThreatStore((s) => s.socketStatus === 'connecting' && s.currentPhase === 'IDLE')
  const failed = useThreatStore((s) => failure(s) !== null)
  return (
    <p className="flex items-center gap-2 text-small text-muted" role="status">
      <span
        className={cn(
          'h-1.5 w-1.5 rounded-full',
          failed ? 'bg-negative' : isRunning(phase) || connecting ? 'bg-warning motion-safe:animate-pulse' : 'bg-muted',
        )}
        aria-hidden="true"
      />
      {failed ? PHASE_LABEL.ERROR : connecting ? 'Connecting to the engine' : (PHASE_LABEL[phase] ?? phase)}
    </p>
  )
}

/**
 * One email's detonation: the verdict, the delivery route and the evidence behind them.
 *
 * From 1280px every block shows on the first screen in three columns (answer, route,
 * provenance), the route graph the largest; narrower, the blocks stack and the page scrolls.
 * The whole screen takes a dropped email; the primary button opens the file picker.
 * The socket is owned by the App shell, not this page, so leaving mid-scan does not close it.
 */
export function LiveDetonation({ onFile }: { onFile: (file: File) => void }) {
  const upload = useEmailUpload(onFile)
  const finding = useFinding()

  return (
    <div className="relative min-h-full xl:h-full" {...upload.dropHandlers}>
      <Screen
        title="Live scan"
        subline={finding}
        fill
        actions={
          <>
            <PhaseStamp />
            <button type="button" className="btn btn-primary" onClick={upload.browse}>
              <Upload className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
              Analyse an email
            </button>
          </>
        }
      >
        {upload.fileInput}
        <div className="grid flex-1 gap-6 md:grid-cols-2 xl:min-h-0 xl:grid-cols-12">
          <div className="flex flex-col gap-6 xl:col-span-3 xl:min-h-0">
            <VerdictCard />
            <ContentHeuristics />
            <AnalystReasoning className={STREAM_PANE} />
          </div>
          <TopologyMap
            onBrowse={upload.browse}
            className="h-[480px] md:order-last md:col-span-2 xl:order-none xl:col-span-6 xl:h-auto xl:min-h-0"
          />
          <div className="flex flex-col gap-6 xl:col-span-3 xl:min-h-0">
            <RouteGeography />
            <PipelineLog className={STREAM_PANE} />
          </div>
        </div>
      </Screen>
      {upload.dragging && (
        <div className="pointer-events-none absolute inset-3 z-20 grid place-items-center rounded-md border border-dashed border-accent bg-ground/90 shadow-float">
          <p className="text-section text-ink">Drop the email to analyse it</p>
        </div>
      )}
    </div>
  )
}
