import { RouteGeography } from '@/components/RouteGeography'
import { Screen } from '@/components/Screen'
import { UploadPanel } from '@/components/UploadPanel'
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

function strongest(contributions: readonly ShapContribution[]): ShapContribution | null {
  return contributions.reduce<ShapContribution | null>(
    (best, c) => (best === null || Math.abs(c.impact) > Math.abs(best.impact) ? c : best),
    null,
  )
}

/** The line under the title: what this scan found, read first. */
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
 * Three things only: drop an email in, read the verdict, watch the route on the globe.
 * Every piece of evidence behind the score lives on Forensics; exports on Reports.
 *
 * From 1280px the globe takes two-thirds of the screen beside the upload and verdict
 * panels, and nothing scrolls; narrower, the panels stack above the globe.
 * The socket is owned by the App shell, not this page, so leaving mid-scan does not close it.
 */
export function Dashboard({ onFile }: { onFile: (file: File) => void }) {
  const finding = useFinding()

  return (
    <Screen title="Dashboard" subline={finding} fill actions={<PhaseStamp />}>
      <div className="grid flex-1 gap-6 md:grid-cols-2 xl:min-h-0 xl:grid-cols-12">
        <div className="flex flex-col gap-6 md:contents xl:col-span-4 xl:flex xl:min-h-0">
          <UploadPanel onFile={onFile} />
          <VerdictCard className="xl:min-h-0 xl:flex-1" />
        </div>
        <RouteGeography className="h-[440px] md:col-span-2 xl:order-first xl:col-span-8 xl:h-auto xl:min-h-0" />
      </div>
    </Screen>
  )
}
