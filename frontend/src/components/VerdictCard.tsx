import { motion, useReducedMotion } from 'framer-motion'
import { TriangleAlert } from 'lucide-react'
import { Link } from 'react-router-dom'
import { type GeoPoint, isPublicIp } from '@/lib/geoResolver'
import { cn } from '@/lib/utils'
import { DECISION_LINE, standIns } from '@/lib/verdict'
import { useThreatStore, type VerdictLevel } from '@/store/useThreatStore'
import { riskColor } from '@/theme/colors'

const VERDICT_PILL: Record<VerdictLevel, string> = {
  BENIGN: 'bg-pill-positive-bg text-pill-positive-ink',
  SUSPICIOUS: 'bg-pill-warning-bg text-pill-warning-ink',
  PHISHING: 'bg-pill-negative-bg text-pill-negative-ink',
  CRITICAL: 'bg-pill-negative-bg text-pill-negative-ink',
}

const VERDICT_LABEL: Record<VerdictLevel, string> = {
  BENIGN: 'Benign',
  SUSPICIOUS: 'Suspicious',
  PHISHING: 'Phishing',
  CRITICAL: 'Critical',
}

/** The language model's verdict (the one stored in history) as a pale pill of its status hue. */
export function VerdictPill({ verdict }: { verdict: VerdictLevel }) {
  return <span className={cn('pill', VERDICT_PILL[verdict])}>{VERDICT_LABEL[verdict]}</span>
}

/** The classifier's call at its decision line, which is what the risk score measures. */
export function DecisionPill({ risk }: { risk: number }) {
  const phishing = risk >= DECISION_LINE
  return (
    <span className={cn('pill', phishing ? 'bg-pill-negative-bg text-pill-negative-ink' : 'bg-pill-positive-bg text-pill-positive-ink')}>
      {phishing ? 'Phishing' : 'Legitimate'}
    </span>
  )
}

function degrees(value: number, positive: string, negative: string): string {
  return `${Math.abs(value).toFixed(1)}°${value >= 0 ? positive : negative}`
}

/** Where a hop sits, or why its globe position is only a stand-in. */
function place(point: GeoPoint): string {
  if (point.source === 'lookup') return `${degrees(point.lat, 'N', 'S')} ${degrees(point.lng, 'E', 'W')}`
  return isPublicIp(point.ip) ? 'Estimated: lookup failed' : 'Estimated: private range'
}

/** The delivery route, sender side first: every relay hop's address and where it is. */
function RoutePath({ ips, scored }: { ips: string[]; scored: boolean }) {
  const points = useThreatStore((s) => s.geoCoordinates)
  if (ips.length === 0) return <p className="text-body text-muted">No relay hop addresses in this email.</p>
  return (
    <ol aria-label="Relay hops, sender side first">
      {ips.map((ip, index) => {
        const point = points[index]?.ip === ip ? points[index] : null
        return (
          <li key={`${index}:${ip}`} className="flex items-baseline gap-3 border-t border-rule py-1.5 first:border-t-0">
            <span className="w-3 shrink-0 text-small text-muted">{index + 1}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-small text-ink">{ip}</span>
            <span className="shrink-0 text-small text-muted">{point ? place(point) : scored ? 'Locating…' : '—'}</span>
          </li>
        )
      })}
    </ol>
  )
}

/**
 * The dashboard's answer, and nothing more: the risk score against the decision line, the
 * classifier's call, and the route the email took. The evidence behind it is on Forensics.
 */
export function VerdictCard({ className }: { className?: string }) {
  const reduceMotion = useReducedMotion()
  const risk = useThreatStore((s) => s.assessment?.overall_risk ?? null)
  const modelStatus = useThreatStore((s) => s.details?.modelStatus ?? null)
  const ips = useThreatStore((s) => s.headerFindings?.extracted_ips ?? s.assessment?.header_forensics.extracted_ips ?? null)
  const scanning = useThreatStore((s) => !['IDLE', 'COMPLETE', 'ERROR'].includes(s.currentPhase))
  const placeholders = modelStatus ? standIns(modelStatus) : []

  return (
    <section className={cn('card flex flex-col overflow-y-auto', className)} aria-labelledby="verdict-title">
      <header className="flex items-center justify-between gap-3">
        <h2 id="verdict-title" className="card-title">
          Verdict
        </h2>
        {risk !== null ? <DecisionPill risk={risk} /> : <span className="text-small text-muted">{scanning ? 'Scanning…' : 'Awaiting scan'}</span>}
      </header>

      <p className="mt-4 text-small text-muted">Risk score</p>
      {risk === null ? (
        <p className="flex h-9 items-end text-body text-muted">{scanning ? 'Scoring when the scan completes' : 'No score yet'}</p>
      ) : (
        <p className="text-figure font-semibold" aria-label={`Risk ${risk} out of 100`}>
          {risk}
          <span className="ml-1 text-body font-normal text-muted">/100</span>
        </p>
      )}
      <div className="relative mt-3 h-2 rounded-full bg-raised" aria-hidden="true">
        {risk !== null && (
          <motion.span
            className="absolute inset-y-0 left-0 rounded-full"
            style={{ backgroundColor: riskColor(risk) }}
            initial={false}
            animate={{ width: `${risk}%` }}
            transition={{ duration: reduceMotion ? 0 : 0.6, ease: 'easeOut' }}
          />
        )}
        <span className="absolute -inset-y-1 w-px bg-ink/70" style={{ left: `${DECISION_LINE}%` }} />
      </div>
      <p className="relative mt-1.5 h-4 text-small text-muted" aria-hidden="true">
        <span className="absolute left-0">0</span>
        <span className="absolute -translate-x-1/2" style={{ left: `${DECISION_LINE}%` }}>
          {DECISION_LINE} decision line
        </span>
        <span className="absolute right-0">100</span>
      </p>

      <h3 className="mt-5 flex items-baseline justify-between text-body font-medium text-ink">
        Route
        {ips && ips.length > 0 && <span className="text-small font-normal text-muted">sender side first</span>}
      </h3>
      <div className="mt-1">
        {ips === null ? <p className="text-body text-muted">The route appears once the headers are read.</p> : <RoutePath ips={ips} scored={risk !== null} />}
      </div>

      {placeholders.length > 0 && (
        <p className="mt-4 flex gap-2 rounded bg-pill-warning-bg px-3 py-2 text-small text-pill-warning-ink">
          <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Stand-in models, scores not evidence: {placeholders.join(', ')}</span>
        </p>
      )}
      {risk !== null && (
        <Link to="/forensics" className="btn btn-secondary mt-auto self-start">
          Open forensics
        </Link>
      )}
    </section>
  )
}
