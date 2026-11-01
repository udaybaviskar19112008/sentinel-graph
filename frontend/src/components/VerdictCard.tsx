import { motion, useReducedMotion } from 'framer-motion'
import { TriangleAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { type AuthStatus, type ModelStatus, useThreatStore, type VerdictLevel } from '@/store/useThreatStore'
import { riskColor } from '@/theme/colors'

const DECISION_LINE = 50 // the classifier's own threshold: probability 0.5

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

/** A verdict as a pale pill of its status hue; the word, not the colour, carries the meaning. */
export function VerdictPill({ verdict }: { verdict: VerdictLevel }) {
  return <span className={cn('pill', VERDICT_PILL[verdict])}>{VERDICT_LABEL[verdict]}</span>
}

const AUTH_RESULTS = [
  ['spf', 'SPF'],
  ['dkim', 'DKIM'],
  ['dmarc', 'DMARC'],
  ['arc', 'ARC'],
] as const

function authTone(status: AuthStatus): string {
  if (status === 'fail') return 'text-negative'
  return status === 'pass' ? 'text-ink' : 'text-muted'
}

/** Engines answering with untrained stand-ins, whose scores are not evidence. */
function standIns(status: ModelStatus): string[] {
  return [
    status.vision_placeholder && 'vision',
    status.memae_placeholder && 'MemAE',
    !status.zero_day_calibrated && 'zero-day threshold',
    status.fusion_dummy && 'fusion',
    status.slm_dummy && 'SLM',
  ].filter((name): name is string => typeof name === 'string')
}

/**
 * The live view's answer: overall risk (0-100) against the decision line, the verdict, the
 * sender authentication results, and any stand-in models called out.
 */
export function VerdictCard({ className }: { className?: string }) {
  const reduceMotion = useReducedMotion()
  const risk = useThreatStore((s) => s.assessment?.overall_risk ?? null)
  const verdict = useThreatStore((s) => s.details?.verdict ?? null)
  const modelStatus = useThreatStore((s) => s.details?.modelStatus ?? null)
  const header = useThreatStore((s) => s.headerFindings ?? s.assessment?.header_forensics ?? null)
  const scanning = useThreatStore((s) => !['IDLE', 'COMPLETE', 'ERROR'].includes(s.currentPhase))
  const placeholders = modelStatus ? standIns(modelStatus) : []

  return (
    <section className={cn('card', className)} aria-labelledby="verdict-title">
      <header className="flex items-center justify-between gap-3">
        <h2 id="verdict-title" className="card-title">
          Verdict
        </h2>
        {verdict ? <VerdictPill verdict={verdict} /> : <span className="text-small text-muted">{scanning ? 'Scanning…' : 'Awaiting scan'}</span>}
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

      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-1" aria-label="Sender authentication">
        {AUTH_RESULTS.map(([key, label]) => (
          <div key={key} className="flex items-baseline justify-between gap-2">
            <dt className="text-muted">{label}</dt>
            <dd className={header ? authTone(header[key]) : 'text-muted'}>{header ? header[key] : '—'}</dd>
          </div>
        ))}
      </dl>

      {placeholders.length > 0 && (
        <p className="mt-4 flex gap-2 rounded bg-pill-warning-bg px-3 py-2 text-small text-pill-warning-ink">
          <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Stand-in models, scores not evidence: {placeholders.join(', ')}</span>
        </p>
      )}
    </section>
  )
}
