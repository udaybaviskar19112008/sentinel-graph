import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { ChevronDown } from 'lucide-react'
import { type ReactNode, useId, useState } from 'react'
import { Link } from 'react-router-dom'
import { AnalystReasoning } from '@/components/AnalystReasoning'
import { EntropyScale, UrgencyMeter } from '@/components/HeuristicMeters'
import { PipelineLog } from '@/components/PipelineLog'
import { Screen } from '@/components/Screen'
import { TopologyMap } from '@/components/TopologyMap'
import { DecisionPill } from '@/components/VerdictCard'
import { COERCIVE_PHRASES, LEGITIMATE_BAND_BITS } from '@/lib/contentHeuristics'
import { FEATURE_SPACE, type FeatureName, featureValues, formatFeature } from '@/lib/featureSpace'
import { cn } from '@/lib/utils'
import { standIns } from '@/lib/verdict'
import {
  type AnalysisDetails,
  type AuthStatus,
  type HeaderForensics,
  type Subsystem,
  type ThreatAssessment,
  useThreatStore,
} from '@/store/useThreatStore'

const SUBSYSTEM_LABEL: Record<Subsystem, string> = {
  PROTOCOL_FORENSICS: 'Protocol forensics',
  VISION_ENGINE: 'Vision',
  TOPOLOGY_GNN: 'Topology',
  COGNITIVE_SLM: 'Language model',
  CONTENT_HEURISTICS: 'Content heuristics',
}

// Feature · value · diverging bar · signed impact, shared by the header row and every feature row.
// On a phone the value column folds away (the selected feature's well still shows it) and
// labels wrap rather than truncate.
const ROW_GRID =
  'grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_3.5rem] items-center gap-3 sm:grid-cols-[minmax(0,1fr)_6.5rem_minmax(0,1.2fr)_4rem]'
const VALUE_CELL = 'hidden sm:block'
// A streamed pane (reasoning, log) closing a side column: fixed when the blocks stack, then
// it takes whatever height its row leaves and scrolls its own overflow, so a long reasoning
// or log never stretches the page.
const STREAM_FILL = 'lg:h-auto lg:flex-1'

function signed(impact: number): string {
  return `${impact >= 0 ? '+' : '−'}${Math.abs(impact).toFixed(3)}`
}

/**
 * Every feature's value and its SHAP impact: a diverging bar around zero, the negative hue
 * toward phishing and the positive hue toward legitimate (the same polarity as the route's
 * edges). The selected feature takes the style's one selection mark: a 1px accent line
 * under its label.
 */
function FeatureAttribution({ assessment, details }: { assessment: ThreatAssessment; details: AnalysisDetails }) {
  const reduceMotion = useReducedMotion()
  const tooltipPrefix = useId()
  const values = featureValues(assessment, details.verdict)
  const byFeature = new Map(details.contributions.map((contribution) => [contribution.feature_name, contribution]))
  const largest = Math.max(...details.contributions.map((contribution) => Math.abs(contribution.impact)), 1e-9)
  const [selected, setSelected] = useState<FeatureName>(
    (details.contributions[0]?.feature_name as FeatureName | undefined) ?? 'graph_nodes_count',
  )
  const chosen = FEATURE_SPACE.find((feature) => feature.name === selected) ?? FEATURE_SPACE[0]
  const chosenImpact = byFeature.get(chosen.name)

  return (
    <section className="card lg:col-span-8" aria-labelledby="attribution-title">
      <header className="mb-3 flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h2 id="attribution-title" className="card-title">
          Feature attribution (SHAP)
        </h2>
        <p className="flex items-center gap-4 text-small text-muted">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-3 rounded-l bg-positive" aria-hidden="true" />
            Toward legitimate
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-3 rounded-r bg-negative" aria-hidden="true" />
            Toward phishing
          </span>
        </p>
      </header>

      <p className={cn(ROW_GRID, 'px-2 pb-1 text-small text-muted')} aria-hidden="true">
        <span>Feature</span>
        <span className={VALUE_CELL}>Value</span>
        <span className="text-center">Impact</span>
        <span className="text-right">SHAP</span>
      </p>
      <ul>
        {FEATURE_SPACE.map((feature, index) => {
          const contribution = byFeature.get(feature.name)
          const share = contribution ? (Math.abs(contribution.impact) / largest) * 50 : 0
          const toPhishing = (contribution?.impact ?? 0) >= 0
          const isSelected = selected === feature.name
          const tooltipId = `${tooltipPrefix}-${index}`
          return (
            <li key={feature.name}>
              <button
                type="button"
                onClick={() => setSelected(feature.name)}
                aria-pressed={isSelected}
                aria-describedby={tooltipId}
                className={cn(
                  ROW_GRID,
                  'group relative w-full cursor-pointer rounded px-2 py-1.5 text-left transition-colors hover:bg-raised/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                )}
              >
                <span className="text-body text-ink sm:truncate">
                  <span className={cn('border-b pb-px', isSelected ? 'border-accent' : 'border-transparent')}>{feature.label}</span>
                </span>
                <span className={cn('truncate text-small text-muted', VALUE_CELL)}>
                  {formatFeature(feature.name, values[feature.name])}
                </span>
                <span className="relative h-2" aria-hidden="true">
                  <span className="absolute inset-y-[-4px] left-1/2 w-px bg-control" />
                  {contribution && (
                    <motion.span
                      className={cn('absolute inset-y-0', toPhishing ? 'left-1/2 rounded-r bg-negative' : 'right-1/2 rounded-l bg-positive')}
                      initial={false}
                      animate={{ width: `${share}%` }}
                      transition={{ duration: reduceMotion ? 0 : 0.5, ease: 'easeOut' }}
                    />
                  )}
                </span>
                <span className={cn('text-right text-body', contribution ? 'text-ink' : 'text-muted')}>
                  {contribution ? signed(contribution.impact) : '<1%'}
                </span>
                <span
                  id={tooltipId}
                  role="tooltip"
                  className="pointer-events-none absolute left-2 top-full z-20 mt-1 hidden w-72 rounded bg-raised px-3 py-2 text-small text-ink shadow-float group-hover:block group-focus-visible:block"
                >
                  {feature.summary}
                </span>
              </button>
            </li>
          )
        })}
      </ul>

      <div className="mt-4 rounded-md bg-raised p-4" aria-live="polite">
        <p className="flex flex-wrap items-baseline gap-x-2">
          <span className="font-semibold text-ink">{chosen.label}</span>
          <span className="text-small text-muted">{SUBSYSTEM_LABEL[chosen.subsystem]}</span>
        </p>
        <p className="mt-1 text-body text-muted">
          Value <span className="text-ink">{formatFeature(chosen.name, values[chosen.name])}</span> · SHAP{' '}
          {chosenImpact ? (
            <>
              <span className="text-ink">{signed(chosenImpact.impact)}</span> ({chosenImpact.percentage.toFixed(1)}% of the decision)
            </>
          ) : (
            'under 1% of the decision'
          )}
        </p>
        <p className="mt-2 text-body text-ink">{chosen.detail}</p>
      </div>
    </section>
  )
}

/** Before a scan: the 12 features the fusion model scores, in its order, with what each one measures. */
function FeatureReference() {
  return (
    <section className="card lg:col-span-8" aria-labelledby="attribution-title">
      <header className="mb-3 flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h2 id="attribution-title" className="card-title">
          Feature attribution (SHAP)
        </h2>
        <p className="text-small text-muted">Each feature’s push is drawn here when a scan completes</p>
      </header>
      <p className="grid grid-cols-[minmax(0,13rem)_minmax(0,1fr)] gap-3 px-2 pb-1 text-small text-muted" aria-hidden="true">
        <span>Feature</span>
        <span>What it measures</span>
      </p>
      <ul>
        {FEATURE_SPACE.map((feature) => (
          <li key={feature.name} className="grid grid-cols-[minmax(0,13rem)_minmax(0,1fr)] gap-3 px-2 py-1.5">
            <span className="truncate text-ink">{feature.label}</span>
            <span className="text-muted">{feature.summary}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

/** A card whose header expands a "how it works" section. */
function DeepDive({
  title,
  explanation,
  className,
  children,
}: {
  title: string
  explanation: ReactNode
  className?: string
  children: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const panelId = useId()
  return (
    <section className={cn('card overflow-y-auto', className)} aria-label={title}>
      <header className="flex items-center justify-between gap-3">
        <h2 className="card-title">{title}</h2>
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          aria-controls={panelId}
          className="text-action flex items-center gap-1 text-small"
        >
          {open ? 'Hide' : 'How it works'}
          <ChevronDown className={cn('h-4 w-4 transition-transform duration-200', open && 'rotate-180')} aria-hidden="true" />
        </button>
      </header>
      <div className="mt-4">{children}</div>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            id={panelId}
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeOut' }}
            className="overflow-hidden"
          >
            {/* Explanations read as notes beside the evidence: smaller, quieter, and capped in height. */}
            <div className="mt-4 max-h-60 space-y-2 overflow-y-auto border-t border-rule pt-3 text-small text-muted">
              {explanation}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  )
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

/**
 * Who the email claims to be from: the authentication results, then the domains that
 * would receive its replies and bounces (the evidence behind display-name spoofing). A
 * domain that differs from the sender's, and a failed check, are the card's red marks.
 */
function SenderIdentity({ header }: { header: HeaderForensics | null }) {
  const from = header?.from_domain ?? null
  const rows: [string, string | null][] = [
    ['From', from],
    ['Reply-To', header?.reply_to_domain ?? null],
    ['Return-Path', header?.return_path_domain ?? null],
  ]
  const diverges = rows.some(([, domain]) => domain !== null && from !== null && domain !== from)
  const brand = header?.impersonated_brand ?? null
  return (
    <section className="card" aria-labelledby="sender-identity-title">
      <header className="flex items-center justify-between gap-3">
        <h2 id="sender-identity-title" className="card-title">
          Sender identity
        </h2>
        {header && brand && (
          <span
            className={cn(
              'pill',
              header.display_name_spoof_risk >= 1 ? 'bg-pill-negative-bg text-pill-negative-ink' : 'bg-pill-warning-bg text-pill-warning-ink',
            )}
          >
            Names {brand.charAt(0).toUpperCase() + brand.slice(1)}
          </span>
        )}
      </header>
      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-1" aria-label="Sender authentication">
        {AUTH_RESULTS.map(([key, label]) => (
          <div key={key} className="flex items-baseline justify-between gap-2">
            <dt className="text-muted">{label}</dt>
            <dd className={header ? authTone(header[key]) : 'text-muted'}>{header ? header[key] : '—'}</dd>
          </div>
        ))}
      </dl>
      <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 border-t border-rule pt-3">
        {rows.map(([term, domain]) => (
          <div key={term} className="contents">
            <dt className="text-muted">{term}</dt>
            <dd
              className={cn(
                'truncate text-right',
                domain === null ? 'text-muted' : 'font-mono text-small leading-5',
                domain !== null && (from === null || domain === from ? 'text-ink' : 'text-negative'),
              )}
              title={domain ?? undefined}
            >
              {domain ?? '—'}
            </dd>
          </div>
        ))}
      </dl>
      {diverges && <p className="mt-3 text-small text-muted">Replies or bounces go to a domain other than the sender’s.</p>}
    </section>
  )
}

/** The two content heuristics in one card, each explained under "How it works". */
function ContentHeuristicsCard({ score, bits, className }: { score: number | null; bits: number | null; className?: string }) {
  return (
    <DeepDive
      title="Content heuristics"
      className={className}
      explanation={
        <>
          <p className="font-medium">Coercive wording (NLP coercion)</p>
          <p>0.25 per coercive phrase, capped at 1. Matched in natural inflections after removing zero-width characters:</p>
          <ul className="flex flex-wrap gap-1.5">
            {COERCIVE_PHRASES.map((phrase) => (
              <li key={phrase} className="rounded bg-raised px-2 py-0.5 text-small text-ink">
                {phrase}
              </li>
            ))}
          </ul>
          <p>Fires on 20.3% of training phishing and 0.1% of legitimate mail.</p>
          <p className="pt-2 font-medium">Link-domain entropy (DGA entropy)</p>
          <p>
            Shannon entropy of the most random link’s registrable label, the part left of the public suffix
            (login.paypa1-secure.co.uk → paypa1-secure). Subdomains are free attacker padding and are ignored.
          </p>
          <p>
            Not “higher is worse”: legitimate links cluster at {LEGITIMATE_BAND_BITS[0].toFixed(1)}–
            {LEGITIMATE_BAND_BITS[1].toFixed(1)} bits (52% of them, against 23% of phishing), while phishing fills both
            tails. In the ablation it is the stronger content feature.
          </p>
        </>
      }
    >
      <div className="space-y-5">
        <UrgencyMeter score={score} />
        <EntropyScale bits={bits} />
      </div>
    </DeepDive>
  )
}

function RouteModel({ assessment }: { assessment: ThreatAssessment | null }) {
  const topology = assessment?.topology_forensics ?? null
  const rows: [string, string][] = [
    ['Relay hops (sender side)', assessment ? String(assessment.header_forensics.route_hop_count) : '—'],
    ['Graph nodes', topology ? String(topology.graph_nodes_count) : '—'],
    ['MemAE loss', topology ? topology.memae_reconstruction_loss.toFixed(3) : '—'],
    ['Zero-day route', topology ? (topology.is_zero_day_route ? 'yes' : 'no') : '—'],
  ]
  return (
    <DeepDive
      title="Route model (MemAE)"
      explanation={
        <>
          <p>
            The delivery route becomes a graph (sender → relay hops → receiver, sender → each link). A graph autoencoder
            trained only on legitimate mail rebuilds it from 50 memorised “normal” prototypes; the reconstruction loss is the
            anomaly score, flagged zero-day above the calibrated threshold.
          </p>
          <p>
            Honest limit: graph nodes only know their position, so it sees route shape. In the ablation, removing the MemAE
            loss left the AUC unchanged (0.953); removing graph size as well dropped it to 0.936.
          </p>
        </>
      }
    >
      <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-1">
        {rows.map(([term, value]) => (
          <div key={term} className="contents">
            <dt className="text-muted">{term}</dt>
            <dd className={cn('text-right', value === '—' ? 'text-muted' : 'text-ink')}>{value}</dd>
          </div>
        ))}
      </dl>
    </DeepDive>
  )
}

/**
 * Every piece of evidence behind the dashboard's score, top to bottom: what moved the score
 * (SHAP), who sent it and what the route model saw, the language evidence and the pipeline,
 * then the delivery route as a graph. Before a scan each block keeps its frame and shows
 * what it will hold.
 */
export function Forensics() {
  const assessment = useThreatStore((s) => s.assessment)
  const details = useThreatStore((s) => s.details)
  const analysing = useThreatStore((s) => !['IDLE', 'COMPLETE', 'ERROR'].includes(s.currentPhase))
  const scored = assessment !== null && details !== null
  const header = assessment?.header_forensics ?? null
  const placeholders = details ? standIns(details.modelStatus) : []

  return (
    <Screen
      title="Forensics"
      subline={
        scored
          ? (header?.subject ?? '(no subject)')
          : analysing
            ? 'A scan is running; its evidence appears here when it completes.'
            : 'No scan to explain yet. After one, this screen breaks its risk score down piece by piece.'
      }
      actions={
        scored ? (
          <div className="text-right">
            <p className="flex items-center justify-end gap-3">
              <DecisionPill risk={assessment.overall_risk} />
              <span className="text-section font-semibold text-ink">
                {assessment.overall_risk}
                <span className="ml-1 text-body font-normal text-muted">/100 risk</span>
              </span>
            </p>
            {placeholders.length > 0 && (
              <p className="mt-1 text-small text-muted">Stand-in models (not evidence): {placeholders.join(', ')}</p>
            )}
          </div>
        ) : (
          !analysing && (
            <Link to="/" className="btn btn-secondary">
              Go to Dashboard
            </Link>
          )
        )
      }
    >
      {/* Each row ends level: the last card of each side column grows into the row's height. */}
      <div className="grid gap-6 lg:grid-cols-12">
        {scored ? <FeatureAttribution assessment={assessment} details={details} /> : <FeatureReference />}
        <div className="flex flex-col gap-6 lg:col-span-4">
          <SenderIdentity header={header} />
          <RouteModel assessment={assessment} />
          <AnalystReasoning className={cn('h-60', STREAM_FILL, 'lg:min-h-[10rem]')} />
        </div>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-12">
        <TopologyMap className="h-[440px] lg:col-span-8" />
        <div className="flex flex-col gap-6 lg:col-span-4 lg:h-[440px]">
          <ContentHeuristicsCard score={header?.nlp_urgency_score ?? null} bits={header?.dga_max_entropy ?? null} />
          <PipelineLog className={cn('h-60', STREAM_FILL, 'lg:min-h-[8rem]')} />
        </div>
      </div>
    </Screen>
  )
}
