import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { ChevronDown } from 'lucide-react'
import { type ReactNode, useId, useState } from 'react'
import { Link } from 'react-router-dom'
import { EntropyScale, UrgencyMeter } from '@/components/HeuristicMeters'
import { Screen } from '@/components/Screen'
import { VerdictPill } from '@/components/VerdictCard'
import { COERCIVE_PHRASES, LEGITIMATE_BAND_BITS } from '@/lib/contentHeuristics'
import { FEATURE_SPACE, type FeatureName, featureValues, formatFeature } from '@/lib/featureSpace'
import { cn } from '@/lib/utils'
import {
  type AnalysisDetails,
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
const ROW_GRID = 'grid grid-cols-[minmax(0,1fr)_6.5rem_minmax(0,1.2fr)_4rem] items-center gap-3'

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
        <span>Value</span>
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
                <span className="truncate text-body text-ink">
                  <span className={cn('border-b pb-px', isSelected ? 'border-accent' : 'border-transparent')}>{feature.label}</span>
                </span>
                <span className="truncate text-small text-muted">{formatFeature(feature.name, values[feature.name])}</span>
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

/** A card whose header expands a "how it works" section. */
function DeepDive({ title, explanation, children }: { title: string; explanation: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const panelId = useId()
  return (
    <section className="card" aria-label={title}>
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
            <div className="mt-4 space-y-2 border-t border-rule pt-3 text-body text-ink">{explanation}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  )
}

/**
 * Who the email claims to be from, beside the domains that would receive its replies and
 * bounces: the evidence behind display-name spoofing. A domain that differs from the
 * sender's is the row's one red mark.
 */
function SenderIdentity({ header }: { header: HeaderForensics }) {
  const from = header.from_domain
  const rows: [string, string | null][] = [
    ['From', from],
    ['Reply-To', header.reply_to_domain],
    ['Return-Path', header.return_path_domain],
  ]
  const diverges = rows.some(([, domain]) => domain !== null && from !== null && domain !== from)
  return (
    <section className="card" aria-labelledby="sender-identity-title">
      <header className="flex items-center justify-between gap-3">
        <h2 id="sender-identity-title" className="card-title">
          Sender identity
        </h2>
        {header.impersonated_brand && (
          <span
            className={cn(
              'pill',
              header.display_name_spoof_risk >= 1
                ? 'bg-pill-negative-bg text-pill-negative-ink'
                : 'bg-pill-warning-bg text-pill-warning-ink',
            )}
          >
            Names {header.impersonated_brand.charAt(0).toUpperCase() + header.impersonated_brand.slice(1)}
          </span>
        )}
      </header>
      <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1">
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

/** The two content heuristics in one card, named as on the live view, each explained under "How it works". */
function ContentHeuristicsCard({ score, bits }: { score: number | null; bits: number | null }) {
  return (
    <DeepDive
      title="Content heuristics"
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

/** No scan yet: the screen keeps its frame and shows what it will explain. */
function EmptyState() {
  const analysing = useThreatStore((s) => !['IDLE', 'COMPLETE', 'ERROR'].includes(s.currentPhase))
  return (
    <Screen
      title="ML forensics"
      subline={
        analysing
          ? 'A scan is running; its evidence appears here when it completes.'
          : 'No scan to explain yet. After one, this screen breaks its risk score down feature by feature.'
      }
      actions={
        !analysing && (
          <Link to="/" className="btn btn-secondary">
            Go to Live scan
          </Link>
        )
      }
    >
      <div className="grid items-start gap-6 lg:grid-cols-12">
        <FeatureReference />
        <div className="flex flex-col gap-6 lg:col-span-4">
          <ContentHeuristicsCard score={null} bits={null} />
          <RouteModel assessment={null} />
        </div>
      </div>
    </Screen>
  )
}

/** Drill-down into the fusion model's evidence for the current scan. */
export function MLAnalysis() {
  const assessment = useThreatStore((s) => s.assessment)
  const details = useThreatStore((s) => s.details)
  if (!assessment || !details) return <EmptyState />

  const header = assessment.header_forensics
  const standIns = [details.modelStatus.vision_placeholder && 'vision', details.modelStatus.slm_dummy && 'language model'].filter(
    (name): name is string => typeof name === 'string',
  )
  return (
    <Screen
      title="ML forensics"
      subline={header.subject ?? '(no subject)'}
      actions={
        <div className="text-right">
          <p className="flex items-center justify-end gap-3">
            <VerdictPill verdict={details.verdict} />
            <span className="text-section font-semibold text-ink">
              {assessment.overall_risk}
              <span className="ml-1 text-body font-normal text-muted">/100 risk</span>
            </span>
          </p>
          {standIns.length > 0 && <p className="mt-1 text-small text-muted">Stand-in models (not evidence): {standIns.join(', ')}</p>}
        </div>
      }
    >
      <div className="grid items-start gap-6 lg:grid-cols-12">
        <FeatureAttribution assessment={assessment} details={details} />
        <div className="flex flex-col gap-6 lg:col-span-4">
          <SenderIdentity header={header} />
          <ContentHeuristicsCard score={header.nlp_urgency_score} bits={header.dga_max_entropy} />
          <RouteModel assessment={assessment} />
        </div>
      </div>
    </Screen>
  )
}
