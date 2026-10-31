import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { BrainCircuit, ChevronDown } from 'lucide-react'
import { type ReactNode, useId, useState } from 'react'
import { Link } from 'react-router-dom'
import { EntropyScale, UrgencyMeter } from '@/components/HeuristicMeters'
import { COERCIVE_PHRASES, LEGITIMATE_BAND_BITS } from '@/lib/contentHeuristics'
import { FEATURE_SPACE, type FeatureName, featureValues, formatFeature } from '@/lib/featureSpace'
import { cn } from '@/lib/utils'
import { type AnalysisDetails, type Subsystem, type ThreatAssessment, useThreatStore } from '@/store/useThreatStore'
import { cyberColors } from '@/theme/colors'

const CARD =
  'rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl transition-all duration-300 hover:border-rose-500/50 hover:shadow-[0_0_30px_rgba(225,29,72,0.15)]'
const CARD_TITLE = 'text-[10px] uppercase tracking-[0.3em] text-stone-400'
const SUBSYSTEM_LABEL: Record<Subsystem, string> = {
  PROTOCOL_FORENSICS: 'Protocol forensics',
  VISION_ENGINE: 'Vision',
  TOPOLOGY_GNN: 'Topology',
  COGNITIVE_SLM: 'Language model',
  CONTENT_HEURISTICS: 'Content heuristics',
}

function signed(impact: number): string {
  return `${impact >= 0 ? '+' : '−'}${Math.abs(impact).toFixed(3)}`
}

/** Every feature's value and its SHAP impact: a diverging bar around zero, rose toward phishing. */
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
    <section className={cn(CARD, 'lg:col-span-2')} aria-label="Feature attribution">
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <p className={CARD_TITLE}>Feature attribution · SHAP</p>
        <p className="flex items-center gap-3 text-[11px] text-stone-400">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-3 rounded-l bg-cyber-safe" aria-hidden="true" />← toward legitimate
          </span>
          <span className="flex items-center gap-1.5">
            toward phishing →<span className="h-2 w-3 rounded-r bg-cyber-alert" aria-hidden="true" />
          </span>
        </p>
      </div>

      <ul className="space-y-0.5">
        {FEATURE_SPACE.map((feature, index) => {
          const contribution = byFeature.get(feature.name)
          const share = contribution ? (Math.abs(contribution.impact) / largest) * 50 : 0
          const toPhishing = (contribution?.impact ?? 0) >= 0
          const tooltipId = `${tooltipPrefix}-${index}`
          return (
            <li key={feature.name}>
              <button
                type="button"
                onClick={() => setSelected(feature.name)}
                aria-pressed={selected === feature.name}
                aria-describedby={tooltipId}
                className={cn(
                  'group relative grid w-full cursor-pointer grid-cols-[minmax(0,1fr)_6rem_minmax(0,1.2fr)_4.5rem] items-center gap-3 rounded p-2 text-left transition-colors hover:bg-white/5 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent',
                  selected === feature.name && 'bg-white/[0.07]',
                )}
              >
                <span className="truncate text-sm text-stone-200">{feature.label}</span>
                <span className="font-mono text-xs text-stone-400">{formatFeature(feature.name, values[feature.name])}</span>
                <span className="relative h-2.5" aria-hidden="true">
                  <span className="absolute inset-y-[-3px] left-1/2 w-px bg-stone-600" />
                  {contribution && (
                    <motion.span
                      className={cn('absolute inset-y-0', toPhishing ? 'left-1/2 rounded-r' : 'right-1/2 rounded-l')}
                      style={{ backgroundColor: toPhishing ? cyberColors['cyber-alert'] : cyberColors['cyber-safe'] }}
                      initial={{ width: '0%' }}
                      animate={{ width: `${share}%` }}
                      transition={{ duration: reduceMotion ? 0 : 0.6, ease: 'easeOut' }}
                    />
                  )}
                </span>
                <span className="text-right font-mono text-xs text-stone-300">
                  {contribution ? signed(contribution.impact) : '<1%'}
                </span>
                <span
                  id={tooltipId}
                  role="tooltip"
                  className="pointer-events-none absolute left-2 top-full z-20 mt-1 hidden w-72 rounded-lg border border-white/10 bg-stone-900/95 px-3 py-2 text-xs text-stone-300 shadow-xl group-hover:block group-focus-visible:block"
                >
                  {feature.summary}
                </span>
              </button>
            </li>
          )
        })}
      </ul>

      <div className="mt-4 rounded-2xl border border-white/10 bg-stone-900/40 p-4" aria-live="polite">
        <p className="text-sm text-white">
          {chosen.label}
          <span className="ml-2 text-xs text-stone-400">{SUBSYSTEM_LABEL[chosen.subsystem]}</span>
        </p>
        <p className="mt-1 font-mono text-xs text-stone-300">
          value {formatFeature(chosen.name, values[chosen.name])} · SHAP{' '}
          {chosenImpact ? `${signed(chosenImpact.impact)} (${chosenImpact.percentage.toFixed(1)}% of the decision)` : 'under 1% of the decision'}
        </p>
        <p className="mt-2 text-sm leading-relaxed text-stone-300">{chosen.detail}</p>
      </div>
    </section>
  )
}

/** A card whose header expands a "how it works" section. */
function DeepDive({ title, explanation, children }: { title: string; explanation: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const panelId = useId()
  return (
    <section className={CARD} aria-label={title}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full cursor-pointer items-center justify-between rounded text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent"
      >
        <span className={CARD_TITLE}>{title}</span>
        <span className="flex items-center gap-1 text-[11px] text-stone-400">
          {open ? 'Hide' : 'How it works'}
          <ChevronDown className={cn('h-4 w-4 transition-transform duration-300', open && 'rotate-180')} aria-hidden="true" />
        </span>
      </button>
      <div className="mt-4">{children}</div>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            id={panelId}
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: 'easeOut' }}
            className="overflow-hidden"
          >
            <div className="mt-4 space-y-2 border-t border-white/10 pt-3 text-xs leading-relaxed text-stone-300">{explanation}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  )
}

function RouteModel({ assessment }: { assessment: ThreatAssessment }) {
  const topology = assessment.topology_forensics
  const rows: [string, string][] = [
    ['Relay hops (sender side)', String(assessment.header_forensics.route_hop_count)],
    ['Graph nodes', topology ? String(topology.graph_nodes_count) : '—'],
    ['MemAE loss', topology ? topology.memae_reconstruction_loss.toFixed(3) : '—'],
    ['Zero-day route', topology ? (topology.is_zero_day_route ? 'yes' : 'no') : '—'],
  ]
  return (
    <DeepDive
      title="Route model · MemAE"
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
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
        {rows.map(([term, value]) => (
          <div key={term} className="contents">
            <dt className="text-stone-400">{term}</dt>
            <dd className="text-right font-mono text-stone-200">{value}</dd>
          </div>
        ))}
      </dl>
    </DeepDive>
  )
}

function EmptyState() {
  const analysing = useThreatStore((s) => !['IDLE', 'COMPLETE', 'ERROR'].includes(s.currentPhase))
  return (
    <div className="glass-panel flex h-full w-full flex-col items-center justify-center gap-4 p-8 text-center text-stone-200">
      <BrainCircuit className="h-10 w-10 text-cyber-accent" aria-hidden="true" />
      <h1 className="font-mono text-lg uppercase tracking-[0.25em] text-white">ML forensics</h1>
      <p className="max-w-md text-sm text-stone-400">
        {analysing
          ? 'Analysis in progress — the model’s evidence appears here when it completes.'
          : 'Analyse an email on the Live scan page; this page then explains how the model reached its score, feature by feature.'}
      </p>
      {!analysing && (
        <Link
          to="/"
          className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-sm text-stone-200 transition-colors hover:border-rose-500/50 hover:bg-white/10"
        >
          Go to Live scan
        </Link>
      )}
    </div>
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
    <div className="h-full w-full overflow-y-auto pr-1 text-stone-200">
      <header className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-mono text-lg uppercase tracking-[0.25em] text-white">ML forensics</h1>
          <p className="mt-1 max-w-2xl truncate text-sm text-stone-400" title={header.subject ?? undefined}>
            {header.subject ?? '(no subject)'}
          </p>
        </div>
        <p className="text-right text-sm text-stone-300">
          Risk <span className="font-mono text-2xl text-white">{assessment.overall_risk}</span>
          <span className="text-stone-400">/100</span>
          {standIns.length > 0 && (
            <span className="block text-[11px] text-stone-400">Stand-in models (not evidence): {standIns.join(', ')}</span>
          )}
        </p>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <FeatureAttribution assessment={assessment} details={details} />
        <div className="flex flex-col gap-6">
          <DeepDive
            title="NLP coercion"
            explanation={
              <>
                <p>0.25 per coercive phrase, capped at 1. Matched in natural inflections after removing zero-width characters:</p>
                <ul className="flex flex-wrap gap-1.5">
                  {COERCIVE_PHRASES.map((phrase) => (
                    <li key={phrase} className="rounded-md border border-white/10 px-2 py-0.5 text-stone-400">
                      {phrase}
                    </li>
                  ))}
                </ul>
                <p>Fires on 20.3% of training phishing and 0.1% of legitimate mail.</p>
              </>
            }
          >
            <UrgencyMeter score={header.nlp_urgency_score} />
          </DeepDive>
          <DeepDive
            title="DGA entropy"
            explanation={
              <>
                <p>
                  Shannon entropy of the most random link’s registrable label, the part left of the public suffix
                  (login.paypa1-secure.co.uk → paypa1-secure). Subdomains are free attacker padding and are ignored.
                </p>
                <p>
                  Not “higher is worse”: legitimate links cluster at {LEGITIMATE_BAND_BITS[0]}–{LEGITIMATE_BAND_BITS[1]} bits
                  (52% of them, against 23% of phishing), while phishing fills both tails. In the ablation it is the stronger
                  content feature.
                </p>
              </>
            }
          >
            <EntropyScale bits={header.dga_max_entropy} />
          </DeepDive>
          <RouteModel assessment={assessment} />
        </div>
      </div>
    </div>
  )
}
