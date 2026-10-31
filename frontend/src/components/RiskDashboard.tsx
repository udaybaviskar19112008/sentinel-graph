import { RiskGauge } from '@/components/RiskGauge'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'
import { cyberColors } from '@/theme/colors'

const POINTS_PER_PHRASE = 0.25 // nlp_heuristics.POINTS_PER_MATCH: one coercive phrase
const DGA_SCALE_MAX_BITS = 5 // a registrable label rarely exceeds ~5 bits (log2 of its character set)
// Where most legitimate links sit. Research corpus (2002-06): 52% of legitimate links fall in
// 2.5-3.0 bits against 23% of phishing, which spreads into both tails. So DGA entropy is not
// "higher is worse" (low-entropy labels are phishing-heavy too), and the bar carries no risk colour.
const LEGITIMATE_BAND_BITS: readonly [number, number] = [2.5, 3.0]
const LABEL = 'text-xs uppercase tracking-widest text-stone-400'
const TRACK = 'relative h-1.5 flex-1 overflow-hidden rounded-full bg-stone-700/50'
const VALUE = 'w-20 shrink-0 text-right font-mono text-xs text-stone-300'

function percentOfScale(value: number, max: number): number {
  return Math.min(Math.max(value / max, 0), 1) * 100
}

/** Coercion score 0-1: the fill's colour at its tip is the severity at that score. */
function UrgencyMeter({ score }: { score: number | null }) {
  const percent = percentOfScale(score ?? 0, 1)
  const phrases = score === null ? null : Math.round(score / POINTS_PER_PHRASE)
  return (
    <div className="space-y-1.5">
      <p className={LABEL}>Social engineering NLP</p>
      <div className="flex items-center gap-3">
        <div
          className={TRACK}
          role="meter"
          aria-label="Coercive phrases in the body"
          aria-valuemin={0}
          aria-valuemax={1}
          aria-valuenow={score ?? 0}
          aria-valuetext={phrases === null ? 'not analysed yet' : `${phrases} coercive phrases, score ${score}`}
        >
          <div
            className="h-full rounded-full transition-[width] duration-700 ease-out"
            style={{
              width: `${percent}%`,
              // Amber -> rose across the whole track, so a short fill shows only its amber start.
              backgroundImage: `linear-gradient(90deg, ${cyberColors['cyber-warning']}, ${cyberColors['cyber-alert']})`,
              backgroundSize: percent > 0 ? `${(100 / percent) * 100}% 100%` : undefined,
            }}
          />
        </div>
        <span className={VALUE}>
          {phrases === null ? '—' : `${phrases === 4 ? '4+' : phrases} phrase${phrases === 1 ? '' : 's'}`}
        </span>
      </div>
    </div>
  )
}

/** Label entropy on a neutral 0-5 bit scale, with the usual legitimate band shaded. */
function EntropyScale({ bits }: { bits: number | null }) {
  const [low, high] = LEGITIMATE_BAND_BITS
  const scored = bits !== null && bits > 0
  const within = scored && bits >= low && bits <= high
  return (
    <div className="space-y-1.5">
      <p className={LABEL}>Algorithmic DGA entropy</p>
      <div className="flex items-center gap-3">
        <div
          className={TRACK}
          role="meter"
          aria-label="Highest Shannon entropy of a link's domain label"
          aria-valuemin={0}
          aria-valuemax={DGA_SCALE_MAX_BITS}
          aria-valuenow={bits ?? 0}
          aria-valuetext={scored ? `${bits.toFixed(2)} bits` : 'no scorable link'}
          title="Research corpus: 52% of legitimate vs 23% of phishing links fall in 2.5–3.0 bits; phishing fills both tails."
        >
          <div
            className="absolute inset-y-0 bg-stone-500/50"
            style={{
              left: `${percentOfScale(low, DGA_SCALE_MAX_BITS)}%`,
              right: `${100 - percentOfScale(high, DGA_SCALE_MAX_BITS)}%`,
            }}
          />
          {scored && (
            <div
              className="absolute inset-y-0 w-1 -translate-x-1/2 rounded-full bg-stone-100 transition-[left] duration-700 ease-out"
              style={{ left: `${percentOfScale(bits, DGA_SCALE_MAX_BITS)}%` }}
            />
          )}
        </div>
        <span className={VALUE}>{bits === null ? '—' : scored ? `${bits.toFixed(2)} bits` : 'no link'}</span>
      </div>
      <p className="text-[10px] leading-snug text-stone-500">
        {bits === null
          ? 'Shaded: where most legitimate links sit (2.5–3.0 bits)'
          : !scored
            ? 'No scorable link domain in this email'
            : within
              ? 'Inside the band most legitimate links sit in'
              : 'Outside the band most legitimate links sit in'}
      </p>
    </div>
  )
}

/** The two content heuristics, filled in as soon as Tier 1 reports. */
export function ContentHeuristics({ className }: { className?: string }) {
  const findings = useThreatStore((s) => s.headerFindings ?? s.assessment?.header_forensics ?? null)
  return (
    <section className={cn('glass-panel pointer-events-auto space-y-4 p-4', className)} aria-label="Content heuristics">
      <p className="text-[10px] uppercase tracking-[0.3em] text-stone-400">Content heuristics</p>
      <UrgencyMeter score={findings ? findings.nlp_urgency_score : null} />
      <EntropyScale bits={findings ? findings.dga_max_entropy : null} />
    </section>
  )
}

/** The right-hand column of the live view: overall risk, then the content heuristics. */
export function RiskDashboard({ className }: { className?: string }) {
  return (
    <div className={cn('flex w-64 flex-col gap-3', className)}>
      <RiskGauge className="w-full" />
      <ContentHeuristics />
    </div>
  )
}
