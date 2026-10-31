import { motion, useReducedMotion } from 'framer-motion'
import { DGA_SCALE_MAX_BITS, LEGITIMATE_BAND_BITS, phraseCount } from '@/lib/contentHeuristics'
import { cyberColors } from '@/theme/colors'

const LABEL = 'text-xs uppercase tracking-widest text-stone-400'
const TRACK = 'relative h-1.5 flex-1 overflow-hidden rounded-full bg-stone-700/50'
const VALUE = 'w-20 shrink-0 text-right font-mono text-xs text-stone-300'
const SEVERITY_GRADIENT = `linear-gradient(90deg, ${cyberColors['cyber-warning']}, ${cyberColors['cyber-alert']})`

function percentOfScale(value: number, max: number): number {
  return Math.min(Math.max(value / max, 0), 1) * 100
}

/** Animate from zero on mount and between values after; instant when reduced motion is asked for. */
function useMeterTransition() {
  return { duration: useReducedMotion() ? 0 : 0.7, ease: 'easeOut' } as const
}

/** Coercion score 0-1. The fill reveals a full-width amber -> rose gradient, so its tip shows the severity. */
export function UrgencyMeter({ score }: { score: number | null }) {
  const transition = useMeterTransition()
  const percent = percentOfScale(score ?? 0, 1)
  const phrases = score === null ? null : phraseCount(score)
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
          <motion.div
            className="absolute inset-0 rounded-full"
            style={{ backgroundImage: SEVERITY_GRADIENT }}
            initial={{ clipPath: 'inset(0 100% 0 0 round 9999px)' }}
            animate={{ clipPath: `inset(0 ${100 - percent}% 0 0 round 9999px)` }}
            transition={transition}
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
export function EntropyScale({ bits }: { bits: number | null }) {
  const transition = useMeterTransition()
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
            <motion.div
              className="absolute inset-y-0 w-1 -translate-x-1/2 rounded-full bg-stone-100"
              initial={{ left: '0%' }}
              animate={{ left: `${percentOfScale(bits, DGA_SCALE_MAX_BITS)}%` }}
              transition={transition}
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
