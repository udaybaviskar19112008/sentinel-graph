import { motion, useReducedMotion } from 'framer-motion'
import { DGA_SCALE_MAX_BITS, LEGITIMATE_BAND_BITS, phraseCount } from '@/lib/contentHeuristics'
import { cn } from '@/lib/utils'

const MAX_PHRASES = 4 // 0.25 per phrase, capped at 1

function percentOfScale(value: number, max: number): number {
  return Math.min(Math.max(value / max, 0), 1) * 100
}

function MeterHead({ label, value }: { label: string; value: string }) {
  return (
    <p className="flex items-baseline justify-between gap-3">
      <span className="text-body text-muted">{label}</span>
      <span className="text-body text-ink">{value}</span>
    </p>
  )
}

/**
 * Coercion score 0-1 as four segments, one per coercive phrase (0.25 each, capped at 1):
 * a lit segment is a phrase found, so the meter reads as a count rather than a vague level.
 */
export function UrgencyMeter({ score }: { score: number | null }) {
  const phrases = score === null ? null : Math.min(phraseCount(score), MAX_PHRASES)
  const value =
    phrases === null ? '—' : phrases === 0 ? 'none' : `${phrases === MAX_PHRASES ? '4+' : phrases} phrase${phrases === 1 ? '' : 's'}`
  return (
    <div className="space-y-2">
      <MeterHead label="Coercive wording" value={value} />
      <div
        className="flex gap-0.5"
        role="meter"
        aria-label="Coercive phrases in the body"
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuenow={score ?? 0}
        aria-valuetext={phrases === null ? 'not analysed yet' : `${phrases} coercive phrases, score ${score}`}
      >
        {Array.from({ length: MAX_PHRASES }, (_, index) => (
          <span
            key={index}
            className={cn(
              'h-2 flex-1 rounded-full transition-colors duration-300',
              phrases !== null && index < phrases ? 'bg-negative' : 'bg-raised',
            )}
          />
        ))}
      </div>
    </div>
  )
}

/** Label entropy on a neutral 0-5 bit scale, with the usual legitimate band shaded. Not "higher is worse". */
export function EntropyScale({ bits }: { bits: number | null }) {
  const reduceMotion = useReducedMotion()
  const [low, high] = LEGITIMATE_BAND_BITS
  const band = `${low.toFixed(1)}–${high.toFixed(1)}`
  const scored = bits !== null && bits > 0
  const within = scored && bits >= low && bits <= high
  return (
    <div className="space-y-2">
      <MeterHead label="Link-domain entropy" value={bits === null ? '—' : scored ? `${bits.toFixed(2)} bits` : 'no link'} />
      <div
        className="relative h-2 rounded-full bg-raised"
        role="meter"
        aria-label="Highest Shannon entropy of a link's domain label"
        aria-valuemin={0}
        aria-valuemax={DGA_SCALE_MAX_BITS}
        aria-valuenow={bits ?? 0}
        aria-valuetext={scored ? `${bits.toFixed(2)} bits` : 'no scorable link'}
        title="Research corpus: 52% of legitimate vs 23% of phishing links fall in 2.5–3.0 bits; phishing fills both tails."
      >
        <span
          className="absolute inset-y-0 bg-control"
          style={{
            left: `${percentOfScale(low, DGA_SCALE_MAX_BITS)}%`,
            right: `${100 - percentOfScale(high, DGA_SCALE_MAX_BITS)}%`,
          }}
        />
        {scored && (
          <motion.span
            className="absolute -inset-y-1 w-0.5 -translate-x-1/2 rounded-full bg-ink"
            initial={false}
            animate={{ left: `${percentOfScale(bits, DGA_SCALE_MAX_BITS)}%` }}
            transition={{ duration: reduceMotion ? 0 : 0.5, ease: 'easeOut' }}
          />
        )}
      </div>
      <p className="flex justify-between text-small text-muted" aria-hidden="true">
        <span>0</span>
        <span>{DGA_SCALE_MAX_BITS} bits</span>
      </p>
      <p className="text-small text-muted">
        {bits === null
          ? `Shaded: where most legitimate links sit (${band} bits)`
          : !scored
            ? 'No scorable link domain in this email'
            : within
              ? `Inside the ${band} bit band most legitimate links sit in`
              : `Outside the ${band} bit band most legitimate links sit in`}
      </p>
    </div>
  )
}
