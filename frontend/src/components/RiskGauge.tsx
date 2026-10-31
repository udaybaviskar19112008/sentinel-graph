import { motion } from 'framer-motion'
import { TriangleAlert } from 'lucide-react'
import { cn } from '@/lib/utils'
import { type ModelStatus, useThreatStore } from '@/store/useThreatStore'
import { cyberColors } from '@/theme/colors'

const RING_RADIUS = 42
const CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS

function ringColor(risk: number | null): string {
  if (risk === null) return 'rgba(255, 255, 255, 0.15)'
  if (risk >= 75) return cyberColors['cyber-alert']
  if (risk >= 40) return cyberColors['cyber-warning']
  return cyberColors['cyber-safe']
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

/** Overall risk (0-100) as a ring, with the verdict and any stand-in models called out. */
export function RiskGauge({ className }: { className?: string }) {
  const risk = useThreatStore((s) => s.assessment?.overall_risk ?? null)
  const verdict = useThreatStore((s) => s.details?.verdict ?? null)
  const modelStatus = useThreatStore((s) => s.details?.modelStatus ?? null)
  const estimatedHops = useThreatStore((s) => s.geoCoordinates.filter((p) => p.source === 'estimated').length)
  const totalHops = useThreatStore((s) => s.geoCoordinates.length)
  const color = ringColor(risk)
  const placeholders = modelStatus ? standIns(modelStatus) : []
  // Globe positions hashed from the IP because no lookup answered; they are not real locations.
  if (estimatedHops > 0) placeholders.push(`${estimatedHops}/${totalHops} hop locations on the globe`)

  return (
    <div className={cn('glass-panel pointer-events-auto w-52 p-4', className)}>
      <p className="text-[10px] uppercase tracking-[0.3em] text-stone-400">Overall risk</p>
      <div className="relative mx-auto my-2 h-28 w-28">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90" aria-hidden="true">
          <circle cx="50" cy="50" r={RING_RADIUS} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
          <motion.circle
            cx="50"
            cy="50"
            r={RING_RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            initial={false}
            animate={{ strokeDashoffset: CIRCUMFERENCE * (1 - (risk ?? 0) / 100) }}
            transition={{ duration: 0.8, ease: 'easeOut' }}
          />
        </svg>
        <span
          className="absolute inset-0 grid place-items-center font-mono text-3xl font-bold"
          style={{ color: risk === null ? undefined : color }}
          aria-label={risk === null ? 'No score yet' : `Risk ${risk} out of 100`}
        >
          {risk ?? '--'}
        </span>
      </div>
      <p className="text-center font-mono text-xs tracking-widest text-stone-300">{verdict ?? 'AWAITING SCAN'}</p>
      {placeholders.length > 0 && (
        <p className="mt-3 flex gap-1.5 border-t border-glass-border pt-2 text-[10px] leading-snug text-stone-400">
          <TriangleAlert className="h-3 w-3 shrink-0 text-cyber-warning" aria-hidden="true" />
          Stand-in models (scores not evidence): {placeholders.join(', ')}
        </p>
      )}
    </div>
  )
}
