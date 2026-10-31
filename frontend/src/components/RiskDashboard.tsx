import { EntropyScale, UrgencyMeter } from '@/components/HeuristicMeters'
import { RiskGauge } from '@/components/RiskGauge'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

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
