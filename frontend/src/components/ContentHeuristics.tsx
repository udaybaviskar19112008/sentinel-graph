import { EntropyScale, UrgencyMeter } from '@/components/HeuristicMeters'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

/** The two content heuristics, filled in as soon as Tier 1 reports. */
export function ContentHeuristics({ className }: { className?: string }) {
  const findings = useThreatStore((s) => s.headerFindings ?? s.assessment?.header_forensics ?? null)
  return (
    <section className={cn('card space-y-5', className)} aria-labelledby="content-heuristics-title">
      <h2 id="content-heuristics-title" className="card-title">
        Content heuristics
      </h2>
      <UrgencyMeter score={findings ? findings.nlp_urgency_score : null} />
      <EntropyScale bits={findings ? findings.dga_max_entropy : null} />
    </section>
  )
}
