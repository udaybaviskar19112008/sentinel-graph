import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

// The stages a scan reports, in order, under the names its log lines use (threatStream.describe).
const STAGES: [phase: string, what: string][] = [
  ['RECEIVED', 'the raw email arrives'],
  ['TIER_1', 'header forensics: authentication, route, links'],
  ['VISION', 'the first link detonated in the sandbox'],
  ['TOPOLOGY', 'the delivery graph and its MemAE score'],
  ['SLM_VERDICT', 'the language model’s reading'],
  ['COMPLETE', 'fusion risk score and SHAP evidence'],
]

/**
 * The analysis telemetry, newest first. Lines are machine output (phase, elapsed time),
 * so they keep the monospace; the newest is in full ink, the rest recede. Before the
 * first scan the pane lists the stages a scan will report, rather than standing empty.
 */
export function PipelineLog({ className }: { className?: string }) {
  const liveLogs = useThreatStore((s) => s.liveLogs)
  const reduceMotion = useReducedMotion()

  return (
    <section className={cn('card flex flex-col', className)} aria-labelledby="pipeline-log-title">
      <header className="mb-3 flex items-baseline justify-between gap-3">
        <h2 id="pipeline-log-title" className="card-title">
          Pipeline log
        </h2>
        <span className="text-small text-muted">Newest first</span>
      </header>
      <ol className="min-h-0 flex-1 space-y-1 overflow-y-auto font-mono text-body text-muted" aria-live="polite">
        <AnimatePresence initial={false}>
          {liveLogs.map((log, index) => (
            // Logs are prepended, so distance from the end is a stable key.
            <motion.li
              key={liveLogs.length - index}
              initial={reduceMotion ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              className={cn('break-words', log.startsWith('ERROR') ? 'text-negative' : index === 0 && 'text-ink')}
            >
              {log}
            </motion.li>
          ))}
        </AnimatePresence>
        {liveLogs.length === 0 && (
          <li>
            <p className="font-sans text-body">No pipeline events yet. A scan reports each stage here:</p>
            <ol className="mt-3 space-y-1.5">
              {STAGES.map(([phase, what]) => (
                <li key={phase} className="flex gap-3">
                  <span className="w-24 shrink-0">{phase}</span>
                  <span className="font-sans">{what}</span>
                </li>
              ))}
            </ol>
          </li>
        )}
      </ol>
    </section>
  )
}
