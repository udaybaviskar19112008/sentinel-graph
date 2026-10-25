import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

const VERDICT_STYLE = {
  BENIGN: 'text-cyber-safe border-cyber-safe/40',
  SUSPICIOUS: 'text-cyber-accent border-cyber-accent/40',
  PHISHING: 'text-cyber-alert border-cyber-alert/40',
  CRITICAL: 'text-cyber-alert border-cyber-alert/60 animate-pulse',
} as const

/** Telemetry log (newest first) over the SLM's streamed reasoning. */
export function LiveTerminal() {
  const liveLogs = useThreatStore((s) => s.liveLogs)
  const slmStream = useThreatStore((s) => s.slmStream)
  const verdict = useThreatStore((s) => s.details?.verdict ?? null)
  const streaming = useThreatStore(
    (s) => s.socketStatus === 'connected' && s.currentPhase !== 'COMPLETE' && s.currentPhase !== 'ERROR',
  )
  const reasoningRef = useRef<HTMLDivElement>(null)

  // Keep the newest reasoning in view as tokens arrive.
  useEffect(() => {
    const pane = reasoningRef.current
    if (pane) pane.scrollTop = pane.scrollHeight
  }, [slmStream])

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel flex h-full flex-col overflow-hidden"
    >
      <header className="border-b border-white/10 px-4 py-2 text-[10px] uppercase tracking-[0.3em] text-white/50">
        Telemetry
      </header>
      <ol className="flex-1 space-y-1 overflow-y-auto px-4 py-2 font-mono text-xs text-cyber-accent" aria-live="polite">
        <AnimatePresence initial={false}>
          {liveLogs.map((log, index) => (
            // Logs are prepended, so distance from the end is a stable key.
            <motion.li
              key={liveLogs.length - index}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              className={cn('break-words', log.startsWith('ERROR') && 'text-cyber-alert')}
            >
              {log}
            </motion.li>
          ))}
        </AnimatePresence>
        {liveLogs.length === 0 && <li className="text-white/30">Awaiting telemetry...</li>}
      </ol>
      <section className="flex h-44 flex-col border-t border-white/10">
        <div className="flex items-center justify-between px-4 pt-2 text-[10px] uppercase tracking-[0.3em] text-white/50">
          <span>SLM reasoning</span>
          {verdict && (
            <span className={cn('rounded border px-2 py-0.5 font-mono tracking-widest', VERDICT_STYLE[verdict])}>
              {verdict}
            </span>
          )}
        </div>
        <div ref={reasoningRef} className="flex-1 overflow-y-auto px-4 py-2 font-mono text-sm font-bold text-white">
          {slmStream || <span className="font-normal text-white/30">No reasoning yet.</span>}
          {streaming && <span className="ml-0.5 animate-pulse text-cyber-accent">▌</span>}
        </div>
      </section>
    </motion.div>
  )
}
