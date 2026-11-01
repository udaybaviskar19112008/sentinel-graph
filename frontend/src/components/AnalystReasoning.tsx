import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

/**
 * The language model's reading of the email, streamed token by token, in a contained well:
 * a quieter grey than the evidence around it, scrolling inside its own frame so a long
 * reading never takes over the page.
 */
export function AnalystReasoning({ className }: { className?: string }) {
  const slmStream = useThreatStore((s) => s.slmStream)
  const standIn = useThreatStore((s) => s.details?.modelStatus.slm_dummy ?? false)
  const streaming = useThreatStore(
    (s) => s.socketStatus === 'connected' && s.currentPhase !== 'COMPLETE' && s.currentPhase !== 'ERROR',
  )
  const paneRef = useRef<HTMLDivElement>(null)

  // Keep the newest reasoning in view as tokens arrive.
  useEffect(() => {
    const pane = paneRef.current
    if (pane) pane.scrollTop = pane.scrollHeight
  }, [slmStream])

  return (
    <section className={cn('card flex flex-col', className)} aria-labelledby="analyst-reasoning-title">
      <header className="mb-3 flex items-center justify-between gap-3">
        <h2 id="analyst-reasoning-title" className="card-title">
          Analyst reasoning
        </h2>
        {standIn && <span className="pill bg-pill-warning-bg text-pill-warning-ink">Scripted stand-in</span>}
      </header>
      <div
        ref={paneRef}
        className="min-h-0 flex-1 overflow-y-auto whitespace-pre-wrap rounded-md bg-raised px-4 py-3 text-body text-muted"
      >
        {slmStream || 'No reasoning yet. The local language model writes its reading here during a scan.'}
        {streaming && <span className="ml-0.5 motion-safe:animate-pulse">▌</span>}
      </div>
    </section>
  )
}
