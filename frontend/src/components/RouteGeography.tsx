import { lazy, Suspense } from 'react'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

// three.js is the bulk of the bundle; let the rest of the screen become interactive first.
const CyberCanvas = lazy(() => import('@/components/CyberCanvas'))

/** The delivery route on a globe, given the dashboard's largest panel. Its hop list is on the verdict card. */
export function RouteGeography({ className }: { className?: string }) {
  const points = useThreatStore((s) => s.geoCoordinates)
  const ips = useThreatStore((s) => s.assessment?.header_forensics.extracted_ips ?? null)
  const located = points.filter((point) => point.source === 'lookup').length

  return (
    <section className={cn('card flex flex-col', className)} aria-labelledby="route-geography-title">
      <header className="flex items-baseline justify-between gap-3">
        <h2 id="route-geography-title" className="card-title">
          Route geography
        </h2>
        {points.length > 0 && (
          <span className="text-small text-muted">
            {points.length} hop{points.length === 1 ? '' : 's'} · {located} located
          </span>
        )}
      </header>
      <div className="relative mt-3 min-h-[260px] flex-1" aria-hidden="true">
        <Suspense fallback={null}>
          <CyberCanvas />
        </Suspense>
        {points.length === 0 && (
          <p className="pointer-events-none absolute inset-x-0 bottom-0 text-center text-body text-muted">
            {ips === null ? 'The route is drawn here after a scan.' : ips.length > 0 ? 'Locating the relay hops…' : 'No relay hop addresses in this email.'}
          </p>
        )}
      </div>
      <p className="mt-3 text-small text-muted">
        Arcs join the relay hops in delivery order, in the colour of the risk score. A dashed arc touches a hop whose position
        is estimated from its address, not looked up.
      </p>
    </section>
  )
}
