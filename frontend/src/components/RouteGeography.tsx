import { lazy, Suspense } from 'react'
import { type GeoPoint, isPublicIp } from '@/lib/geoResolver'
import { cn } from '@/lib/utils'
import { useThreatStore } from '@/store/useThreatStore'

// three.js is the bulk of the bundle; let the rest of the screen become interactive first.
const CyberCanvas = lazy(() => import('@/components/CyberCanvas'))

const SHOWN_HOPS = 5

function degrees(value: number, positive: string, negative: string): string {
  return `${Math.abs(value).toFixed(1)}°${value >= 0 ? positive : negative}`
}

/** Where a hop sits, or why its globe position is only a stand-in. */
function place(point: GeoPoint): string {
  if (point.source === 'lookup') return `${degrees(point.lat, 'N', 'S')} ${degrees(point.lng, 'E', 'W')}`
  return isPublicIp(point.ip) ? 'Estimated: lookup failed' : 'Estimated: private range'
}

/** The route on a globe, with the hop list beside it carrying each hop's address and position. */
export function RouteGeography({ className }: { className?: string }) {
  const points = useThreatStore((s) => s.geoCoordinates)
  const ips = useThreatStore((s) => s.assessment?.header_forensics.extracted_ips ?? null)
  const estimated = points.filter((point) => point.source === 'estimated').length
  const hidden = points.length - SHOWN_HOPS

  return (
    <section className={cn('card', className)} aria-labelledby="route-geography-title">
      <header className="flex items-baseline justify-between gap-3">
        <h2 id="route-geography-title" className="card-title">
          Route geography
        </h2>
        {points.length > 0 && (
          <span className="text-small text-muted">
            {points.length} hop{points.length === 1 ? '' : 's'}
          </span>
        )}
      </header>
      <div className="mt-3 h-[200px]" aria-hidden="true">
        <Suspense fallback={null}>
          <CyberCanvas />
        </Suspense>
      </div>
      {points.length > 0 ? (
        <ol className="mt-3" aria-label="Relay hops, sender side first">
          {points.slice(0, SHOWN_HOPS).map((point, index) => (
            <li key={`${index}:${point.ip}`} className="flex items-baseline gap-3 border-t border-rule py-1.5 first:border-t-0">
              <span className="w-3 shrink-0 text-small text-muted">{index + 1}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-small text-ink">{point.ip}</span>
              <span className="shrink-0 text-small text-muted">{place(point)}</span>
            </li>
          ))}
          {hidden > 0 && <li className="pt-1 text-small text-muted">+{hidden} more hops</li>}
        </ol>
      ) : (
        <p className="mt-3 text-body text-muted">
          {ips === null ? 'Hop locations appear after a scan.' : ips.length > 0 ? 'Locating the relay hops…' : 'No relay hop addresses in this email.'}
        </p>
      )}
      {estimated > 0 && (
        <p className="mt-2 text-small text-muted">Dashed arcs touch estimated hops: positions hashed from the address, not where the host is.</p>
      )}
    </section>
  )
}
