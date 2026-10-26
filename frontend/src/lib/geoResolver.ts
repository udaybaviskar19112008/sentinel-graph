/**
 * Relay-hop IPs -> globe coordinates.
 *
 * Public IPs are looked up at ipapi.co. Anything that cannot be located (private or
 * reserved ranges, lookup failures, CORS errors, 429 rate limits, timeouts) gets a
 * deterministic stand-in coordinate hashed from the IP, so the globe always has
 * something to draw. Stand-ins are flagged ``estimated`` and must be shown as such:
 * they are not where the host is.
 *
 * Note: a lookup sends the hop's IP to ipapi.co. Set ``VITE_GEO_LOOKUP=off`` to keep
 * every IP on this machine (all points are then estimated).
 */

export interface GeoPoint {
  ip: string
  lat: number
  lng: number
  source: 'lookup' | 'estimated'
}

const LOOKUP_ENABLED = import.meta.env.VITE_GEO_LOOKUP !== 'off'
const LOOKUP_TIMEOUT_MS = 4000
// ipapi.co's free tier is rate limited; never ask twice for the same IP in one session.
const cache = new Map<string, Promise<GeoPoint>>()

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
const IPV6_RE = /^[0-9a-f:.]+$/i

/** Whether ``ip`` is a syntactically valid, globally routable address worth looking up. */
export function isPublicIp(ip: string): boolean {
  const v4 = IPV4_RE.exec(ip)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    if (v4.slice(1).some((octet) => Number(octet) > 255)) return false
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 || // multicast and reserved
      (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    )
  }
  if (!ip.includes(':') || !IPV6_RE.test(ip)) return false
  const lower = ip.toLowerCase()
  return !(lower === '::' || lower === '::1' || /^f[cd]/.test(lower) || /^fe[89ab]/.test(lower))
}

/** 32-bit FNV-1a; ``seed`` gives independent hashes of the same string. */
function fnv1a(text: string, seed: number): number {
  let hash = 0x811c9dc5 ^ seed
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193)
  }
  return hash >>> 0
}

/** A stable stand-in location for ``ip``: lat in [-90, 90], lng in [-180, 180). */
export function estimatedPoint(ip: string): GeoPoint {
  return {
    ip,
    lat: (fnv1a(ip, 0) % 18001) / 100 - 90,
    lng: (fnv1a(ip, 0x9e3779b9) % 36000) / 100 - 180,
    source: 'estimated',
  }
}

async function lookup(ip: string): Promise<GeoPoint> {
  try {
    const response = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
    })
    if (!response.ok) return estimatedPoint(ip) // 429 and friends
    // A refused lookup still answers 200: {"error": true, "reason": "RateLimited"}.
    const body = (await response.json()) as { latitude?: unknown; longitude?: unknown; error?: unknown }
    const { latitude, longitude } = body
    if (body.error || typeof latitude !== 'number' || typeof longitude !== 'number') return estimatedPoint(ip)
    return { ip, lat: latitude, lng: longitude, source: 'lookup' }
  } catch {
    return estimatedPoint(ip) // network or CORS failure, timeout, malformed JSON
  }
}

/** One point per IP, in input order (sender side first). Never rejects. */
export function resolveIPsToCoords(ips: string[]): Promise<GeoPoint[]> {
  return Promise.all(
    ips.map((ip) => {
      if (!LOOKUP_ENABLED || !isPublicIp(ip)) return Promise.resolve(estimatedPoint(ip))
      let point = cache.get(ip)
      if (!point) {
        point = lookup(ip)
        cache.set(ip, point)
      }
      return point
    }),
  )
}
