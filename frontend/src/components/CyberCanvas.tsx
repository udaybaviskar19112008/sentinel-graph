import { Line, Sphere } from '@react-three/drei'
import { Canvas, useFrame } from '@react-three/fiber'
import { useMemo, useRef } from 'react'
import * as THREE from 'three'
import type { GeoPoint } from '@/lib/geoResolver'
import { useThreatStore } from '@/store/useThreatStore'
import { cyberColors } from '@/theme/colors'

const GLOBE_RADIUS = 2
const ARC_SEGMENTS = 50
// Lowest an arc's apex may sit, as a multiple of the radius, however far apart its hops are.
const ARC_APEX = 1.1
const MARKER_RADIUS = 0.035
const ALERT_RISK = 50 // the classifier's own decision threshold: probability 0.5
const SPIN_RADIANS_PER_SECOND = 0.06 // about 0.001 rad per frame at 60 fps
const ESTIMATED_COLOR = 'rgba(214, 211, 209, 0.6)' // stone-300: a stand-in position, never a risk state
const GLOBE_COLOR = '#57534e' // stone-600

/** Geographic degrees to a point on a sphere of ``radius``: +y is north, the prime meridian is +x. */
function latLongToVector3(lat: number, lon: number, radius: number): THREE.Vector3 {
  const phi = THREE.MathUtils.degToRad(90 - lat) // polar angle from the north pole
  const theta = THREE.MathUtils.degToRad(lon + 180)
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  )
}

/**
 * Points along a Bezier arc lifted off the surface between two hops, or null if they coincide.
 *
 * The control point sits on the normalised midpoint direction. Its height grows with the
 * angle between the hops: a fixed 1.2x radius (right for short hops) lets wide arcs dip
 * through the globe, since a quadratic Bezier only reaches halfway to its control point.
 */
function arcPoints(from: GeoPoint, to: GeoPoint): THREE.Vector3[] | null {
  const start = latLongToVector3(from.lat, from.lng, GLOBE_RADIUS)
  const end = latLongToVector3(to.lat, to.lng, GLOBE_RADIUS)
  if (start.distanceTo(end) < 1e-3) return null
  let direction = start.clone().add(end)
  if (direction.lengthSq() < 1e-6) {
    // Antipodal hops: any great circle works; pick one perpendicular to the start.
    const axis = Math.abs(start.y) < GLOBE_RADIUS * 0.99 ? new THREE.Vector3(0, 1, 0) : new THREE.Vector3(1, 0, 0)
    direction = new THREE.Vector3().crossVectors(start, axis)
  }
  const halfAngle = start.angleTo(end) / 2
  // Apex = 0.5 * control + 0.25 * (start + end); solve for the control height that puts it at ARC_APEX.
  const lift = GLOBE_RADIUS * (2 * ARC_APEX - Math.cos(halfAngle))
  const control = direction.normalize().multiplyScalar(lift)
  return new THREE.QuadraticBezierCurve3(start, control, end).getPoints(ARC_SEGMENTS)
}

function ThreatGlobe() {
  const group = useRef<THREE.Group>(null)
  const geoCoordinates = useThreatStore((s) => s.geoCoordinates)
  const alert = useThreatStore((s) => (s.assessment?.overall_risk ?? 0) > ALERT_RISK)
  const reducedMotion = useMemo(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches, [])
  const arcColor = alert ? cyberColors['cyber-alert'] : cyberColors['cyber-safe']

  // Hop 0 -> hop 1 -> ... in delivery order; an arc is estimated if either end is.
  const arcs = useMemo(
    () =>
      geoCoordinates.slice(1).flatMap((to, index) => {
        const from = geoCoordinates[index]
        const points = arcPoints(from, to)
        const estimated = from.source === 'estimated' || to.source === 'estimated'
        return points ? [{ key: `${index}:${from.ip}->${to.ip}`, points, estimated }] : []
      }),
    [geoCoordinates],
  )

  useFrame((_state, delta) => {
    if (group.current) group.current.rotation.y += delta * SPIN_RADIANS_PER_SECOND * (reducedMotion ? 0.2 : 1)
  })

  return (
    <group ref={group} rotation={[0.35, 0, 0]}>
      <Sphere args={[GLOBE_RADIUS, 64, 64]}>
        <meshBasicMaterial color={GLOBE_COLOR} wireframe transparent opacity={0.3} depthWrite={false} />
      </Sphere>
      {arcs.map(({ key, points, estimated }) => (
        <Line
          key={key}
          points={points}
          color={estimated ? ESTIMATED_COLOR : arcColor}
          lineWidth={2}
          transparent
          opacity={0.8}
          dashed={estimated}
          dashSize={0.08}
          gapSize={0.06}
        />
      ))}
      {geoCoordinates.map((point, index) => (
        <mesh key={`${index}:${point.ip}`} position={latLongToVector3(point.lat, point.lng, GLOBE_RADIUS)}>
          <sphereGeometry args={[MARKER_RADIUS, 12, 12]} />
          <meshBasicMaterial color={point.source === 'estimated' ? ESTIMATED_COLOR : arcColor} />
        </mesh>
      ))}
    </group>
  )
}

/**
 * Full-screen wireframe Earth with the delivery route drawn hop to hop: cyan, or red above
 * risk 75. Dashed white arcs touch a hop whose location is a hashed stand-in, not a lookup.
 */
export default function CyberCanvas() {
  return (
    <Canvas camera={{ position: [0, 0, 6], fov: 55 }} dpr={[1, 2]} gl={{ alpha: true }} fallback={null}>
      <ThreatGlobe />
    </Canvas>
  )
}
