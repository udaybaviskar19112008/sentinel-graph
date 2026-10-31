import { Line, Sphere } from '@react-three/drei'
import { Canvas, useFrame } from '@react-three/fiber'
import { type ReactNode, useMemo, useRef } from 'react'
import * as THREE from 'three'
import type { GeoPoint } from '@/lib/geoResolver'
import { type SocketStatus, useThreatStore } from '@/store/useThreatStore'
import { cyberColors } from '@/theme/colors'

const GLOBE_RADIUS = 2
const ARC_SEGMENTS = 50
// Lowest an arc's apex may sit, as a multiple of the radius, however far apart its hops are.
const ARC_APEX = 1.1
const MARKER_RADIUS = 0.035
const ALERT_RISK = 50 // the classifier's own decision threshold: probability 0.5
const TILT = 0.35 // radians: the globe leans toward the viewer
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

/** The globe's contents: sphere, route arcs and hop markers (the camera rig moves them). */
function ThreatGlobe() {
  const geoCoordinates = useThreatStore((s) => s.geoCoordinates)
  const alert = useThreatStore((s) => (s.assessment?.overall_risk ?? 0) > ALERT_RISK)
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

  return (
    <>
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
    </>
  )
}

type Stance = 'idle' | 'analysing' | 'complete'

// Spin in radians per second. An upload spins the globe up tenfold; the verdict settles it.
// (The brief's 0.05 rad/s "faster" spin was slower than the existing 0.06 idle, so the intent sets these.)
const SPIN: Record<Stance, number> = { idle: 0.06, analysing: 0.6, complete: 0.06 }
const CAMERA_Z_IDLE = 12
const CAMERA_Z_FRAMED = 7 // pushed in to frame the route once the verdict and hop locations are in
const SMOOTHING = 2.5 // per second: exponential approach, the same at any frame rate

/** What the scene should be doing; the store has no "analysing" phase, so it is derived. */
function stanceOf(phase: string, socket: SocketStatus): Stance {
  if (phase === 'COMPLETE') return 'complete'
  if (phase === 'ERROR') return 'idle'
  // IDLE while the socket connects is the moment an upload starts.
  return phase === 'IDLE' && socket === 'disconnected' ? 'idle' : 'analysing'
}

/** The globe yaw that turns the route's centre toward the camera on +z. */
function facingYaw(points: GeoPoint[]): number {
  const centre = points
    .reduce((sum, point) => sum.add(latLongToVector3(point.lat, point.lng, GLOBE_RADIUS)), new THREE.Vector3())
    .divideScalar(points.length)
  // Hops on opposite sides cancel out; face the first hop instead.
  const target = centre.lengthSq() > 1e-6 ? centre : latLongToVector3(points[0].lat, points[0].lng, GLOBE_RADIUS)
  return Math.atan2(-target.x, target.z)
}

/** Damp an angle toward a target the shortest way round. */
function dampAngle(current: number, target: number, delta: number): number {
  const difference = THREE.MathUtils.euclideanModulo(target - current + Math.PI, Math.PI * 2) - Math.PI
  return current + difference * (1 - Math.exp(-SMOOTHING * delta))
}

/**
 * State-driven cinematography: the globe spins up while an email is analysed; when the
 * verdict and hop locations arrive the camera pushes in and the route turns to face it;
 * idle, both settle back. It reads the store inside the frame loop, so phase changes never
 * re-render React. Reduced motion: a slow spin and an instant camera.
 */
function CameraRig({ children }: { children: ReactNode }) {
  const spinning = useRef<THREE.Group>(null)
  const spin = useRef(SPIN.idle)
  const reducedMotion = useMemo(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches, [])

  useFrame((state, delta) => {
    const { currentPhase, socketStatus, geoCoordinates } = useThreatStore.getState()
    const stance = stanceOf(currentPhase, socketStatus)
    const framing = stance === 'complete' && geoCoordinates.length > 0

    spin.current = THREE.MathUtils.damp(spin.current, SPIN[stance] * (reducedMotion ? 0.2 : 1), SMOOTHING, delta)
    const group = spinning.current
    if (group) {
      if (framing) {
        const yaw = facingYaw(geoCoordinates)
        group.rotation.y = reducedMotion ? yaw : dampAngle(group.rotation.y, yaw, delta)
      } else {
        group.rotation.y += spin.current * delta
      }
    }

    const z = framing ? CAMERA_Z_FRAMED : CAMERA_Z_IDLE
    state.camera.position.z = reducedMotion ? z : THREE.MathUtils.damp(state.camera.position.z, z, SMOOTHING, delta)
  })
  return <group ref={spinning}>{children}</group>
}

/**
 * Full-screen wireframe Earth with the delivery route drawn hop to hop: rose above risk 50,
 * emerald below. Dashed stone arcs touch a hop whose location is a hashed stand-in, not a lookup.
 */
export default function CyberCanvas() {
  return (
    <Canvas camera={{ position: [0, 0, CAMERA_Z_IDLE], fov: 55 }} dpr={[1, 2]} gl={{ alpha: true }} fallback={null}>
      {/* Tilt outside the spin, so the globe turns about its own tilted axis instead of wobbling. */}
      <group rotation={[TILT, 0, 0]}>
        <CameraRig>
          <ThreatGlobe />
        </CameraRig>
      </group>
    </Canvas>
  )
}
