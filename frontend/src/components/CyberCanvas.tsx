import { Line, Sphere } from '@react-three/drei'
import { Canvas, useFrame } from '@react-three/fiber'
import { type ReactNode, useMemo, useRef } from 'react'
import * as THREE from 'three'
import type { GeoPoint } from '@/lib/geoResolver'
import { type SocketStatus, useThreatStore } from '@/store/useThreatStore'
import { palette, riskColor } from '@/theme/colors'

const GLOBE_RADIUS = 2
const ARC_SEGMENTS = 50
// Lowest an arc's apex may sit, as a multiple of the radius, however far apart its hops are.
const ARC_APEX = 1.1
const MARKER_RADIUS = 0.06
const TILT = 0.35 // radians: idle, the globe leans toward the viewer
const ESTIMATED_COLOR = palette.muted // a stand-in position, never a risk state
const GRATICULE_STEP = 30 // degrees between meridians and between parallels
const SAMPLE_STEP = 3 // degrees between the points of each graticule line

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

/** Meridians and parallels every GRATICULE_STEP degrees, as one set of line segments. */
function graticule(radius: number): THREE.BufferGeometry {
  const points: THREE.Vector3[] = []
  for (let lng = -180; lng < 180; lng += GRATICULE_STEP) {
    for (let lat = -90; lat < 90; lat += SAMPLE_STEP) {
      points.push(latLongToVector3(lat, lng, radius), latLongToVector3(lat + SAMPLE_STEP, lng, radius))
    }
  }
  for (let lat = -90 + GRATICULE_STEP; lat < 90; lat += GRATICULE_STEP) {
    for (let lng = -180; lng < 180; lng += SAMPLE_STEP) {
      points.push(latLongToVector3(lat, lng, radius), latLongToVector3(lat, lng + SAMPLE_STEP, radius))
    }
  }
  return new THREE.BufferGeometry().setFromPoints(points)
}

/**
 * The globe's contents: an opaque sphere (so the far side's lines stay hidden), the
 * graticule, route arcs and hop markers (the camera rig moves them).
 */
function ThreatGlobe() {
  const geoCoordinates = useThreatStore((s) => s.geoCoordinates)
  // The same bands as the verdict card's risk bar, so one score wears one hue on the screen.
  const arcColor = useThreatStore((s) => riskColor(s.assessment?.overall_risk ?? 0))
  const grid = useMemo(() => graticule(GLOBE_RADIUS * 1.002), [])

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
      <Sphere args={[GLOBE_RADIUS, 48, 48]}>
        <meshBasicMaterial color={palette.rule} />
      </Sphere>
      <lineSegments geometry={grid}>
        <lineBasicMaterial color={palette.control} />
      </lineSegments>
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
// The globe sits in a card about 200px tall: idle, it fills most of the height (fov 55).
const CAMERA_Z_IDLE = 5.6
const CAMERA_Z_FRAMED = 4.6 // pushed in to frame the route once the verdict and hop locations are in
const SMOOTHING = 2.5 // per second: exponential approach, the same at any frame rate
const MAX_PITCH = 1.2 // radians: never tip a polar route so far that the globe turns over

/** What the scene should be doing; the store has no "analysing" phase, so it is derived. */
function stanceOf(phase: string, socket: SocketStatus): Stance {
  if (phase === 'COMPLETE') return 'complete'
  if (phase === 'ERROR') return 'idle'
  // IDLE while the socket connects is the moment an upload starts.
  return phase === 'IDLE' && socket === 'disconnected' ? 'idle' : 'analysing'
}

/**
 * The yaw (spin) and pitch (tilt) that turn the route's centre toward the camera on +z:
 * yaw brings its meridian round to face the camera, then pitch lifts its latitude to the
 * middle of the view, so a northern route is not framed half off the top of the card.
 */
function facingAngles(points: GeoPoint[]): { yaw: number; pitch: number } {
  const centre = points
    .reduce((sum, point) => sum.add(latLongToVector3(point.lat, point.lng, GLOBE_RADIUS)), new THREE.Vector3())
    .divideScalar(points.length)
  // Hops on opposite sides cancel out; face the first hop instead.
  const target = centre.lengthSq() > 1e-6 ? centre : latLongToVector3(points[0].lat, points[0].lng, GLOBE_RADIUS)
  const latitude = Math.asin(THREE.MathUtils.clamp(target.y / target.length(), -1, 1))
  return {
    yaw: Math.atan2(-target.x, target.z),
    pitch: THREE.MathUtils.clamp(latitude, -MAX_PITCH, MAX_PITCH),
  }
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
 *
 * The tilt sits outside the spin, so the globe turns about its own tilted axis instead of
 * wobbling; framing a route moves both.
 */
function CameraRig({ children }: { children: ReactNode }) {
  const tilting = useRef<THREE.Group>(null)
  const spinning = useRef<THREE.Group>(null)
  const spin = useRef(SPIN.idle)
  const reducedMotion = useMemo(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches, [])

  useFrame((state, delta) => {
    const { currentPhase, socketStatus, geoCoordinates } = useThreatStore.getState()
    const stance = stanceOf(currentPhase, socketStatus)
    const framing = stance === 'complete' && geoCoordinates.length > 0
    const facing = framing ? facingAngles(geoCoordinates) : null

    spin.current = THREE.MathUtils.damp(spin.current, SPIN[stance] * (reducedMotion ? 0.2 : 1), SMOOTHING, delta)
    const group = spinning.current
    if (group) {
      if (facing) {
        group.rotation.y = reducedMotion ? facing.yaw : dampAngle(group.rotation.y, facing.yaw, delta)
      } else {
        group.rotation.y += spin.current * delta
      }
    }
    const tilt = tilting.current
    if (tilt) {
      const pitch = facing ? facing.pitch : TILT
      tilt.rotation.x = reducedMotion ? pitch : THREE.MathUtils.damp(tilt.rotation.x, pitch, SMOOTHING, delta)
    }

    const z = framing ? CAMERA_Z_FRAMED : CAMERA_Z_IDLE
    state.camera.position.z = reducedMotion ? z : THREE.MathUtils.damp(state.camera.position.z, z, SMOOTHING, delta)
  })
  return (
    <group ref={tilting} rotation={[TILT, 0, 0]}>
      <group ref={spinning}>{children}</group>
    </group>
  )
}

/**
 * A graticule Earth with the delivery route drawn hop to hop, in the status hue of the
 * overall risk. Dashed grey arcs touch a hop whose location is a hashed stand-in, not a
 * lookup. It fills its parent, which sets the size.
 */
export default function CyberCanvas() {
  return (
    <Canvas camera={{ position: [0, 0, CAMERA_Z_IDLE], fov: 55 }} dpr={[1, 2]} gl={{ alpha: true }} fallback={null}>
      <CameraRig>
        <ThreatGlobe />
      </CameraRig>
    </Canvas>
  )
}
