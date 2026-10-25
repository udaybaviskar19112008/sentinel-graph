import { Canvas, useFrame } from '@react-three/fiber'
import { useMemo, useRef } from 'react'
import * as THREE from 'three'
import { useThreatStore } from '@/store/useThreatStore'
import { cyberColors } from '@/theme/colors'

const PARTICLES = 5000
const RADIUS = 2.4
const ALERT_RISK = 75
const SPIN_RADIANS_PER_SECOND = 0.05
const ALERT_COLOR = new THREE.Color(cyberColors['cyber-alert'])
const SAFE_COLOR = new THREE.Color(cyberColors['cyber-safe'])

/** Points on a thin spherical shell, uniform over the surface. */
function sphericalShell(count: number, radius: number): Float32Array {
  const positions = new Float32Array(count * 3)
  for (let i = 0; i < count; i++) {
    const theta = Math.random() * Math.PI * 2
    const phi = Math.acos(2 * Math.random() - 1) // acos keeps the poles from bunching
    const r = radius * (0.92 + 0.08 * Math.random())
    positions[i * 3] = r * Math.sin(phi) * Math.cos(theta)
    positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta)
    positions[i * 3 + 2] = r * Math.cos(phi)
  }
  return positions
}

function ParticleSystem() {
  const points = useRef<THREE.Points>(null)
  const material = useRef<THREE.PointsMaterial>(null)
  const positions = useMemo(() => sphericalShell(PARTICLES, RADIUS), [])
  const reducedMotion = useMemo(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches, [])
  const alert = useThreatStore((s) => (s.assessment?.overall_risk ?? 0) > ALERT_RISK)

  useFrame((_state, delta) => {
    if (!points.current || !material.current) return
    const spin = SPIN_RADIANS_PER_SECOND * (alert ? 3 : 1) * (reducedMotion ? 0.2 : 1)
    points.current.rotation.y += delta * spin
    points.current.rotation.x += delta * spin * 0.3
    // Exponential ease toward the target colour: frame-rate independent, settles in about a second.
    material.current.color.lerp(alert ? ALERT_COLOR : SAFE_COLOR, 1 - Math.exp(-delta * 3))
  })

  return (
    <points ref={points}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        ref={material}
        color={SAFE_COLOR}
        size={0.02}
        sizeAttenuation
        transparent
        opacity={0.75}
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  )
}

/** Full-screen particle sphere: green while calm, red and spinning faster above risk 75. */
export default function CyberCanvas() {
  return (
    <Canvas camera={{ position: [0, 0, 6], fov: 55 }} dpr={[1, 2]} gl={{ alpha: true }} fallback={null}>
      <ParticleSystem />
    </Canvas>
  )
}
