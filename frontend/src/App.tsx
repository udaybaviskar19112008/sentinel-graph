import { lazy, Suspense } from 'react'
import { Dropzone } from '@/components/Dropzone'
import { LiveTerminal } from '@/components/LiveTerminal'
import { RiskGauge } from '@/components/RiskGauge'
import { TopologyMap } from '@/components/TopologyMap'
import { useThreatSocket } from '@/hooks/useThreatSocket'

// three.js is the bulk of the bundle; let the panels become interactive first.
const CyberCanvas = lazy(() => import('@/components/CyberCanvas'))

export default function App() {
  const { uploadAndAnalyze } = useThreatSocket()

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-cyber-bg bg-cyber-grid text-white">
      <div className="absolute inset-0 z-0" aria-hidden="true">
        <Suspense fallback={null}>
          <CyberCanvas />
        </Suspense>
      </div>

      <main className="pointer-events-none absolute inset-0 z-10 grid h-full w-full grid-cols-12 grid-rows-1 gap-4 p-4">
        <aside className="col-span-3 flex min-h-0 flex-col gap-4">
          <Dropzone onFile={uploadAndAnalyze} className="pointer-events-auto" />
          <div className="pointer-events-auto min-h-0 flex-1">
            <LiveTerminal />
          </div>
        </aside>

        <section className="pointer-events-auto relative col-span-9 min-h-0 overflow-hidden rounded-xl">
          <TopologyMap />
          <RiskGauge className="absolute right-4 top-4" />
        </section>
      </main>
    </div>
  )
}
