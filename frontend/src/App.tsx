import { lazy, Suspense } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { SidebarNavigation } from '@/components/SidebarNavigation'
import { useThreatSocket } from '@/hooks/useThreatSocket'
import { LiveDetonation } from '@/pages/LiveDetonation'
import { ThreatHistory } from '@/pages/ThreatHistory'

// three.js is the bulk of the bundle; let the panels become interactive first.
const CyberCanvas = lazy(() => import('@/components/CyberCanvas'))

/**
 * Persistent shell: the WebGL canvas and the analysis socket live here, outside
 * <Routes>, so neither is torn down when the user switches pages.
 */
export default function App() {
  const { uploadAndAnalyze } = useThreatSocket()

  return (
    <BrowserRouter>
      <div className="relative h-screen w-screen overflow-hidden bg-cyber-bg bg-cyber-grid text-white">
        <div className="absolute inset-0 z-0" aria-hidden="true">
          <Suspense fallback={null}>
            <CyberCanvas />
          </Suspense>
        </div>

        <div className="pointer-events-none absolute inset-0 z-10 flex">
          <SidebarNavigation />
          <main className="pointer-events-auto relative min-w-0 flex-1 p-4">
            <Routes>
              <Route path="/" element={<LiveDetonation onFile={uploadAndAnalyze} />} />
              <Route path="/history" element={<ThreatHistory />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  )
}
