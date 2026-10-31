import { AnimatePresence } from 'framer-motion'
import { BrowserRouter, Route, Routes, useLocation } from 'react-router-dom'
import { Layout } from '@/components/Layout'
import { PageTransition } from '@/components/PageTransition'
import { useThreatSocket } from '@/hooks/useThreatSocket'
import { LiveDetonation } from '@/pages/LiveDetonation'
import { ThreatHistory } from '@/pages/ThreatHistory'

/**
 * Keyed by path so AnimatePresence sees each page leave before the next one enters
 * (mode "wait": no two pages ever share the layout, so nothing snaps).
 */
function AnimatedRoutes({ onFile }: { onFile: (file: File) => void }) {
  const location = useLocation()
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route
          path="/"
          element={
            <PageTransition>
              <LiveDetonation onFile={onFile} />
            </PageTransition>
          }
        />
        <Route
          path="/history"
          element={
            <PageTransition>
              <ThreatHistory />
            </PageTransition>
          }
        />
      </Routes>
    </AnimatePresence>
  )
}

/**
 * The analysis socket lives here and the WebGL canvas in Layout, both outside <Routes>,
 * so neither is torn down when the user switches pages.
 */
export default function App() {
  const { uploadAndAnalyze } = useThreatSocket()

  return (
    <BrowserRouter>
      <Layout>
        <AnimatedRoutes onFile={uploadAndAnalyze} />
      </Layout>
    </BrowserRouter>
  )
}
