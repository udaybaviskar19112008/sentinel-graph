import { AnimatePresence } from 'framer-motion'
import type { ReactNode } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Layout } from '@/components/Layout'
import { PageTransition } from '@/components/PageTransition'
import { useThreatSocket } from '@/hooks/useThreatSocket'
import { LiveDetonation } from '@/pages/LiveDetonation'
import { MLAnalysis } from '@/pages/MLAnalysis'
import { Reports } from '@/pages/Reports'
import { ThreatHistory } from '@/pages/ThreatHistory'

function page(content: ReactNode) {
  return <PageTransition>{content}</PageTransition>
}

/**
 * Keyed by path so AnimatePresence sees each page leave before the next one enters
 * (mode "wait": no two pages ever share the layout, so nothing snaps).
 */
function AnimatedRoutes({ onFile }: { onFile: (file: File) => void }) {
  const location = useLocation()
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={page(<LiveDetonation onFile={onFile} />)} />
        {/* The live view stays at "/" (as the docs say); /live is an alias. */}
        <Route path="/live" element={<Navigate to="/" replace />} />
        <Route path="/history" element={page(<ThreatHistory />)} />
        <Route path="/ml-forensics" element={page(<MLAnalysis />)} />
        <Route path="/reports" element={page(<Reports />)} />
        <Route path="*" element={<Navigate to="/" replace />} />
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
