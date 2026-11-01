import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from '@/components/Layout'
import { useThreatSocket } from '@/hooks/useThreatSocket'
import { LiveDetonation } from '@/pages/LiveDetonation'
import { MLAnalysis } from '@/pages/MLAnalysis'
import { Reports } from '@/pages/Reports'
import { ThreatHistory } from '@/pages/ThreatHistory'

/**
 * The analysis socket lives here, outside <Routes>, so leaving the live view mid-scan
 * never closes it; the store keeps the results for when the user returns. Screens
 * switch instantly: on a working screen nothing performs an entrance.
 */
export default function App() {
  const { uploadAndAnalyze } = useThreatSocket()

  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<LiveDetonation onFile={uploadAndAnalyze} />} />
          {/* The live view stays at "/" (as the docs say); /live is an alias. */}
          <Route path="/live" element={<Navigate to="/" replace />} />
          <Route path="/history" element={<ThreatHistory />} />
          <Route path="/ml-forensics" element={<MLAnalysis />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
