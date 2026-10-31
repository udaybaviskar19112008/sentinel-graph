import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Layout } from '@/components/Layout'
import { useThreatSocket } from '@/hooks/useThreatSocket'
import { LiveDetonation } from '@/pages/LiveDetonation'
import { ThreatHistory } from '@/pages/ThreatHistory'

/**
 * The analysis socket lives here and the WebGL canvas in Layout, both outside <Routes>,
 * so neither is torn down when the user switches pages.
 */
export default function App() {
  const { uploadAndAnalyze } = useThreatSocket()

  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<LiveDetonation onFile={uploadAndAnalyze} />} />
          <Route path="/history" element={<ThreatHistory />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
