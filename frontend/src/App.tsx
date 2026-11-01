import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from '@/components/Layout'
import { useThreatSocket } from '@/hooks/useThreatSocket'
import { Dashboard } from '@/pages/Dashboard'
import { Forensics } from '@/pages/Forensics'
import { Reports } from '@/pages/Reports'

/**
 * Three workspaces: the dashboard (upload, verdict, globe), forensics (every piece of
 * evidence) and reports (exports and the scan history).
 *
 * The analysis socket lives here, outside <Routes>, so leaving the dashboard mid-scan
 * never closes it; the store keeps the results for when the user returns. Screens
 * switch instantly: on a working screen nothing performs an entrance.
 */
export default function App() {
  const { uploadAndAnalyze } = useThreatSocket()

  return (
    <BrowserRouter>
      <Layout onFile={uploadAndAnalyze}>
        <Routes>
          <Route path="/" element={<Dashboard onFile={uploadAndAnalyze} />} />
          <Route path="/forensics" element={<Forensics />} />
          <Route path="/reports" element={<Reports />} />
          {/* Earlier addresses, kept so bookmarks and the docs still land somewhere sensible. */}
          <Route path="/live" element={<Navigate to="/" replace />} />
          <Route path="/ml-forensics" element={<Navigate to="/forensics" replace />} />
          <Route path="/history" element={<Navigate to="/reports" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
