import type { Edge, Node } from 'reactflow'
import { create } from 'zustand'
import type { GeoPoint } from '@/lib/geoResolver'

// ---------------------------------------------------------------------------
// Backend contracts. These mirror src/schemas.py and the events streamed by
// src/core/orchestrator.py; change both sides together.
// ---------------------------------------------------------------------------

export type AuthStatus = 'pass' | 'fail' | 'neutral' | 'none' | 'permerror' | 'temperror'
export type VerdictLevel = 'BENIGN' | 'SUSPICIOUS' | 'PHISHING' | 'CRITICAL'
export type Subsystem = 'PROTOCOL_FORENSICS' | 'VISION_ENGINE' | 'TOPOLOGY_GNN' | 'COGNITIVE_SLM'
export type NodeKind = 'SENDER' | 'RELAY_HOP' | 'RECEIVER' | 'URL'

export interface HeaderForensics {
  spf: AuthStatus
  dkim: AuthStatus
  dmarc: AuthStatus
  arc: AuthStatus
  route_hop_count: number
  private_ip_leak: boolean
  timestamp_regression_flag: boolean
  display_name_spoof_risk: number // 1.0 display-name spoof, 0.5 brand only in the subject
  extracted_ips: string[] // connecting IP of each Received hop, sender side first
  impersonated_brand: string | null
  subject: string | null
  from_domain: string | null
  reply_to_domain: string | null
  return_path_domain: string | null
}

export interface VisionForensics {
  screenshot_hash: string
  visual_spoof_score: number
  detected_brand: string | null
  is_credential_harvester: boolean
}

export interface TopologyForensics {
  graph_nodes_count: number
  memae_reconstruction_loss: number
  is_zero_day_route: boolean
}

export interface ThreatAssessment {
  header_forensics: HeaderForensics
  vision_forensics: VisionForensics | null
  topology_forensics: TopologyForensics | null
  overall_risk: number // 0-100
  analyst_trace: string
}

/** One SHAP attribution; positive impact pushes toward phishing. */
export interface ShapContribution {
  feature_name: string
  impact: number
  percentage: number
  subsystem: Subsystem
}

/** Which engines are untrained stand-ins; their scores carry no meaning. */
export interface ModelStatus {
  vision_placeholder: boolean
  memae_placeholder: boolean
  zero_day_calibrated: boolean
  fusion_dummy: boolean
  slm_dummy: boolean
}

export interface GraphLayout {
  nodes: { id: string; kind: NodeKind; label: string; score: number }[]
  edges: { id: string; source: string; target: string }[]
}

interface EventBase {
  analysis_id: string
  elapsed_ms: number
}

export type TelemetryEvent = EventBase &
  (
    | { phase: 'RECEIVED'; bytes: number }
    | { phase: 'TIER_1'; status: string; findings: HeaderForensics; url_count: number }
    | { phase: 'VISION'; status: string; url?: string; captured?: boolean; findings?: VisionForensics }
    | { phase: 'TOPOLOGY'; status: string; nodes?: number; graph_layout?: GraphLayout; findings?: TopologyForensics }
    | { phase: 'SLM_REASONING'; token: string }
    | { phase: 'SLM_VERDICT'; verdict: VerdictLevel }
    | {
        phase: 'COMPLETE'
        assessment: ThreatAssessment
        verdict: VerdictLevel
        risk_probability: number
        contributions: ShapContribution[]
        model_status: ModelStatus
        graph_layout: GraphLayout
        scan_id: number | null // history record id; null if it was not saved
      }
  )

/** Sent instead of further telemetry when an analysis fails; the server then closes. */
export interface ErrorEvent {
  error: string
}

export type ServerMessage = TelemetryEvent | ErrorEvent

// ---------------------------------------------------------------------------
// React Flow payloads
// ---------------------------------------------------------------------------

export interface NodeData {
  label: string
  kind: NodeKind
  score: number
}

export interface EdgeData {
  kind: 'route' | 'link' // delivery hop, or sender-to-URL
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export type SocketStatus = 'disconnected' | 'connecting' | 'connected'

/** The rest of the COMPLETE event, kept beside the assessment itself. */
export interface AnalysisDetails {
  analysisId: string
  scanId: number | null
  verdict: VerdictLevel
  riskProbability: number
  contributions: ShapContribution[]
  modelStatus: ModelStatus
}

export const MAX_LOGS = 50

export interface ThreatState {
  socketStatus: SocketStatus
  currentPhase: string
  liveLogs: string[] // newest first
  slmStream: string
  assessment: ThreatAssessment | null
  details: AnalysisDetails | null
  graphNodes: Node<NodeData>[]
  graphEdges: Edge<EdgeData>[]
  geoCoordinates: GeoPoint[] // one per relay-hop IP, sender side first

  setStatus: (status: SocketStatus) => void
  setPhase: (phase: string) => void
  addLog: (log: string) => void
  appendSlmToken: (token: string) => void
  setGraph: (nodes: Node<NodeData>[], edges: Edge<EdgeData>[]) => void
  setAssessment: (
    data: ThreatAssessment,
    nodes: Node<NodeData>[],
    edges: Edge<EdgeData>[],
    details?: AnalysisDetails,
  ) => void
  setGeoCoordinates: (points: GeoPoint[]) => void
  resetState: () => void
}

const initialScan = {
  currentPhase: 'IDLE',
  liveLogs: [] as string[],
  slmStream: '',
  assessment: null,
  details: null,
  graphNodes: [] as Node<NodeData>[],
  graphEdges: [] as Edge<EdgeData>[],
  geoCoordinates: [] as GeoPoint[],
} satisfies Partial<ThreatState>

export const useThreatStore = create<ThreatState>()((set) => ({
  socketStatus: 'disconnected',
  ...initialScan,

  setStatus: (socketStatus) => set({ socketStatus }),
  setPhase: (currentPhase) => set({ currentPhase }),
  addLog: (log) => set((state) => ({ liveLogs: [log, ...state.liveLogs].slice(0, MAX_LOGS) })),
  appendSlmToken: (token) => set((state) => ({ slmStream: state.slmStream + token })),
  setGraph: (graphNodes, graphEdges) => set({ graphNodes, graphEdges }),
  setAssessment: (assessment, graphNodes, graphEdges, details) =>
    set({ assessment, graphNodes, graphEdges, details: details ?? null, currentPhase: 'COMPLETE' }),
  setGeoCoordinates: (geoCoordinates) => set({ geoCoordinates }),
  // Socket status is left alone: it tracks the connection, not the scan.
  resetState: () => set({ ...initialScan }),
}))
