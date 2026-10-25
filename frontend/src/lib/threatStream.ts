import { toFlowElements } from '@/lib/graphLayout'
import { type ServerMessage, type TelemetryEvent, useThreatStore } from '@/store/useThreatStore'

export const STREAM_PATH = '/ws/api/v1/stream-analysis'
/** The backend's MAX_EMAIL_BYTES default; larger files would be refused after upload anyway. */
export const MAX_EMAIL_BYTES = 16 * 1024 * 1024

/** Absolute socket URL on the page's own host, so the Vite proxy (or a reverse proxy) routes it. */
export function analysisSocketUrl(location: Location = window.location): string {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${location.host}${STREAM_PATH}`
}

/** A server frame as a typed message, or null if it is not one we understand. */
export function parseServerMessage(raw: unknown): ServerMessage | null {
  if (typeof raw !== 'string') return null
  try {
    const value: unknown = JSON.parse(raw)
    if (typeof value !== 'object' || value === null) return null
    if (typeof (value as { error?: unknown }).error === 'string') return value as ServerMessage
    if (typeof (value as { phase?: unknown }).phase === 'string') return value as ServerMessage
  } catch {
    // fall through: not JSON
  }
  return null
}

function describe(event: TelemetryEvent): string {
  const at = `+${Math.round(event.elapsed_ms)}ms`
  switch (event.phase) {
    case 'RECEIVED':
      return `${at} RECEIVED ${event.bytes} bytes`
    case 'SLM_VERDICT':
      return `${at} SLM_VERDICT ${event.verdict}`
    case 'COMPLETE':
      return `${at} COMPLETE risk ${event.assessment.overall_risk}/100, verdict ${event.verdict}`
    case 'VISION': {
      const extra = event.captured === undefined ? (event.url ?? '') : `captured=${event.captured}`
      return `${at} VISION ${event.status}${extra ? ` (${extra})` : ''}`
    }
    case 'TOPOLOGY':
      return `${at} TOPOLOGY ${event.status}${event.nodes === undefined ? '' : ` (${event.nodes} nodes)`}`
    case 'TIER_1':
      return `${at} TIER_1 ${event.status} (${event.url_count} URLs)`
    case 'SLM_REASONING':
      return `${at} SLM_REASONING`
  }
}

/** Fold one server message into the store. */
export function applyServerMessage(message: ServerMessage): void {
  const store = useThreatStore.getState()
  if ('error' in message) {
    store.setPhase('ERROR')
    store.addLog(`ERROR ${message.error}`)
    return
  }
  switch (message.phase) {
    case 'SLM_REASONING':
      store.appendSlmToken(message.token)
      return
    case 'COMPLETE': {
      const { nodes, edges } = toFlowElements(message.graph_layout)
      store.setAssessment(message.assessment, nodes, edges, {
        analysisId: message.analysis_id,
        scanId: message.scan_id,
        verdict: message.verdict,
        riskProbability: message.risk_probability,
        contributions: message.contributions,
        modelStatus: message.model_status,
      })
      store.addLog(describe(message))
      return
    }
    case 'TOPOLOGY':
      if (message.graph_layout) {
        const { nodes, edges } = toFlowElements(message.graph_layout)
        store.setGraph(nodes, edges)
      }
      break
  }
  store.setPhase(message.phase)
  store.addLog(describe(message))
}

/**
 * Open a socket, upload ``file`` once it connects, and stream telemetry into the store.
 *
 * ``isCurrent`` lets the caller retire a socket: handlers of a superseded scan go quiet
 * instead of writing over the new one. Returns null when the file is refused up front.
 */
export function openAnalysisStream(
  file: File,
  isCurrent: (socket: WebSocket) => boolean = () => true,
): WebSocket | null {
  const store = useThreatStore.getState()
  store.resetState()
  if (file.size > MAX_EMAIL_BYTES) {
    store.setStatus('disconnected')
    store.setPhase('ERROR')
    store.addLog(`ERROR ${file.name} is ${file.size} bytes; the limit is ${MAX_EMAIL_BYTES}`)
    return null
  }
  store.setStatus('connecting')

  const socket = new WebSocket(analysisSocketUrl())
  socket.onopen = async () => {
    if (!isCurrent(socket)) return
    store.setStatus('connected')
    const buffer = await file.arrayBuffer()
    if (isCurrent(socket) && socket.readyState === WebSocket.OPEN) socket.send(buffer)
  }
  socket.onmessage = (event: MessageEvent) => {
    if (!isCurrent(socket)) return
    const message = parseServerMessage(event.data)
    if (message) applyServerMessage(message)
  }
  socket.onerror = () => {
    if (!isCurrent(socket)) return
    store.setStatus('disconnected')
  }
  socket.onclose = (event: CloseEvent) => {
    if (!isCurrent(socket)) return
    store.setStatus('disconnected')
    if (event.code !== 1000 && useThreatStore.getState().currentPhase !== 'ERROR') {
      store.addLog(`ERROR stream closed (code ${event.code}) before the analysis finished`)
    }
  }
  return socket
}
