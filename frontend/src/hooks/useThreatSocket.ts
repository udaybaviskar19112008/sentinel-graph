import { useCallback, useEffect, useRef } from 'react'
import { openAnalysisStream } from '@/lib/threatStream'

/**
 * Owns at most one analysis socket for the calling component.
 *
 * Store actions are read with ``getState()`` rather than selected, so the host
 * component does not re-render on every telemetry event, and ``uploadAndAnalyze``
 * keeps one identity across renders.
 */
export function useThreatSocket(): { uploadAndAnalyze: (file: File) => void } {
  const socketRef = useRef<WebSocket | null>(null)

  const uploadAndAnalyze = useCallback((file: File) => {
    const previous = socketRef.current
    socketRef.current = null // retire it first so its close event cannot touch the new scan
    previous?.close()
    socketRef.current = openAnalysisStream(file, (socket) => socketRef.current === socket)
  }, [])

  useEffect(
    () => () => {
      const socket = socketRef.current
      socketRef.current = null
      socket?.close()
    },
    [],
  )

  return { uploadAndAnalyze }
}
