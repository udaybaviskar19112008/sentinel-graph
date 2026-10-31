import { useEffect, useState } from 'react'
import ReactFlow, {
  Background,
  Controls,
  type Edge,
  MarkerType,
  type NodeTypes,
  type ReactFlowInstance,
  useEdgesState,
  useNodesState,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { ThreatNode } from '@/components/ThreatNode'
import { type EdgeRisk, edgeRisk } from '@/lib/edgeRisk'
import { THREAT_NODE_TYPE } from '@/lib/graphLayout'
import { type EdgeData, type NodeData, useThreatStore } from '@/store/useThreatStore'
import { cyberColors } from '@/theme/colors'

const EDGE_STROKE: Record<EdgeRisk, string> = {
  alert: cyberColors['cyber-alert'],
  safe: cyberColors['cyber-safe'],
  pending: cyberColors['cyber-accent'],
  unscored: 'rgba(255, 255, 255, 0.25)',
}

// Defined once at module level: React Flow re-creates its renderers if this object changes.
const NODE_TYPES: NodeTypes = { [THREAT_NODE_TYPE]: ThreatNode }

function styleEdge(edge: Edge<EdgeData>, risk: EdgeRisk): Edge<EdgeData> {
  const stroke = EDGE_STROKE[risk]
  return {
    ...edge,
    type: 'smoothstep',
    animated: risk === 'alert',
    style: { stroke, strokeWidth: risk === 'alert' ? 2.5 : 1.5, opacity: risk === 'pending' ? 0.6 : 1 },
    markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
  }
}

/** The email's delivery route and links, with edges coloured by their SHAP evidence. */
export function TopologyMap() {
  const graphNodes = useThreatStore((s) => s.graphNodes)
  const graphEdges = useThreatStore((s) => s.graphEdges)
  const contributions = useThreatStore((s) => s.details?.contributions ?? null)
  const visionRan = useThreatStore((s) => s.assessment?.vision_forensics != null)

  const [nodes, setNodes, onNodesChange] = useNodesState<NodeData>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<EdgeData>([])
  const [flow, setFlow] = useState<ReactFlowInstance<NodeData, EdgeData> | null>(null)

  useEffect(() => setNodes(graphNodes), [graphNodes, setNodes])

  useEffect(() => {
    // The sandbox detonates the first URL; only its link carries vision evidence.
    const detonated = visionRan ? (graphNodes.find((n) => n.data.kind === 'URL')?.id ?? null) : null
    setEdges(graphEdges.map((edge) => styleEdge(edge, edgeRisk(edge, contributions, detonated))))
  }, [graphEdges, graphNodes, contributions, visionRan, setEdges])

  useEffect(() => {
    if (!flow || graphNodes.length === 0) return
    const frame = requestAnimationFrame(() => flow.fitView({ padding: 0.25, duration: 400 }))
    return () => cancelAnimationFrame(frame)
  }, [flow, graphNodes])

  return (
    <div className="relative h-full w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onInit={setFlow}
        nodeTypes={NODE_TYPES}
        nodesConnectable={false}
        fitView
      >
        <Background color={cyberColors['cyber-grid']} gap={40} />
        <Controls showInteractive={false} />
      </ReactFlow>
      {graphNodes.length === 0 && (
        <p className="pointer-events-none absolute inset-0 grid place-items-center font-mono text-xs uppercase tracking-[0.3em] text-stone-500">
          Drop an email to map its delivery route
        </p>
      )}
    </div>
  )
}
