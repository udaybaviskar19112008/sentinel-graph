import { useReducedMotion } from 'framer-motion'
import { useEffect, useMemo } from 'react'
import ReactFlow, {
  Background,
  Controls,
  type Edge,
  MarkerType,
  type NodeTypes,
  useEdgesState,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  useStore,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { Link } from 'react-router-dom'
import { ThreatNode } from '@/components/ThreatNode'
import { type EdgeRisk, edgeRisk } from '@/lib/edgeRisk'
import { THREAT_NODE_TYPE } from '@/lib/graphLayout'
import { cn } from '@/lib/utils'
import { type EdgeData, type NodeData, useThreatStore } from '@/store/useThreatStore'
import { palette } from '@/theme/colors'

// The edge colour is the sign of its subsystems' SHAP impact: the same polarity hues as the ML forensics chart.
const EDGE_STROKE: Record<EdgeRisk, string> = {
  alert: palette.negative,
  safe: palette.positive,
  pending: palette.muted,
  unscored: palette.control,
}

const EDGE_LABEL: Record<EdgeRisk, string> = {
  alert: 'Raised the risk',
  safe: 'Lowered the risk',
  pending: 'Awaiting evidence',
  unscored: 'Not scored',
}

const LEGEND_ORDER: EdgeRisk[] = ['alert', 'safe', 'pending', 'unscored']

// Defined once at module level: React Flow re-creates its renderers if this object changes.
const NODE_TYPES: NodeTypes = { [THREAT_NODE_TYPE]: ThreatNode }

function styleEdge(edge: Edge<EdgeData>, risk: EdgeRisk): Edge<EdgeData> {
  const stroke = EDGE_STROKE[risk]
  return {
    ...edge,
    type: 'smoothstep',
    style: { stroke, strokeWidth: risk === 'alert' ? 2.5 : 1.5, opacity: risk === 'pending' ? 0.6 : 1 },
    markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
  }
}

/**
 * Frame the graph once React Flow has measured every node, and again for each new graph.
 * Fitting straight after the nodes change used their unmeasured (zero) size, so the view
 * zoomed in too far and sat off-centre, with the last hop under the zoom controls.
 */
function FitOnLayout({ graph }: { graph: unknown }) {
  const measured = useNodesInitialized()
  const sized = useStore((s) => s.width > 0 && s.height > 0) // fitView is a no-op on an unmeasured pane
  const { fitView } = useReactFlow()
  const reduceMotion = useReducedMotion()
  useEffect(() => {
    if (measured && sized) fitView({ padding: 0.25, duration: reduceMotion ? 0 : 400 })
  }, [measured, sized, graph, fitView, reduceMotion])
  return null
}

/**
 * The email's delivery route and links, with edges coloured by their SHAP evidence. The
 * legend lists only the kinds of edge on screen. Before the first scan the canvas says
 * where the route comes from: a slot to drop the email into when `onBrowse` is given,
 * otherwise a pointer to the dashboard.
 */
export function TopologyMap({ className, onBrowse }: { className?: string; onBrowse?: () => void }) {
  const graphNodes = useThreatStore((s) => s.graphNodes)
  const graphEdges = useThreatStore((s) => s.graphEdges)
  const contributions = useThreatStore((s) => s.details?.contributions ?? null)
  const visionRan = useThreatStore((s) => s.assessment?.vision_forensics != null)
  const scanning = useThreatStore((s) => !['IDLE', 'COMPLETE', 'ERROR'].includes(s.currentPhase))

  const [nodes, setNodes, onNodesChange] = useNodesState<NodeData>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<EdgeData>([])

  const risks = useMemo(() => {
    // The sandbox detonates the first URL; only its link carries vision evidence.
    const detonated = visionRan ? (graphNodes.find((n) => n.data.kind === 'URL')?.id ?? null) : null
    return graphEdges.map((edge) => edgeRisk(edge, contributions, detonated))
  }, [graphEdges, graphNodes, contributions, visionRan])

  useEffect(() => setNodes(graphNodes), [graphNodes, setNodes])
  useEffect(
    () => setEdges(graphEdges.map((edge, index) => styleEdge(edge, risks[index]))),
    [graphEdges, risks, setEdges],
  )

  const legend = LEGEND_ORDER.filter((risk) => risks.includes(risk))

  return (
    <section className={cn('card flex flex-col p-0', className)} aria-labelledby="delivery-route-title">
      <header className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2 px-5 pt-5">
        <h2 id="delivery-route-title" className="card-title">
          Delivery route
        </h2>
        {legend.length > 0 && (
          <ul className="flex flex-wrap gap-x-4 gap-y-1 text-small text-muted" aria-label="Edge colours">
            {legend.map((risk) => (
              <li key={risk} className="flex items-center gap-1.5">
                <span className="h-0.5 w-4 rounded-full" style={{ backgroundColor: EDGE_STROKE[risk] }} aria-hidden="true" />
                {EDGE_LABEL[risk]}
              </li>
            ))}
          </ul>
        )}
      </header>
      <div className="relative min-h-0 flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={NODE_TYPES}
          nodesConnectable={false}
          fitView
        >
          <FitOnLayout graph={graphNodes} />
          <Background color={palette.control} gap={32} size={1} />
          <Controls showInteractive={false} position="bottom-left" />
        </ReactFlow>
        {graphNodes.length === 0 &&
          (scanning ? (
            <p className="pointer-events-none absolute inset-0 grid place-items-center text-body text-muted">
              Mapping the delivery route…
            </p>
          ) : (
            <div className="absolute inset-5 grid place-items-center rounded-md border border-dashed border-control bg-surface text-center">
              {onBrowse ? (
                <div>
                  <p className="text-body text-ink">Drop a raw email (.eml) here</p>
                  <p className="mt-1 text-body text-muted">
                    or{' '}
                    <button type="button" className="text-action" onClick={onBrowse}>
                      choose a file
                    </button>
                  </p>
                </div>
              ) : (
                <p className="text-body text-muted">
                  The delivery route is drawn here after a scan.{' '}
                  <Link to="/" className="text-action">
                    Analyse an email
                  </Link>
                </p>
              )}
            </div>
          ))}
      </div>
    </section>
  )
}
