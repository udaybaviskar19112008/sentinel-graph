import type { Edge, Node } from 'reactflow'
import { LINK_HANDLE, ROUTE_HANDLE } from '@/components/ThreatNode'
import type { EdgeData, GraphLayout, NodeData } from '@/store/useThreatStore'

/** The custom node type registered by TopologyMap. */
export const THREAT_NODE_TYPE = 'threat'

const ROW_GAP = 110
const URL_COLUMN_X = 280

/**
 * Position the backend's delivery graph for React Flow: the route (sender, hops,
 * receiver) runs top to bottom, and the URLs stack in a column beside it. The
 * result is tall and narrow, so it stays clear of overlays in the pane's corners.
 */
export function toFlowElements(layout: GraphLayout): { nodes: Node<NodeData>[]; edges: Edge<EdgeData>[] } {
  let routeRow = 0
  let urlRow = 0
  const nodes = layout.nodes.map(
    (node): Node<NodeData> => ({
      id: node.id,
      type: THREAT_NODE_TYPE,
      position: node.kind === 'URL' ? { x: URL_COLUMN_X, y: urlRow++ * ROW_GAP } : { x: 0, y: routeRow++ * ROW_GAP },
      data: { label: node.label, kind: node.kind, score: node.score },
    }),
  )
  const kinds = new Map(layout.nodes.map((node) => [node.id, node.kind]))
  const edges = layout.edges.map((edge): Edge<EdgeData> => {
    const kind = kinds.get(edge.target) === 'URL' ? 'link' : 'route'
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      sourceHandle: kind === 'link' ? LINK_HANDLE : ROUTE_HANDLE,
      data: { kind },
    }
  })
  return { nodes, edges }
}
