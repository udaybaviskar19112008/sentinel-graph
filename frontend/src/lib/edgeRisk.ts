import type { Edge } from 'reactflow'
import type { EdgeData, ShapContribution, Subsystem } from '@/store/useThreatStore'

/**
 * - pending: the graph is drawn but SHAP has not arrived yet
 * - unscored: no attributed evidence concerns this edge (e.g. a URL that was not detonated)
 * - alert / safe: the edge's subsystems pushed the risk up / did not
 */
export type EdgeRisk = 'pending' | 'unscored' | 'alert' | 'safe'

/** Delivery hops carry the protocol and route evidence; the sender-to-URL link carries what the sandbox saw. */
const EDGE_SUBSYSTEMS: Record<EdgeData['kind'], readonly Subsystem[]> = {
  route: ['PROTOCOL_FORENSICS', 'TOPOLOGY_GNN'],
  link: ['VISION_ENGINE'],
}

/**
 * Classify an edge by the signed SHAP impact of the subsystems it stands for.
 * ``detonatedUrlNode`` is the URL node the sandbox rendered, if it rendered one.
 */
export function edgeRisk(
  edge: Edge<EdgeData>,
  contributions: readonly ShapContribution[] | null,
  detonatedUrlNode: string | null,
): EdgeRisk {
  if (contributions === null) return 'pending'
  const kind = edge.data?.kind ?? 'route'
  if (kind === 'link' && edge.target !== detonatedUrlNode) return 'unscored'
  const subsystems = EDGE_SUBSYSTEMS[kind]
  const relevant = contributions.filter((c) => subsystems.includes(c.subsystem))
  if (relevant.length === 0) return 'unscored'
  return relevant.reduce((sum, c) => sum + c.impact, 0) > 0 ? 'alert' : 'safe'
}
