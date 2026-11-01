import { Handle, type NodeProps, Position } from 'reactflow'
import { cn } from '@/lib/utils'
import type { NodeData } from '@/store/useThreatStore'

const HANDLE = '!h-1.5 !w-1.5 !min-h-0 !min-w-0 !border-0 !bg-control'

/** Handle ids, so edges can leave the sender from the right side they belong to. */
export const ROUTE_HANDLE = 'route'
export const LINK_HANDLE = 'link'

/**
 * Route nodes connect top to bottom. URLs receive from the left, and the sender links
 * to them from its right side, so a URL link can never look as if it left a relay.
 * Route nodes already name themselves ("Sender", "Relay hop 2"); a link names its kind
 * over the URL, which is an identifier and so keeps the monospace. A selected node takes
 * the style's one selection mark, a 1px accent line on its bottom edge.
 */
export function ThreatNode({ data, selected }: NodeProps<NodeData>) {
  const isUrl = data.kind === 'URL'
  return (
    <div className={cn('w-44 rounded-md border border-transparent bg-raised px-3 py-2', selected && 'border-b-accent')}>
      <Handle type="target" position={isUrl ? Position.Left : Position.Top} className={HANDLE} />
      {isUrl ? (
        <>
          <span className="block text-small text-muted">Link</span>
          <span className="block font-mono text-small text-ink [overflow-wrap:anywhere]">{data.label}</span>
        </>
      ) : (
        <span className="block text-body text-ink">{data.label}</span>
      )}
      {!isUrl && data.kind !== 'RECEIVER' && (
        <Handle type="source" id={ROUTE_HANDLE} position={Position.Bottom} className={HANDLE} />
      )}
      {data.kind === 'SENDER' && <Handle type="source" id={LINK_HANDLE} position={Position.Right} className={HANDLE} />}
    </div>
  )
}
