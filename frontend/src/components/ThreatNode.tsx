import { Handle, type NodeProps, Position } from 'reactflow'
import { cn } from '@/lib/utils'
import type { NodeData, NodeKind } from '@/store/useThreatStore'

const KIND_LABEL: Record<NodeKind, string> = {
  SENDER: 'sender',
  RELAY_HOP: 'relay',
  RECEIVER: 'receiver',
  URL: 'url',
}

const KIND_BORDER: Record<NodeKind, string> = {
  SENDER: 'border-cyber-accent/80',
  RELAY_HOP: 'border-white/25',
  RECEIVER: 'border-cyber-accent/80',
  URL: 'border-white/25',
}

/** Handle ids, so edges can leave the sender from the right side they belong to. */
export const ROUTE_HANDLE = 'route'
export const LINK_HANDLE = 'link'

/**
 * Route nodes connect top to bottom. URLs receive from the left, and the sender links
 * to them from its right side, so a URL link can never look as if it left a relay.
 */
export function ThreatNode({ data }: NodeProps<NodeData>) {
  const isUrl = data.kind === 'URL'
  return (
    <div
      className={cn(
        'w-44 rounded-lg border bg-stone-900/85 px-3 py-2 font-mono text-[11px] text-white backdrop-blur',
        KIND_BORDER[data.kind],
      )}
    >
      <Handle type="target" position={isUrl ? Position.Left : Position.Top} className="!border-0 !bg-white/40" />
      <span className="block text-[9px] uppercase tracking-[0.25em] text-stone-400">{KIND_LABEL[data.kind]}</span>
      <span className="block [overflow-wrap:anywhere]">{data.label}</span>
      {!isUrl && data.kind !== 'RECEIVER' && (
        <Handle type="source" id={ROUTE_HANDLE} position={Position.Bottom} className="!border-0 !bg-white/40" />
      )}
      {data.kind === 'SENDER' && (
        <Handle type="source" id={LINK_HANDLE} position={Position.Right} className="!border-0 !bg-white/40" />
      )}
    </div>
  )
}
