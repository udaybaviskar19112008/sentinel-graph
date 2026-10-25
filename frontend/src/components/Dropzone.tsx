import { Upload } from 'lucide-react'
import { type DragEvent, type KeyboardEvent, useRef, useState } from 'react'
import { cn } from '@/lib/utils'
import { type SocketStatus, useThreatStore } from '@/store/useThreatStore'

const STATUS_DOT: Record<SocketStatus, string> = {
  disconnected: 'bg-white/30',
  connecting: 'bg-cyber-accent animate-pulse',
  connected: 'bg-cyber-safe animate-pulse',
}

/** Drop (or pick) one raw email; each new file starts a new scan. */
export function Dropzone({ onFile, className }: { onFile: (file: File) => void; className?: string }) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const socketStatus = useThreatStore((s) => s.socketStatus)
  const phase = useThreatStore((s) => s.currentPhase)

  const take = (files: FileList | null) => {
    const file = files?.[0]
    if (file) onFile(file)
  }
  const browse = () => inputRef.current?.click()

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label="Upload an email for analysis"
      onClick={browse}
      onKeyDown={(event: KeyboardEvent) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          browse()
        }
      }}
      onDragOver={(event: DragEvent) => {
        event.preventDefault() // required for the drop event to fire
        event.dataTransfer.dropEffect = 'copy'
      }}
      onDragEnter={() => setDragging(true)}
      onDragLeave={(event: DragEvent) => {
        // Ignore leaving into a child element.
        if (!(event.relatedTarget instanceof Node && event.currentTarget.contains(event.relatedTarget))) {
          setDragging(false)
        }
      }}
      onDrop={(event: DragEvent) => {
        event.preventDefault()
        setDragging(false)
        take(event.dataTransfer.files)
      }}
      className={cn(
        'glass-panel flex cursor-pointer flex-col items-center gap-2 border-dashed px-4 py-6 text-center outline-none transition-colors',
        'focus-visible:border-cyber-accent hover:border-cyber-accent/60',
        dragging && 'border-cyber-accent bg-cyber-accent/10',
        className,
      )}
    >
      <Upload className={cn('h-6 w-6', dragging ? 'text-cyber-accent' : 'text-white/60')} aria-hidden="true" />
      <p className="text-sm text-white/80">Drop a raw email (.eml) or click to browse</p>
      <p className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.25em] text-white/50">
        <span className={cn('h-1.5 w-1.5 rounded-full', STATUS_DOT[socketStatus])} aria-hidden="true" />
        {socketStatus} · {phase}
      </p>
      <input
        ref={inputRef}
        type="file"
        accept=".eml,.msg,.txt,message/rfc822"
        className="hidden"
        onClick={(event) => event.stopPropagation()}
        onChange={(event) => {
          take(event.target.files)
          event.target.value = '' // let the same file be chosen again
        }}
      />
    </div>
  )
}
