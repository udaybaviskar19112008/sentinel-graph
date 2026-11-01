import { type DragEvent, useRef, useState } from 'react'

const ACCEPT = '.eml,.txt,message/rfc822'

/** Only a drag that carries files lights the drop target; dragging a graph node never does. */
function carriesFiles(event: DragEvent): boolean {
  return event.dataTransfer.types.includes('Files')
}

/**
 * The ways an email gets in: a file picker behind the screen's primary button, and a drop
 * anywhere on the screen. Each new file starts a new scan. Render `fileInput` once.
 */
export function useEmailUpload(onFile: (file: File) => void) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  const take = (files: FileList | null) => {
    const file = files?.[0]
    if (file) onFile(file)
  }

  return {
    dragging,
    browse: () => inputRef.current?.click(),
    dropHandlers: {
      onDragOver: (event: DragEvent) => {
        if (!carriesFiles(event)) return
        event.preventDefault() // required for the drop event to fire
        event.dataTransfer.dropEffect = 'copy'
      },
      onDragEnter: (event: DragEvent) => {
        if (carriesFiles(event)) setDragging(true)
      },
      onDragLeave: (event: DragEvent) => {
        // Ignore leaving into a child element.
        if (!(event.relatedTarget instanceof Node && event.currentTarget.contains(event.relatedTarget))) {
          setDragging(false)
        }
      },
      onDrop: (event: DragEvent) => {
        if (!carriesFiles(event)) return
        event.preventDefault()
        setDragging(false)
        take(event.dataTransfer.files)
      },
    },
    fileInput: (
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPT}
        className="hidden"
        tabIndex={-1}
        aria-hidden="true"
        onChange={(event) => {
          take(event.target.files)
          event.target.value = '' // let the same file be chosen again
        }}
      />
    ),
  }
}
