import { useEffect, useRef, useState } from 'react'

const ACCEPT = '.eml,.txt,message/rfc822'

/** The file picker behind the upload panel. Each new file starts a new scan. Render `fileInput` once. */
export function useEmailPicker(onFile: (file: File) => void) {
  const inputRef = useRef<HTMLInputElement>(null)
  return {
    browse: () => inputRef.current?.click(),
    fileInput: (
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPT}
        className="hidden"
        tabIndex={-1}
        aria-hidden="true"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) onFile(file)
          event.target.value = '' // let the same file be chosen again
        }}
      />
    ),
  }
}

function carriesFiles(event: DragEvent): boolean {
  return event.dataTransfer?.types.includes('Files') ?? false
}

/**
 * Accept an email dropped anywhere in the window, on any page. Only a drag that carries
 * files counts, so dragging a graph node or selected text never lights the overlay, and a
 * dropped file never makes the browser navigate away to display it. Enter and leave are
 * counted, because each child element the pointer crosses fires its own pair.
 * Returns whether a file is being dragged over the window.
 */
export function useWindowFileDrop(onFile: (file: File) => void): boolean {
  const [dragging, setDragging] = useState(false)

  useEffect(() => {
    let depth = 0
    const enter = (event: DragEvent) => {
      if (!carriesFiles(event)) return
      depth += 1
      setDragging(true)
    }
    const leave = (event: DragEvent) => {
      if (!carriesFiles(event)) return
      depth = Math.max(0, depth - 1)
      if (depth === 0) setDragging(false)
    }
    const over = (event: DragEvent) => {
      if (!carriesFiles(event)) return
      event.preventDefault() // required for the drop event to fire
      if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy'
    }
    const drop = (event: DragEvent) => {
      if (!carriesFiles(event)) return
      event.preventDefault()
      depth = 0
      setDragging(false)
      const file = event.dataTransfer?.files[0]
      if (file) onFile(file)
    }
    window.addEventListener('dragenter', enter)
    window.addEventListener('dragleave', leave)
    window.addEventListener('dragover', over)
    window.addEventListener('drop', drop)
    return () => {
      window.removeEventListener('dragenter', enter)
      window.removeEventListener('dragleave', leave)
      window.removeEventListener('dragover', over)
      window.removeEventListener('drop', drop)
    }
  }, [onFile])

  return dragging
}
