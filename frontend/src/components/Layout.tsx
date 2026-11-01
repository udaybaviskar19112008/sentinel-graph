import { type ReactNode, useCallback, useEffect, useRef } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useWindowFileDrop } from '@/components/Dropzone'
import { SidebarNavigation } from '@/components/SidebarNavigation'

/**
 * The persistent frame: the navigation, and the current screen in a canvas that scrolls
 * on its own. It never unmounts while the user switches screens; the analysis socket
 * lives above it in App, so a scan in flight survives every navigation.
 *
 * An email dropped anywhere, on any page, starts a scan and opens the dashboard to show it.
 */
export function Layout({ children, onFile }: { children: ReactNode; onFile: (file: File) => void }) {
  const navigate = useNavigate()
  const analyse = useCallback(
    (file: File) => {
      navigate('/')
      onFile(file)
    },
    [navigate, onFile],
  )
  const dragging = useWindowFileDrop(analyse)

  // The canvas outlives each page, so its scroll offset would carry from one page into the next.
  const { pathname } = useLocation()
  const canvasRef = useRef<HTMLElement>(null)
  useEffect(() => {
    canvasRef.current?.scrollTo({ top: 0 })
  }, [pathname])

  return (
    <div className="flex h-full w-full flex-col md:flex-row">
      <SidebarNavigation />
      {/* Vertical scrolling only: nothing on a page may push it sideways. */}
      <main ref={canvasRef} className="min-h-0 min-w-0 flex-1 overflow-y-auto overflow-x-hidden">
        {children}
      </main>
      {dragging && (
        <div
          className="pointer-events-none fixed inset-3 z-50 grid place-items-center rounded-md border border-dashed border-accent bg-ground/90 shadow-float"
          aria-hidden="true"
        >
          <p className="text-section text-ink">Drop the email to analyse it</p>
        </div>
      )}
    </div>
  )
}
