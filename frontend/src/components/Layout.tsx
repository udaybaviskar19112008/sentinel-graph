import { lazy, type ReactNode, Suspense } from 'react'
import { SidebarNavigation } from '@/components/SidebarNavigation'

// three.js is the bulk of the bundle; let the panels become interactive first.
const CyberCanvas = lazy(() => import('@/components/CyberCanvas'))

/**
 * The persistent frame: the globe behind, the sidebar and the current page on top.
 *
 * It never unmounts while the user switches pages, so the WebGL context survives every
 * navigation. Glass lives on the individual panels rather than one full-screen sheet:
 * a single frosted pane over the whole page would blur the globe out of sight.
 */
export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="relative h-full w-full overflow-hidden text-white">
      <div className="absolute inset-0 z-0" aria-hidden="true">
        <Suspense fallback={null}>
          <CyberCanvas />
        </Suspense>
      </div>

      <div className="pointer-events-none absolute inset-0 z-10 flex">
        <SidebarNavigation />
        <main className="pointer-events-auto relative min-w-0 flex-1 p-4">{children}</main>
      </div>
    </div>
  )
}
