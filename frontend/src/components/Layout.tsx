import type { ReactNode } from 'react'
import { SidebarNavigation } from '@/components/SidebarNavigation'

/**
 * The persistent frame: the navigation, and the current screen in a canvas that scrolls
 * on its own. It never unmounts while the user switches screens; the analysis socket
 * lives above it in App, so a scan in flight survives every navigation.
 */
export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full w-full flex-col md:flex-row">
      <SidebarNavigation />
      <main className="min-h-0 min-w-0 flex-1 overflow-y-auto">{children}</main>
    </div>
  )
}
