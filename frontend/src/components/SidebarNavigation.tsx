import { Database, type LucideIcon, Radar } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'

const LINKS: { to: string; label: string; icon: LucideIcon }[] = [
  { to: '/', label: 'Live detonation', icon: Radar },
  { to: '/history', label: 'Threat history', icon: Database },
]

/**
 * Icon rail that widens to show labels on hover or keyboard focus.
 *
 * The rail reserves a fixed 4rem; the widening panel overlays the page instead of
 * pushing it, so the topology map does not re-layout every time the pointer passes.
 */
export function SidebarNavigation() {
  return (
    <div className="pointer-events-auto relative z-20 w-16 shrink-0">
      <nav
        aria-label="Primary"
        className="group absolute inset-y-0 left-0 flex w-16 flex-col gap-2 overflow-hidden border-r border-white/10 bg-cyber-panel px-3 py-4 backdrop-blur-md transition-all duration-200 focus-within:w-48 hover:w-48"
      >
        {LINKS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end
            className={({ isActive }) =>
              cn(
                'flex h-10 items-center gap-3 rounded-lg px-2 text-white/60 transition-colors hover:bg-white/5 hover:text-white focus-visible:outline focus-visible:outline-1 focus-visible:outline-cyber-accent',
                isActive && 'bg-cyber-accent/10 text-cyber-accent hover:text-cyber-accent',
              )
            }
          >
            <Icon className="h-5 w-5 shrink-0" aria-hidden="true" />
            <span className="whitespace-nowrap text-sm opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100">
              {label}
            </span>
          </NavLink>
        ))}
      </nav>
    </div>
  )
}
