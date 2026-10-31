import { BrainCircuit, Database, FileDown, type LucideIcon, Radar } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'

const LINKS: { to: string; label: string; icon: LucideIcon }[] = [
  { to: '/', label: 'Live scan', icon: Radar },
  { to: '/history', label: 'History', icon: Database },
  { to: '/ml-forensics', label: 'ML engine', icon: BrainCircuit },
  { to: '/reports', label: 'Export', icon: FileDown },
]

/**
 * Icon rail that widens to show labels on hover or keyboard focus.
 *
 * The rail reserves a fixed 4rem; the widening panel overlays the page instead of
 * pushing it, so the topology map does not re-layout every time the pointer passes.
 * Every link carries a 4px right border (transparent until active), so the active
 * marker never shifts a link's content. Focus shows as a ring: cn()'s class merging
 * drops a bare `outline` next to `outline-1`, which left keyboard focus invisible.
 */
export function SidebarNavigation() {
  return (
    <div className="pointer-events-auto relative z-20 w-16 shrink-0">
      <nav
        aria-label="Primary"
        className="group absolute inset-y-0 left-0 flex w-16 flex-col gap-2 overflow-hidden border-r border-glass-border bg-glass-base px-3 py-4 shadow-2xl backdrop-blur-2xl transition-all duration-200 focus-within:w-48 hover:w-48"
      >
        {LINKS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end
            className={({ isActive }) =>
              cn(
                'flex h-10 cursor-pointer items-center gap-3 rounded-lg border-r-4 border-transparent px-2 text-stone-400 transition-all duration-200 hover:translate-x-1 hover:bg-white/5 hover:text-white focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent',
                isActive && 'border-rose-500 bg-white/10 text-white hover:bg-white/10',
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
