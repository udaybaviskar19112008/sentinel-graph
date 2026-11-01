import { BrainCircuit, Database, FileDown, type LucideIcon, Radar } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { PRODUCT_NAME } from '@/components/Screen'
import { cn } from '@/lib/utils'

const LINKS: { to: string; label: string; icon: LucideIcon }[] = [
  { to: '/', label: 'Live scan', icon: Radar },
  { to: '/history', label: 'History', icon: Database },
  { to: '/ml-forensics', label: 'ML engine', icon: BrainCircuit },
  { to: '/reports', label: 'Export', icon: FileDown },
]

/** The product's mark: its own delivery graph, a sender over two route hops with a link off to the side. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" aria-hidden="true">
      <path d="M7 5v14M7 5l10 5" className="stroke-accent" strokeWidth="1.75" strokeLinecap="round" />
      <circle cx="7" cy="5" r="2.5" className="fill-accent" />
      <circle cx="7" cy="12" r="2.25" className="fill-accent" />
      <circle cx="7" cy="19" r="2.25" className="fill-accent" />
      <circle cx="17" cy="10" r="2.25" className="fill-surface stroke-accent" strokeWidth="1.75" />
    </svg>
  )
}

/**
 * An icon rail on the page ground from 768px up; below that, a bottom bar with labels.
 *
 * The move of the dealt style: the active item is marked only by a 1px accent line on the
 * nearest existing edge (the rail's border, or the bar's top edge) and its icon turning
 * white. Every icon carries an accessible name and a tooltip. Focus shows as a ring:
 * cn()'s class merging drops a bare `outline`, which once left keyboard focus invisible.
 */
export function SidebarNavigation() {
  return (
    <nav
      aria-label="Primary"
      className="order-last flex h-16 shrink-0 border-t border-line bg-ground md:order-first md:h-full md:w-14 md:flex-col md:items-stretch md:border-r md:border-t-0 md:py-4"
    >
      <span className="hidden h-12 items-center justify-center md:mb-4 md:flex" title={PRODUCT_NAME}>
        <BrandMark className="h-6 w-6" />
        <span className="sr-only">{PRODUCT_NAME}</span>
      </span>
      {LINKS.map(({ to, label, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          end
          aria-label={label}
          className={({ isActive }) =>
            cn(
              'group relative flex flex-1 flex-col items-center justify-center gap-1 text-muted transition-colors hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent md:h-11 md:flex-none',
              isActive && 'text-ink',
            )
          }
        >
          {({ isActive }) => (
            <>
              <Icon className="h-[18px] w-[18px]" strokeWidth={1.5} aria-hidden="true" />
              <span className="text-small md:hidden">{label}</span>
              {isActive && (
                <span
                  className="absolute left-1/2 top-[-1px] h-px w-10 -translate-x-1/2 bg-accent md:left-auto md:right-[-1px] md:top-1/2 md:h-5 md:w-px md:-translate-y-1/2 md:translate-x-0"
                  aria-hidden="true"
                />
              )}
              <span
                className="pointer-events-none absolute left-full top-1/2 z-30 ml-2 hidden -translate-y-1/2 whitespace-nowrap rounded bg-raised px-2 py-1 text-small text-ink opacity-0 shadow-float transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100 md:block"
                aria-hidden="true"
              >
                {label}
              </span>
            </>
          )}
        </NavLink>
      ))}
    </nav>
  )
}
