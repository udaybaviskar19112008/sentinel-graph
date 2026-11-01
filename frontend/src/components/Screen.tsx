import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export const PRODUCT_NAME = 'Sentinel-Graph'

/**
 * One screen's canvas: the product and the screen's name as a breadcrumb (the name is the
 * h1), one grey line about the data under it, and the screen's actions on the right.
 *
 * `fill` locks the screen to the viewport from 1280px up, so a console view (the live
 * scan) keeps every block on the first screen; narrower, it scrolls like the rest.
 */
export function Screen({
  title,
  subline,
  actions,
  fill = false,
  className,
  children,
}: {
  title: string
  subline?: ReactNode
  actions?: ReactNode
  fill?: boolean
  className?: string
  children: ReactNode
}) {
  return (
    <div className={cn('flex min-h-full flex-col px-4 pb-6 pt-5 md:px-8 md:pb-8 md:pt-7', fill && 'xl:h-full', className)}>
      <header className="mb-6 flex flex-wrap items-end justify-between gap-x-8 gap-y-3">
        <div className="min-w-0 max-w-3xl">
          <div className="flex items-baseline gap-2 text-section md:text-title">
            <span className="font-normal text-muted">{PRODUCT_NAME}</span>
            <span className="text-control" aria-hidden="true">
              /
            </span>
            <h1 className="font-bold">{title}</h1>
          </div>
          {subline && <p className="mt-1 line-clamp-2 text-body text-muted">{subline}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-4">{actions}</div>}
      </header>
      <div className={cn('flex flex-1 flex-col', fill && 'xl:min-h-0')}>{children}</div>
    </div>
  )
}
