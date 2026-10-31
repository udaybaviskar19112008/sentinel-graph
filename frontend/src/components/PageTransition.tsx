import { motion, type TargetAndTransition, useReducedMotion } from 'framer-motion'
import type { ReactNode } from 'react'

const MOTION = {
  initial: { opacity: 0, y: 10, filter: 'blur(10px)' },
  // Ends at filter: none, not blur(0px): any filter on an ancestor makes it a backdrop root,
  // and the glass panels inside would stop blurring the globe behind them.
  animate: { opacity: 1, y: 0, filter: 'blur(0px)', transitionEnd: { filter: 'none' } },
  exit: { opacity: 0, y: -10, filter: 'blur(10px)' },
} satisfies Record<string, TargetAndTransition>

const FADE_ONLY = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  exit: { opacity: 0 },
} satisfies Record<string, TargetAndTransition>

/** Fade, slide and un-blur a routed page in; the reverse on the way out. Reduced motion: fade only. */
export function PageTransition({ children }: { children: ReactNode }) {
  const variants = useReducedMotion() ? FADE_ONLY : MOTION
  return (
    <motion.div
      className="h-full w-full"
      initial={variants.initial}
      animate={variants.animate}
      exit={variants.exit}
      transition={{ duration: 0.4, ease: 'easeOut' }}
    >
      {children}
    </motion.div>
  )
}
