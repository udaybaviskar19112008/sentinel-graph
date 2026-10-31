/**
 * The UI palette: stone surfaces, a plum accent, and a reserved status scale.
 * tailwind.config.js builds its `cyber-*` and `glass-*` colours from this, and code that
 * cannot use Tailwind classes (WebGL materials, React Flow edge styles, SVG strokes)
 * imports it directly, so the two never drift apart. `cyber-*` names are roles, not hues.
 *
 * Status colours (safe / warning / alert) mean risk and verdicts only, never decoration,
 * and always ship with a text label. Checked with the dataviz palette validator against
 * the stone surface: every one clears 3:1 contrast, and the closest colour-blind pair
 * (amber vs emerald, protanopia) separates by ΔE 8.9; emerald vs rose by 10.5.
 */
export const cyberColors = {
  'cyber-bg': '#1c1917', // stone-900: the base surface under the animated gradient
  'cyber-grid': '#292524', // stone-800: hairlines (the topology map's background)
  'cyber-accent': '#f0abfc', // fuchsia-300, the plum accent: interface chrome, never a risk state
  'cyber-safe': '#10b981', // emerald-500: status good
  'cyber-warning': '#f59e0b', // amber-500: status warning (SUSPICIOUS, mid risk)
  'cyber-alert': '#e11d48', // rose-600: status critical
  // Glass is translucent white: no Tailwind opacity modifier on these (it replaces the alpha).
  'glass-base': 'rgba(255, 255, 255, 0.05)',
  'glass-border': 'rgba(255, 255, 255, 0.1)',
  'glass-highlight': 'rgba(255, 255, 255, 0.15)',
} as const
