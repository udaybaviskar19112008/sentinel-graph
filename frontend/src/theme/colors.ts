/**
 * The HUD palette. tailwind.config.js builds its `cyber-*` colours from this, and
 * code that cannot use Tailwind classes (WebGL materials, React Flow edge styles,
 * SVG strokes) imports it directly, so the two never drift apart.
 */
export const cyberColors = {
  'cyber-bg': '#030508', // Deep Void
  'cyber-grid': '#0a111a', // Graphite
  'cyber-accent': '#00f0ff', // Neon Cyan
  'cyber-alert': '#ff003c', // Crimson Warning
  'cyber-safe': '#00ff66', // Emerald Clear
  'cyber-panel': 'rgba(15, 20, 25, 0.4)', // Glassmorphism Base
} as const
