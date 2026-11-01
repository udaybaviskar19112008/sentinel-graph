/**
 * The UI palette: the design-taste skill's "data terminal" style (dealt into
 * .taste-skill/direction.json, seed 2083124650), with the positive hue re-stepped to teal.
 * tailwind.config.js builds its colours from this, and code that cannot use Tailwind
 * classes (WebGL materials, React Flow edge styles, SVG strokes) imports it directly, so
 * the two never drift apart. Names are roles, not hues.
 *
 * Cards sit one step darker than the ground and are told apart by a soft shadow, never a
 * border or a glow. The accent is only ever a 1px selection line (and the focus ring).
 *
 * positive / warning / negative mean risk and verdicts only, never decoration, and always
 * ship with a text label. They double as the SHAP polarity: negative pushes toward
 * phishing, positive toward legitimate. Checked with the dataviz palette validator on the
 * surface: the dealt green sat 4.3 ΔE from the red for deuteranopes, so positive is a
 * teal (8.2 ΔE; 28.4 in normal vision); every text pair clears 4.5:1 on its own ground.
 */
export const palette = {
  ground: '#171719', // the page, the rail and the bottom bar
  surface: '#131217', // cards
  raised: '#212023', // nested wells, graph nodes, tooltips
  line: '#222224', // the rail's edge, the table header's rule
  rule: '#1b1a1f', // row rules inside cards
  control: '#3a3a3e', // control borders, chart baselines, unscored edges
  ink: '#ffffff',
  muted: '#8a8c92', // secondary text: 5.5:1 on the surface, 4.8:1 on raised
  accent: '#4a8ad6', // selection lines and focus rings only
  positive: '#22a6a0',
  warning: '#d9a441',
  negative: '#e5566f',
  'pill-positive-bg': '#142826',
  'pill-positive-ink': '#5ec9c2',
  'pill-warning-bg': '#2a2416',
  'pill-warning-ink': '#d9a441',
  'pill-negative-bg': '#2c1a20',
  'pill-negative-ink': '#e5566f',
  'pill-neutral-bg': '#212023',
  'pill-neutral-ink': '#bdbdc0',
} as const

/** Status colour for a 0-100 risk score: the bands the risk bar has always used. */
export function riskColor(risk: number): string {
  if (risk >= 75) return palette.negative
  if (risk >= 40) return palette.warning
  return palette.positive
}
