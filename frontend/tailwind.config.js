import { palette } from './src/theme/colors.ts'

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      // ground, surface, raised, line, rule, control, ink, muted, accent, positive, warning, negative, pill-*
      colors: { ...palette },
      fontFamily: {
        // Public Sans is loaded in index.html; offline, the system face takes over.
        sans: ['"Public Sans"', 'Inter', 'system-ui', 'sans-serif'],
      },
      // Title 28 · section 20 · card 18 · body 15 · small 13, plus one answer figure. Raised from the
      // sheet's dense 26/20/16/13/12 after the scale read as too faint in use.
      fontSize: {
        figure: ['36px', { lineHeight: '40px', letterSpacing: '-0.02em' }],
        title: ['28px', { lineHeight: '34px', letterSpacing: '-0.015em' }],
        section: ['20px', { lineHeight: '28px' }],
        card: ['18px', { lineHeight: '26px', letterSpacing: '-0.01em' }],
        body: ['15px', { lineHeight: '22px' }],
        small: ['13px', { lineHeight: '18px' }],
      },
      boxShadow: {
        // Cards only: they sit darker than the ground, so the shadow is what lifts them.
        card: '0 12px 28px rgba(0, 0, 0, 0.2)',
        // Things that truly float: tooltips, the drop overlay.
        float: '0 8px 24px rgba(0, 0, 0, 0.45)',
      },
    },
  },
  plugins: [],
}
