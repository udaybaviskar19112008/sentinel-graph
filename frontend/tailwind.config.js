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
      // The sheet's scale: title 26 · section 20 · card 16 · body 13 · small 12, plus one answer figure.
      fontSize: {
        figure: ['32px', { lineHeight: '36px', letterSpacing: '-0.02em' }],
        title: ['26px', { lineHeight: '32px', letterSpacing: '-0.01em' }],
        section: ['20px', { lineHeight: '28px' }],
        card: ['16px', { lineHeight: '24px' }],
        body: ['13px', { lineHeight: '20px' }],
        small: ['12px', { lineHeight: '16px' }],
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
