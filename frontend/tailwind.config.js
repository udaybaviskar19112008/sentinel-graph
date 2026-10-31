import { cyberColors } from './src/theme/colors.ts'

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      // cyber-bg, cyber-grid, cyber-accent, cyber-safe, cyber-warning, cyber-alert, glass-*
      colors: { ...cyberColors },
      keyframes: {
        // The backdrop layer is oversized (see index.css), so a ±12% drift never shows an edge.
        'gradient-pan': {
          '0%': { transform: 'translate3d(-12%, -12%, 0)' },
          '100%': { transform: 'translate3d(12%, 12%, 0)' },
        },
      },
      animation: {
        'gradient-pan': 'gradient-pan 15s ease-in-out infinite alternate',
      },
    },
  },
  plugins: [],
}
