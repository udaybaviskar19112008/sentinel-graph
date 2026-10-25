import { cyberColors } from './src/theme/colors.ts'

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      // cyber-bg, cyber-grid, cyber-accent, cyber-alert, cyber-safe, cyber-panel
      colors: { ...cyberColors },
    },
  },
  plugins: [],
}
