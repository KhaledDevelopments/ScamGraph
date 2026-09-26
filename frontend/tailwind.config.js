/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        base: '#0B1220',
        surface: '#141B2D',
        border: '#253147',
        muted: '#8B98B3',
        accent: '#38BDF8',
        risk: {
          low: '#22C55E',
          medium: '#F5A623',
          high: '#E5484D',
        },
      },
      fontFamily: {
        sans: ['"Space Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
}