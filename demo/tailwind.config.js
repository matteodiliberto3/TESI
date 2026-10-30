/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#09090b",
        surface: {
          DEFAULT: "#121215",
          elevated: "#18181b",
          subtle: "#1c1c21",
        },
        producer: {
          DEFAULT: "#3b82f6",
          glow: "rgba(59, 130, 246, 0.15)",
        },
        registry: {
          DEFAULT: "#8b5cf6",
          glow: "rgba(139, 92, 246, 0.15)",
        },
        gate: {
          pass: "#10b981",
          warn: "#f59e0b",
          glow: "rgba(16, 185, 129, 0.15)",
        },
        consumer: {
          DEFAULT: "#f97316",
          glow: "rgba(249, 115, 22, 0.15)",
        },
        audit: {
          DEFAULT: "#ef4444",
          glow: "rgba(239, 68, 68, 0.2)",
        }
      },
      fontFamily: {
        sans: ['Geist', 'Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Geist Mono', 'Fira Code', 'monospace'],
      },
      transitionTimingFunction: {
        'ease-out-expo': 'cubic-bezier(0.19, 1, 0.22, 1)',
        'ease-vaul': 'cubic-bezier(0.32, 0.72, 0, 1)',
      }
    },
  },
  plugins: [],
}
