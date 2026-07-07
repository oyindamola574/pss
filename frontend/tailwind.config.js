/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        panel: "#121a2d",
        accent: "#1e3a8a",
        neonGreen: "#10b981",
        neonPurple: "#a855f7",
        neonBlue: "#3b82f6",
        neonRed: "#ef4444",
        neonYellow: "#f59e0b"
      }
    },
  },
  plugins: [],
}
