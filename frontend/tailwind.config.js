/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        command: {
          base: "#070B14",
          surface: "#0B1220",
          elevated: "#101A2B",
          glass: "rgba(18,32,49,.72)",
          border: "rgba(125,165,205,.16)",
        },
        brand: { cyan: "#42E8F5", blue: "#568BFF", violet: "#B66BFF" },
        signal: { success: "#35E6A1", critical: "#FF5576", warning: "#FFC66D" },
        sky: { 300: "#8CF2FA", 400: "#42E8F5", 500: "#42E8F5", 600: "#26B8C5" },
        emerald: { 300: "#80F1C4", 400: "#35E6A1" },
        rose: { 300: "#FF99AD", 400: "#FF5576" },
        slate: {
          400: "#93A7C1",
          500: "#8295AE",
          600: "#60748D",
          700: "#283950",
          800: "#1B2A40",
          900: "#0B1220",
          950: "#070B14",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
