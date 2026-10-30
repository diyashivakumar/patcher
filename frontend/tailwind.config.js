/** @type {import('tailwindcss').Config} */
const token = (v) => `rgb(var(${v}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Consolas", "monospace"],
      },
      colors: {
        // Named design tokens (defined in src/index.css :root).
        brand: { DEFAULT: token("--brand"), ink: token("--brand-ink") },
        ink: token("--ink"),
        surface: { DEFAULT: token("--surface"), 2: token("--surface-2") },
        line: token("--line"),
        verified: token("--verified"),
        breached: token("--breached"),
        blocked: token("--blocked"),
        pending: token("--pending"),
      },
      letterSpacing: {
        tightish: "-0.012em",
        display: "-0.02em",
      },
      boxShadow: {
        card: "0 1px 0 0 rgb(255 255 255 / 0.02) inset, 0 8px 24px -12px rgb(0 0 0 / 0.5)",
        pop: "0 12px 40px -12px rgb(0 0 0 / 0.6)",
      },
      fontSize: {
        display: ["1.75rem", { lineHeight: "2.1rem", letterSpacing: "-0.02em", fontWeight: "650" }],
      },
    },
  },
  plugins: [],
};
