/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#020617',
        panel: '#0f172a',
        edge: '#1e293b',
        accent: '#22d3ee',
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(34,211,238,0.15), 0 20px 60px rgba(2,6,23,0.65)',
      },
    },
  },
  plugins: [],
};
