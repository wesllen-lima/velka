module.exports = {
  content: ["./docs/**/*.html"],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Space Grotesk', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'monospace'],
      },
      colors: {
        sin: {
          mortal: '#dc2626',
          venial: '#f59e0b',
          virtue: '#10b981',
          dark: '#0a0a0f',
          surface: '#141418'
        }
      }
    }
  }
}
