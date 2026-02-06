/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    darkMode: "class",
    theme: {
        extend: {
            colors: {
                primary: "#00CCFF",
                "background-light": "#F8FAFC",
                "background-dark": "#000000",
                "surface-gray": "#1A1A1A",
            },
            fontFamily: {
                display: ["Inter", "sans-serif"],
                mono: ["Space Mono", "monospace"],
                script: ["Caveat", "cursive"],
            },
            borderRadius: {
                DEFAULT: "0.75rem",
            },
            boxShadow: {
                'neon-glow': '0 0 15px rgba(0, 204, 255, 0.4)',
            }
        },
    },
    plugins: [],
}
