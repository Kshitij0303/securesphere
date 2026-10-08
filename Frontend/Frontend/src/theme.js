// Light / dark theme. The visitor's choice is remembered in this browser; without one, the system setting is used.
const KEY = "securesphere-theme";

function saved() {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null; // storage blocked (private window, strict settings): fall back to the system setting
  }
}

export function currentTheme() {
  return saved() || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}

export function applyTheme(theme) {
  document.documentElement.classList.toggle("dark", theme === "dark");
}

export function setTheme(theme) {
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // not remembered, but still applied for this visit
  }
  applyTheme(theme);
}
