import { useState } from "react";
import { currentTheme, setTheme } from "../theme";
import Icon from "./Icon";

export default function ThemeToggle() {
  const [theme, setState] = useState(currentTheme);
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      onClick={() => { setTheme(next); setState(next); }}
      aria-label={`Switch to ${next} mode`}
      title={`Switch to ${next} mode`}
      className="rounded-xl p-2 text-muted transition-colors hover:bg-surface-2 hover:text-fg"
    >
      <Icon name={theme === "dark" ? "sun" : "moon"} />
    </button>
  );
}
