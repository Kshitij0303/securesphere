// Small line icons drawn inline (no icon library, so the strict Content-Security-Policy stays as it is).
const PATHS = {
  shield: "M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z",
  shieldCheck: "M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z M9 12l2 2 4-4",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M21 21l-4.3-4.3",
  history: "M3 12a9 9 0 1 0 3-6.7L3 8 M3 3v5h5 M12 7v5l3 2",
  radar: "M12 12m-9 0a9 9 0 1 0 18 0 9 9 0 1 0-18 0 M12 12m-5 0a5 5 0 1 0 10 0 5 5 0 1 0-10 0 M12 12l6-6",
  bell: "M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9 M10.3 21a1.9 1.9 0 0 0 3.4 0",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M4 21a8 8 0 0 1 16 0",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4 M16 17l5-5-5-5 M21 12H9",
  sun: "M12 12m-4 0a4 4 0 1 0 8 0 4 4 0 1 0-8 0 M12 2v2 M12 20v2 M4.9 4.9l1.4 1.4 M17.7 17.7l1.4 1.4 M2 12h2 M20 12h2 M4.9 19.1l1.4-1.4 M17.7 6.3l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  lock: "M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4",
  cert: "M4 4h16v12H4z M8 8h8 M8 12h5 M15 16l1 5 2-1.5 2 1.5-1-5",
  layers: "M12 3l9 5-9 5-9-5 9-5z M3 13l9 5 9-5",
  key: "M15 7a4 4 0 1 1-3.9 5H3v3h3v3h3v-3h2.1A4 4 0 0 1 15 7z",
  file: "M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-6-6z M14 3v6h6",
  cookie: "M12 3a9 9 0 1 0 9 9 4 4 0 0 1-5-5 4 4 0 0 1-4-4z M8.5 12.5h.01 M12 16h.01 M15 13h.01",
  bug: "M8 8a4 4 0 0 1 8 0v8a4 4 0 0 1-8 0V8z M3 13h5 M16 13h5 M4 7l4 3 M20 7l-4 3 M4 19l4-3 M20 19l-4-3",
  globe: "M12 12m-9 0a9 9 0 1 0 18 0 9 9 0 1 0-18 0 M3 12h18 M12 3a14 14 0 0 1 0 18 M12 3a14 14 0 0 0 0 18",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1 M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  download: "M12 3v12 M7 10l5 5 5-5 M4 21h16",
  check: "M5 12l5 5L20 7",
  alert: "M12 3l10 18H2L12 3z M12 10v4 M12 17h.01",
  help: "M12 12m-9 0a9 9 0 1 0 18 0 9 9 0 1 0-18 0 M9.5 9a2.5 2.5 0 0 1 5 .5c0 1.5-2.5 2-2.5 3.5 M12 17h.01",
  chat: "M21 12a8 8 0 0 1-11.5 7.2L4 20l1-4.5A8 8 0 1 1 21 12z",
  x: "M6 6l12 12 M18 6L6 18",
  arrowRight: "M5 12h14 M13 6l6 6-6 6",
  arrowLeft: "M19 12H5 M11 6l-6 6 6 6",
  mail: "M3 5h18v14H3z M3 6l9 7 9-7",
  chart: "M4 20V10 M10 20V4 M16 20v-7 M22 20H2",
  wrench: "M14.7 6.3a4 4 0 0 0 5 5L22 14l-8 8-2.3-2.3a4 4 0 0 0-5-5L2 10l8-8z",
  send: "M22 2L11 13 M22 2l-7 20-4-9-9-4 20-7z",
  menu: "M4 6h16 M4 12h16 M4 18h16",
};

export default function Icon({ name, className = "h-5 w-5", strokeWidth = 1.8 }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth={strokeWidth}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name]} />
    </svg>
  );
}
