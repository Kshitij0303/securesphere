import { useEffect, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { askAssistant } from "../api";
import { useScan } from "../ScanContext";
import Icon from "./Icon";

const START = [{ role: "assistant", text: "Hi! Ask me anything about HTTPS security or your scan results. I will keep it simple." }];
const SUGGESTIONS = ["Why is my score low?", "What should I fix first?", "Explain HSTS", "Are my cookies safe?"];

export default function Assistant() {
  const { lastScan } = useScan();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState(START);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState(null); // "ai" or "basic", known after the first answer
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [messages, open]);

  // Close the chat when the user moves to another page, so it never covers that page's links and buttons.
  const { pathname } = useLocation();
  useEffect(() => setOpen(false), [pathname]);

  // The assistant explains a scan, so it appears only once there is one (a finished scan or an opened report).
  if (!lastScan) return null;

  async function send(text) {
    const message = text.trim();
    if (!message || busy) return;
    setInput("");
    // Earlier turns give the AI context; the greeting is ours, not part of the conversation.
    const history = messages.slice(1).map((m) => ({ role: m.role, content: m.text }));
    setMessages((m) => [...m, { role: "user", text: message }]);
    setBusy(true);
    try {
      const { reply, ai } = await askAssistant(message, lastScan, history);
      setMode(ai ? "ai" : "basic");
      setMessages((m) => [...m, { role: "assistant", text: reply }]);
    } catch (e) {
      setMessages((m) => [...m, { role: "assistant", text: e.message }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed bottom-4 right-4 z-50">
      {open && (
        <div
          role="dialog"
          aria-label="SecureSphere assistant"
          onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
          className="fade-up mb-3 flex h-[30rem] max-h-[calc(100vh-7rem)] w-[calc(100vw-2rem)] max-w-sm flex-col overflow-hidden rounded-2xl border border-line bg-surface shadow-2xl"
        >
          <div className="flex items-center justify-between gap-3 border-b border-line bg-gradient-to-r from-teal-600 to-cyan-700 px-4 py-3 text-white">
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-white/15">
                <Icon name="shieldCheck" className="h-5 w-5" />
              </span>
              <div>
                <p className="font-semibold">Security assistant</p>
                <p className="text-xs text-white/80">
                  {lastScan ? `Using your scan of ${lastScan.domain}` : "Scan a site for personal answers"}
                  {mode === "ai" && " · AI answers"}
                  {mode === "basic" && " · built-in answers"}
                </p>
              </div>
            </div>
            <button onClick={() => setOpen(false)} aria-label="Close assistant" className="rounded-lg p-1.5 hover:bg-white/15">
              <Icon name="x" className="h-4 w-4" />
            </button>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto p-4" aria-live="polite">
            {messages.map((m, i) => (
              <div key={i} className={m.role === "user" ? "flex justify-end" : "flex justify-start"}>
                <p
                  className={`max-w-[85%] whitespace-pre-line rounded-2xl px-3.5 py-2 text-sm ${
                    m.role === "user" ? "rounded-br-sm bg-accent text-on-accent" : "rounded-bl-sm bg-surface-2 text-fg"
                  }`}
                >
                  {m.text}
                </p>
              </div>
            ))}
            {busy && (
              <p className="flex items-center gap-1 text-sm text-subtle" aria-label="Thinking">
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-subtle" />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-subtle [animation-delay:0.15s]" />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-subtle [animation-delay:0.3s]" />
              </p>
            )}
            {messages.length === 1 && (
              <div className="flex flex-wrap gap-2">
                {SUGGESTIONS.map((s) => (
                  <button
                    key={s}
                    onClick={() => send(s)}
                    className="rounded-full border border-line px-3 py-1 text-sm text-fg transition-colors hover:border-accent hover:text-accent"
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
            <div ref={endRef} />
          </div>

          <form onSubmit={(e) => { e.preventDefault(); send(input); }} className="flex gap-2 border-t border-line p-3">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Type your question"
              aria-label="Your question"
              className="min-w-0 flex-1 rounded-xl border border-line bg-surface-2 px-3 py-2 text-sm text-fg outline-none placeholder:text-subtle focus:border-accent"
            />
            <button type="submit" disabled={busy} aria-label="Send" className="btn-primary px-3 py-2">
              <Icon name="send" className="h-4 w-4" />
            </button>
          </form>
        </div>
      )}

      <button
        onClick={() => setOpen(!open)}
        aria-label={open ? "Close assistant" : "Open security assistant"}
        aria-expanded={open}
        className="ml-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-teal-500 to-cyan-700 text-white shadow-lg shadow-teal-900/20 transition-transform hover:scale-105"
      >
        <Icon name={open ? "x" : "chat"} className="h-6 w-6" strokeWidth={2} />
      </button>
    </div>
  );
}
