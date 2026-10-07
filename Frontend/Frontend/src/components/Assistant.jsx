import { useEffect, useRef, useState } from "react";
import { askAssistant } from "../api";
import { useScan } from "../ScanContext";

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
          className="mb-3 flex h-[28rem] w-[calc(100vw-2rem)] max-w-sm flex-col overflow-hidden rounded-lg border border-slate-200 bg-white shadow-xl"
        >
          <div className="flex items-center justify-between bg-teal-700 px-4 py-3 text-white">
            <div>
              <p className="font-semibold">Security assistant</p>
              <p className="text-xs text-teal-100">
                {lastScan ? `Using your scan of ${lastScan.domain}` : "Scan a site for personal answers"}
                {mode === "ai" && " · AI answers"}
                {mode === "basic" && " · built-in answers"}
              </p>
            </div>
            <button onClick={() => setOpen(false)} aria-label="Close assistant" className="rounded px-2 py-1 hover:bg-teal-800">✕</button>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto p-4" aria-live="polite">
            {messages.map((m, i) => (
              <div key={i} className={m.role === "user" ? "flex justify-end" : "flex justify-start"}>
                <p className={`max-w-[85%] whitespace-pre-line rounded-lg px-3 py-2 ${m.role === "user" ? "bg-teal-700 text-white" : "bg-slate-100 text-slate-900"}`}>
                  {m.text}
                </p>
              </div>
            ))}
            {busy && <p className="text-sm text-slate-500">Thinking…</p>}
            {messages.length === 1 && (
              <div className="flex flex-wrap gap-2">
                {SUGGESTIONS.map((s) => (
                  <button key={s} onClick={() => send(s)} className="rounded-full border border-slate-300 px-3 py-1 text-sm hover:bg-slate-100">
                    {s}
                  </button>
                ))}
              </div>
            )}
            <div ref={endRef} />
          </div>

          <form onSubmit={(e) => { e.preventDefault(); send(input); }} className="flex gap-2 border-t border-slate-200 p-3">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Type your question"
              aria-label="Your question"
              className="min-w-0 flex-1 rounded-md border border-slate-300 px-3 py-2 outline-none focus:border-teal-700"
            />
            <button type="submit" disabled={busy} className="rounded-md bg-teal-700 px-4 py-2 font-semibold text-white hover:bg-teal-800 disabled:opacity-60">
              Send
            </button>
          </form>
        </div>
      )}

      <button
        onClick={() => setOpen(!open)}
        aria-label={open ? "Close assistant" : "Open security assistant"}
        aria-expanded={open}
        className="ml-auto flex h-14 w-14 items-center justify-center rounded-full bg-teal-700 text-white shadow-lg hover:bg-teal-800"
      >
        <svg viewBox="0 0 24 24" className="h-7 w-7" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M21 12a8 8 0 0 1-11.5 7.2L4 20l1-4.5A8 8 0 1 1 21 12z" />
        </svg>
      </button>
    </div>
  );
}