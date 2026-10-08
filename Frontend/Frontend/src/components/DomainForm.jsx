import { useState } from "react";
import { cleanDomain, isValidDomain } from "../api";
import Icon from "./Icon";

// Shared search box: validates the domain, then calls onSubmit(domain).
export default function DomainForm({ buttonText, loadingText, loading, onSubmit, onInvalid }) {
  const [input, setInput] = useState("");

  function submit() {
    const domain = cleanDomain(input);
    if (!isValidDomain(domain)) {
      onInvalid("Enter a valid domain, like example.com.");
      return;
    }
    onSubmit(domain);
  }

  return (
    <div className="mt-6 flex flex-col gap-2 rounded-2xl border border-line bg-surface p-2 shadow-sm transition focus-within:border-accent focus-within:ring-4 focus-within:ring-accent/15 sm:flex-row">
      <div className="flex flex-1 items-center gap-3 px-3">
        <Icon name="globe" className="h-5 w-5 shrink-0 text-subtle" />
        <span className="hidden font-mono text-sm text-subtle sm:inline" aria-hidden="true">https://</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !loading && submit()}
          placeholder="example.com"
          aria-label="Domain"
          autoCapitalize="none"
          spellCheck="false"
          className="min-w-0 flex-1 bg-transparent py-3 font-mono text-fg outline-none placeholder:text-subtle"
        />
      </div>
      <button onClick={submit} disabled={loading} className="btn-primary py-3">
        {loading ? (
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" />
        ) : (
          <Icon name="search" className="h-4 w-4" />
        )}
        {loading ? loadingText : buttonText}
      </button>
    </div>
  );
}
