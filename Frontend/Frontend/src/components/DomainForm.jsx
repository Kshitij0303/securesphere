import { useState } from "react";
import { cleanDomain, isValidDomain } from "../api";

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
    <div className="mt-6 flex flex-col gap-3 sm:flex-row">
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && !loading && submit()}
        placeholder="example.com"
        aria-label="Domain"
        className="flex-1 rounded-md border border-slate-300 bg-white px-4 py-3 outline-none focus:border-teal-700 focus:ring-2 focus:ring-teal-700/30"
      />
      <button
        onClick={submit}
        disabled={loading}
        className="rounded-md bg-teal-700 px-6 py-3 font-semibold text-white hover:bg-teal-800 disabled:opacity-60"
      >
        {loading ? loadingText : buttonText}
      </button>
    </div>
  );
}