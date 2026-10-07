import { createContext, useContext, useState } from "react";

// Remembers the latest scan so the AI assistant can talk about it from any page.
const ScanContext = createContext({ lastScan: null, setLastScan: () => {} });

export function ScanProvider({ children }) {
  const [lastScan, setLastScan] = useState(null);
  return <ScanContext.Provider value={{ lastScan, setLastScan }}>{children}</ScanContext.Provider>;
}

export const useScan = () => useContext(ScanContext);