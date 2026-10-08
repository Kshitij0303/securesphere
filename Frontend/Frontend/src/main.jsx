import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import { ScanProvider } from "./ScanContext.jsx";
import "./index.css";
import { applyTheme, currentTheme } from "./theme";

applyTheme(currentTheme());

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <BrowserRouter>
      <ScanProvider>
        <App />
      </ScanProvider>
    </BrowserRouter>
  </StrictMode>
);