import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./app";
import ErrorBoundary from "./components/ErrorBoundary";
import "./styles/theme.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    {/* See components/ErrorBoundary.jsx for why this exists -- turns
        an uncaught render crash anywhere in the app into a visible,
        recoverable message instead of a blank white screen. */}
    <ErrorBoundary onReset={() => window.location.assign("/")}>
      <App />
    </ErrorBoundary>
  </StrictMode>,
);
