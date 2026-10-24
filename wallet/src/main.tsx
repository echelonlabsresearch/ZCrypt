import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import "./App.css";

// Dev only: `?mock=1` in a plain browser swaps the Rust backend for canned answers so the
// screens can be styled without building the app. Tree-shaken out of production builds.
if (import.meta.env.DEV && new URLSearchParams(window.location.search).has("mock")) {
  const { installMock } = await import("./mock");
  installMock();
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
