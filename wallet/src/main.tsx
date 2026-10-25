import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";

const params = new URLSearchParams(window.location.search);

// Dev only: `?mock=1` in a plain browser swaps the Rust backend for canned answers so the
// screens can be styled without building the app. Tree-shaken out of production builds.
if (import.meta.env.DEV && params.has("mock")) {
  const { installMock } = await import("./mock");
  installMock();
}

// The phone gets its own shell: a PIN + Face ID gate, a portfolio home and a bottom tab
// bar. The desktop keeps the full wallet. `?mobile=1` previews the phone shell in a browser.
const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || params.has("mobile");

let Root: React.ComponentType;
if (isMobile) {
  document.documentElement.dataset.shell = "mobile";
  await import("./mobile/mobile.css");
  Root = (await import("./mobile/MobileApp")).default;
} else {
  await import("./App.css");
  Root = (await import("./App")).default;
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
