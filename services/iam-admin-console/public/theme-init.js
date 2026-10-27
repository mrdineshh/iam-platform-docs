// Applies the saved (or system) light/dark theme before the page paints, so
// there is no flash of the wrong theme. A separate file rather than an inline
// <script> because the Content-Security-Policy allows scripts from this site
// only (no inline script), which is what blocks injected scripts.
(function () {
  try {
    var stored = localStorage.getItem("iam-admin-console:theme");
    var theme =
      stored === "light" || stored === "dark"
        ? stored
        : window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light";
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {}
})();
