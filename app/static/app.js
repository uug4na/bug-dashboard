(function () {
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const stored = localStorage.getItem("theme");
  if (!stored) document.documentElement.dataset.theme = prefersDark ? "dark" : "light";
  else document.documentElement.dataset.theme = stored;
})();

function toggleTheme() {
  const cur = document.documentElement.dataset.theme;
  const nxt = cur === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = nxt;
  localStorage.setItem("theme", nxt);
}

function enableAutoRefresh(ms) {
  setInterval(() => {
    const el = document.querySelector("[data-autorefresh]");
    if (el && el.dataset.status && (el.dataset.status === "queued" || el.dataset.status === "running")) {
      location.reload();
    }
  }, ms);
}

function applyMinScoreFilter() {
  const min = parseInt(document.getElementById("minScore").value || "0", 10);
  document.querySelectorAll("#topFindings tbody tr").forEach(tr => {
    const score = parseInt(tr.dataset.score || "0", 10);
    tr.style.display = score >= min ? "" : "none";
  });
}
