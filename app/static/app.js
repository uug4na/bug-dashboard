// Enhanced BugDash JavaScript

// Theme Management
;(function initTheme() {
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches
  const stored = localStorage.getItem("theme")
  const theme = stored || (prefersDark ? "dark" : "light")

  document.documentElement.dataset.theme = theme
  updateThemeIcon(theme)
})()

function toggleTheme() {
  const current = document.documentElement.dataset.theme
  const next = current === "dark" ? "light" : "dark"

  document.documentElement.dataset.theme = next
  localStorage.setItem("theme", next)
  updateThemeIcon(next)
}

function updateThemeIcon(theme) {
  const icon = document.getElementById("theme-icon")
  if (icon) {
    icon.textContent = theme === "dark" ? "☀️" : "🌙"
  }
}

// Auto-refresh for running tasks
function enableAutoRefresh(ms = 4000) {
  setInterval(() => {
    const element = document.querySelector("[data-autorefresh]")
    if (element && element.dataset.status) {
      const status = element.dataset.status
      if (status === "queued" || status === "running") {
        // Add loading indicator
        showRefreshIndicator()
        setTimeout(() => {
          location.reload()
        }, 500)
      }
    }
  }, ms)
}

function showRefreshIndicator() {
  // Create a subtle refresh indicator
  const indicator = document.createElement("div")
  indicator.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: var(--accent-primary);
    color: white;
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 500;
    z-index: 1000;
    animation: slideIn 0.3s ease;
  `
  indicator.textContent = "Refreshing..."

  // Add animation keyframes
  if (!document.getElementById("refresh-animation")) {
    const style = document.createElement("style")
    style.id = "refresh-animation"
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `
    document.head.appendChild(style)
  }

  document.body.appendChild(indicator)
}

// Score filtering for findings table
function applyMinScoreFilter() {
  const minScore = Number.parseInt(document.getElementById("minScore")?.value || "0", 10)
  const rows = document.querySelectorAll("#topFindings tbody tr")

  rows.forEach((row) => {
    const score = Number.parseInt(row.dataset.score || "0", 10)
    row.style.display = score >= minScore ? "" : "none"
  })

  // Update visible count
  const visibleRows = Array.from(rows).filter((row) => row.style.display !== "none")
  updateFilterCount(visibleRows.length, rows.length)
}

function updateFilterCount(visible, total) {
  let countElement = document.getElementById("filter-count")
  if (!countElement) {
    countElement = document.createElement("span")
    countElement.id = "filter-count"
    countElement.className = "badge badge-info"
    countElement.style.marginLeft = "8px"

    const header = document.querySelector("#topFindings").closest(".panel").querySelector(".panel-title")
    if (header) {
      header.appendChild(countElement)
    }
  }

  if (visible < total) {
    countElement.textContent = `${visible}/${total} shown`
    countElement.style.display = "inline-flex"
  } else {
    countElement.style.display = "none"
  }
}

// Enhanced form handling
document.addEventListener("DOMContentLoaded", () => {
  // Add loading states to forms
  const forms = document.querySelectorAll("form")
  forms.forEach((form) => {
    form.addEventListener("submit", (e) => {
      const submitBtn = form.querySelector('button[type="submit"]')
      if (submitBtn) {
        submitBtn.disabled = true
        submitBtn.style.opacity = "0.6"

        const originalText = submitBtn.innerHTML
        submitBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite;">
            <path d="M21 12a9 9 0 11-6.219-8.56"/>
          </svg>
          Loading...
        `

        // Add spin animation
        if (!document.getElementById("spin-animation")) {
          const style = document.createElement("style")
          style.id = "spin-animation"
          style.textContent = `
            @keyframes spin {
              from { transform: rotate(0deg); }
              to { transform: rotate(360deg); }
            }
          `
          document.head.appendChild(style)
        }

        // Reset after 10 seconds (fallback)
        setTimeout(() => {
          submitBtn.disabled = false
          submitBtn.style.opacity = "1"
          submitBtn.innerHTML = originalText
        }, 10000)
      }
    })
  })

  // Initialize score filter if present
  if (document.getElementById("minScore")) {
    applyMinScoreFilter()
  }

  // Add keyboard shortcuts
  document.addEventListener("keydown", (e) => {
    // Ctrl/Cmd + K for search (if search exists)
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault()
      const searchInput = document.querySelector('input[type="text"]')
      if (searchInput) {
        searchInput.focus()
      }
    }

    // Ctrl/Cmd + R for refresh
    if ((e.ctrlKey || e.metaKey) && e.key === "r") {
      showRefreshIndicator()
    }
  })
})

// Utility functions
function copyToClipboard(text) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      showToast("Copied to clipboard", "success")
    })
    .catch(() => {
      showToast("Failed to copy", "error")
    })
}

function showToast(message, type = "info") {
  const toast = document.createElement("div")
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: var(--${type === "success" ? "success" : type === "error" ? "error" : "accent-primary"});
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    z-index: 1000;
    animation: slideUp 0.3s ease;
  `
  toast.textContent = message

  // Add animation
  if (!document.getElementById("toast-animation")) {
    const style = document.createElement("style")
    style.id = "toast-animation"
    style.textContent = `
      @keyframes slideUp {
        from { transform: translateY(100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
    `
    document.head.appendChild(style)
  }

  document.body.appendChild(toast)

  setTimeout(() => {
    toast.remove()
  }, 3000)
}
