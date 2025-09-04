// ==========================================
// HEXILL Core Utilities (v1.3 Polished)
// ==========================================

// 🔍 Detect hash type
function detectHashType(input) {
  const trimmed = input.trim();

  if (/^0x[a-f0-9]{64}$/i.test(trimmed)) return "ETH_TX";
  if (/^[a-f0-9]{64}$/i.test(trimmed)) return "SHA256";
  if (/^[a-f0-9]{40}$/i.test(trimmed)) return "SHA1";
  if (/^[a-f0-9]{32}$/i.test(trimmed)) return "MD5";
  if (/^Qm[1-9A-Za-z]{44}$/.test(trimmed)) return "IPFS_CID";
  if (trimmed.includes('.')) return "URL";
  return "UNKNOWN";
}

// 💬 Show scanner/cracker status
function showStatus(text) {
  const statusEl = document.getElementById("statusText");
  if (statusEl) {
    statusEl.innerHTML = `<i class="fas fa-circle-notch fa-spin"></i> <p>${text}</p>`;
    statusEl.style.display = "block";
  }
}

// 💬 Display final scan/crack result
function showResult(text) {
  const resultEl = document.getElementById("result");
  if (resultEl) {
    resultEl.innerHTML = `<div class="result-success">${text}</div>`;
    resultEl.style.display = "block";
  }
}

// Clear input and UI
function clearInput() {
  const input = document.getElementById("hashInput");
  const clearBtn = document.getElementById("clearBtn");

  input.value = "";
  clearBtn.style.display = "none";
  showStatus("Ready to scan");

  const resultBox = document.getElementById("resultContent");
  if (resultBox) resultBox.classList.add("hidden");

  input.focus();
}

// 🔁 Handle typing, enter, and paste
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("hashInput");
  const clearBtn = document.getElementById("clearBtn");

  if (input) {
    // Show/hide ❌ button
    input.addEventListener("input", () => {
      clearBtn.style.display = input.value ? "inline" : "none";
    });

    // Auto-scan on Enter
    input.addEventListener("keypress", (e) => {
      if (e.key === "Enter") scanHash();
    });

    // Auto-scan on paste
    input.addEventListener("paste", () => {
      setTimeout(() => {
        if (input.value.length >= 20) scanHash();
      }, 100);
    });
  }
});
