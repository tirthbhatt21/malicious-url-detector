/* ================= THEME ================= */

function updateThemeIcon() {
  const btn = document.getElementById("themeBtn");

  if (!btn) return;

  if (document.body.classList.contains("light-mode")) {
    btn.innerHTML = "☀️";
    btn.title = "Switch to Dark Mode";
  } else {
    btn.innerHTML = "🌙";
    btn.title = "Switch to Light Mode";
  }
}

function toggleTheme() {
  document.body.classList.toggle("light-mode");

  const mode =
    document.body.classList.contains("light-mode")
      ? "light"
      : "dark";

  localStorage.setItem("theme", mode);

  updateThemeIcon();

  if (window.lastScore !== undefined) {
    drawGraph(window.lastScore);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const saved = localStorage.getItem("theme");

  if (saved === "light") {
    document.body.classList.add("light-mode");
  }

  updateThemeIcon();
  updateHistory();
});

/* ================= TOAST ================= */

function showToast(msg, success = true) {
  const toast = document.getElementById("toast");

  toast.textContent = msg;

  toast.style.borderColor =
    success ? "#22c55e" : "#ef4444";

  toast.style.opacity = "1";

  setTimeout(() => {
    toast.style.opacity = "0";
  }, 3000);
}

/* ================= CONFIG ================= */

const FEED_URL =
  "https://raw.githubusercontent.com/tirthbhatt21/malicious-url-detector/main/feed.json";

let FEED_CACHE = {
  domains: [],
  lastUpdated: 0
};

let scanHistory = [];

window.lastScore = 0;

/* ================= LOAD FEED ================= */

async function loadFeed() {
  const now = Date.now();

  if (
    now - FEED_CACHE.lastUpdated <
    15 * 60 * 1000
  ) {
    return;
  }

  try {
    const res = await fetch(FEED_URL);

    const data = await res.json();

    FEED_CACHE = {
      domains: data.domains || [],
      lastUpdated: now
    };

    showToast(
      `Feed Loaded (${FEED_CACHE.domains.length})`
    );

  } catch (e) {

    FEED_CACHE = {
      domains: [
        "paypal-secure-login.com",
        "google-auth-check.net"
      ],
      lastUpdated: now
    };

    showToast(
      "Feed unavailable → fallback active",
      false
    );
  }
}

loadFeed();

/* ================= SAFE URL ================= */

function safeURL(urlStr) {
  try {
    return new URL(urlStr);
  } catch {
    return null;
  }
}

/* ================= ENTROPY ================= */

function entropy(str) {
  const map = {};

  for (const c of str) {
    map[c] = (map[c] || 0) + 1;
  }

  let result = 0;

  for (const count of Object.values(map)) {
    const p = count / str.length;
    result -= p * Math.log2(p);
  }

  return result;
}

/* ================= LEVENSHTEIN ================= */

function levenshtein(a, b) {

  const matrix = Array.from(
    { length: b.length + 1 },
    () => []
  );

  for (let i = 0; i <= b.length; i++) {
    matrix[i][0] = i;
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {

    for (let j = 1; j <= a.length; j++) {

      matrix[i][j] =
        b[i - 1] === a[j - 1]
          ? matrix[i - 1][j - 1]
          : Math.min(
              matrix[i - 1][j - 1] + 1,
              matrix[i][j - 1] + 1,
              matrix[i - 1][j] + 1
            );
    }
  }

  return matrix[b.length][a.length];
}

/* ================= DOMAIN NORMALIZER ================= */

function normalizeDomain(domain) {
  return domain
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a");
}

/* ================= DETECTORS ================= */

function runDetectors(urlStr, domain, protocol) {

  const signals = [];

  const keywords = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
    "password",
    "signin"
  ];

  const brands = [
    "google",
    "paypal",
    "amazon",
    "facebook",
    "apple",
    "microsoft",
    "netflix",
    "instagram"
  ];

  /* ===== LIVE FEED ===== */

  if (
  FEED_CACHE.domains.some(
    d =>
      domain === d ||
      domain.endsWith("." + d)
  )
) {
  signals.push({
    name: "Live Threat Feed",
    score: 100
  });
}

  /* ===== PHISHING KEYWORDS ===== */

  if (
    keywords.some(
      k =>
        urlStr
          .toLowerCase()
          .includes(k)
    )
  ) {
    signals.push({
      name: "Phishing Keywords",
      score: 60
    });
  }

  /* ===== @ SYMBOL ===== */

  if (urlStr.includes("@")) {
    signals.push({
      name: "@ Symbol",
      score: 90
    });
  }

  /* ===== SHORTENED URL ===== */

  if (
    /bit\.ly|tinyurl|goo\.gl|t\.co/i
      .test(urlStr)
  ) {
    signals.push({
      name: "Shortened URL",
      score: 65
    });
  }

  /* ===== IP ADDRESS URL ===== */

  if (
    /^(\d+\.){3}\d+$/
      .test(domain)
  ) {
    signals.push({
      name: "IP Address URL",
      score: 85
    });
  }

  /* ===== NO HTTPS ===== */

  if (protocol !== "https:") {
    signals.push({
      name: "No HTTPS",
      score: 25
    });
  }

  /* ===== LONG DOMAIN ===== */

  if (domain.length > 25) {
    signals.push({
      name: "Long Domain",
      score: 40
    });
  }

  /* ===== SUBDOMAINS ===== */

  if (
    domain.split(".").length > 3
  ) {
    signals.push({
      name:
        "Multiple Subdomains",
      score: 35
    });
  }

  /* ===== HIGH ENTROPY ===== */

  if (
    entropy(domain) > 3.8
  ) {
    signals.push({
      name:
        "High Entropy Domain",
      score: 65
    });
  }

  /* ===== HYPHEN ===== */

  if (domain.includes("-")) {
    signals.push({
      name:
        "Hyphen Domain",
      score: 20
    });
  }

  /* ===== NUMERIC DOMAIN ===== */

  const digits =
    (
      domain.match(/\d/g)
      || []
    ).length;

  if (digits >= 4) {
    signals.push({
      name:
        "Numeric Domain",
      score: 25
    });
  }

  /* ===== BRAND IMPERSONATION ===== */

  for (const brand of brands) {

    if (
      urlStr.includes(brand) &&
      !domain.includes(brand)
    ) {
      signals.push({
        name:
          "Brand Impersonation",
        score: 85
      });

      break;
    }
  }

  /* ===== LOOKALIKE DOMAIN ===== */

  const normalized =
    normalizeDomain(domain);

  for (const brand of brands) {

    const d =
      levenshtein(
        normalized
          .replace(/\./g, ""),
        brand
      );

    if (d > 0 && d <= 2) {
      signals.push({
        name:
          "Possible Brand Spoof",
        score: 90
      });

      break;
    }
  }

  return signals;
}

/* ================= SCORE ENGINE ================= */

function computeScore(signals) {

  if (!signals.length)
    return 5;

  let score = 0;

  for (const s of signals) {
    score += s.score;
  }

  const criticalSignals = [
    "Live Threat Feed",
    "Possible Brand Spoof",
    "Brand Impersonation"
  ];

  if (
    signals.some(s =>
      criticalSignals.includes(
        s.name
      )
    )
  ) {
    return 100;
  }

  return Math.min(score, 100);
}


/* ==========================================================
   PART 2 : GRAPH + DNS + HEURISTICS + THREAT INTEL
========================================================== */

/* ================= GRAPH ================= */

function drawGraph(score) {

  window.lastScore = score;

  let canvas =
    document.getElementById(
      "riskGraph"
    );

  if (!canvas) {

    canvas =
      document.createElement(
        "canvas"
      );

    canvas.id = "riskGraph";

    document
      .getElementById("result")
      .appendChild(canvas);
  }

  canvas.width = 520;
  canvas.height = 220;

  const ctx =
    canvas.getContext("2d");

  const dark =
    !document.body
      .classList
      .contains("light-mode");

  /* ===== BACKGROUND ===== */

  ctx.fillStyle = dark
    ? "#0f172a"
    : "#ffffff";

  ctx.fillRect(
    0,
    0,
    canvas.width,
    canvas.height
  );

  /* ===== GRID ===== */

  ctx.strokeStyle = dark
    ? "#334155"
    : "#d1d5db";

  ctx.lineWidth = 1;

  for (let i = 0; i <= 5; i++) {

    const y =
      (canvas.height / 5) * i;

    ctx.beginPath();

    ctx.moveTo(0, y);

    ctx.lineTo(
      canvas.width,
      y
    );

    ctx.stroke();

    ctx.fillStyle = dark
      ? "#cbd5e1"
      : "#374151";

    ctx.font =
      "11px monospace";

    ctx.fillText(
      `${100 - i * 20}%`,
      5,
      y + 12
    );
  }

  for (let i = 0; i <= 10; i++) {

    const x =
      (canvas.width / 10) * i;

    ctx.beginPath();

    ctx.moveTo(x, 0);

    ctx.lineTo(
      x,
      canvas.height
    );

    ctx.stroke();
  }

  /* ===== RISK COLOR ===== */

  let riskColor;

  if (score >= 80) {
    riskColor = "#ef4444";
  } else if (score >= 60) {
    riskColor = "#f97316";
  } else if (score >= 40) {
    riskColor = "#eab308";
  } else {
    riskColor = "#22c55e";
  }

  /* ===== POINT ===== */

  const x =
    canvas.width - 20;

  const y =
    canvas.height -
    (score / 100) *
      canvas.height;

  ctx.shadowBlur = 15;
  ctx.shadowColor =
    riskColor;

  ctx.fillStyle =
    riskColor;

  ctx.beginPath();

  ctx.arc(
    x,
    y,
    8,
    0,
    Math.PI * 2
  );

  ctx.fill();

  ctx.shadowBlur = 0;

  /* ===== LABEL ===== */

  ctx.fillStyle =
    riskColor;

  ctx.font =
    "bold 14px monospace";

  ctx.fillText(
    `${score}%`,
    canvas.width - 60,
    18
  );

  /* ===== CROSSHAIR ===== */

  ctx.strokeStyle =
    riskColor;

  ctx.setLineDash([
    4,
    4
  ]);

  ctx.beginPath();

  ctx.moveTo(0, y);

  ctx.lineTo(x, y);

  ctx.stroke();

  ctx.setLineDash([]);
}

/* ================= DNS CHECK ================= */

async function dnsCheck(
  domain
) {

  try {

    const res =
      await fetch(
        `https://dns.google/resolve?name=${domain}`
      );

    const data =
      await res.json();

    let score = 0;

    if (!data.Answer) {
      score += 20;
    }

    return {
      score,
      records:
        data.Answer || []
    };

  } catch {

    return {
      score: 0,
      records: []
    };
  }
}

/* ================= DOMAIN HEURISTICS ================= */

function domainHeuristics(
  domain
) {

  let score = 0;

  const riskyTLDs = [
    ".xyz",
    ".top",
    ".site",
    ".online",
    ".tech",
    ".club",
    ".click",
    ".live"
  ];

  if (
    riskyTLDs.some(
      t =>
        domain.endsWith(t)
    )
  ) {

    score += 30;
  }

  if (
    entropy(domain) > 3.8 &&
    domain.length < 12
  ) {

    score += 25;
  }

  if (
    domain
      .split(".")
      .length > 4
  ) {

    score += 20;
  }

  return { score };
}


/* ================= PHISHTANK ================= */

async function checkPhishTank(
  url
) {

  try {

    const res =
      await fetch(
        "https://checkurl.phishtank.com/checkurl/",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded"
          },

          body:
            new URLSearchParams(
              {
                url,
                format:
                  "json"
              }
            )
        }
      );

    const data =
      await res.json();

    return {

      score:
        data?.results
          ?.in_database
          ? 80
          : 0,

      detected:
        data?.results
          ?.in_database ||
        false,

      verified:
        data?.results
          ?.verified ||
        false
    };

  } catch {

     return {
    score: 0,
    detected: false,
    verified: false,
    status: "UNAVAILABLE"
  };
  }
}

/* ================= SSL CHECK ================= */

function sslCheck(url) {

  try {

    const u =
      new URL(url);

    return {
      secure:
        u.protocol ===
        "https:"
    };

  } catch {

    return {
      secure: false
    };
  }
}

/* ================= RISK LEVEL ================= */

function getRiskLevel(
  score
) {

  if (score >= 80) {
    return "CRITICAL";
  }

  if (score >= 60) {
    return "HIGH";
  }

  if (score >= 40) {
    return "MEDIUM";
  }

  return "LOW";
}

/* ================= RISK VERDICT ================= */

function getVerdict(
  score
) {

  if (score >= 80) {
    return "DEFINITE PHISHING";
  }

  if (score >= 60) {
    return "LIKELY PHISHING";
  }

  if (score >= 40) {
    return "SUSPICIOUS";
  }

  return "LIKELY SAFE";
}

/* ==========================================================
   PART 3 : ANALYZE + LOADER + HISTORY + RENDER
========================================================== */

/* ================= LOADER ================= */

function showLoader() {

  document
    .getElementById("loader")
    .classList.remove("hidden");

  document
    .getElementById("loaderText")
    .classList.remove("hidden");

  let t = 3;

  document
    .getElementById("timer")
    .textContent = t;

  clearInterval(
    window.loaderInterval
  );

  window.loaderInterval =
    setInterval(() => {

      t--;

      if (t >= 0) {

        document
          .getElementById("timer")
          .textContent = t;
      }

    }, 1000);
}

function hideLoader() {

  document
    .getElementById("loader")
    .classList.add("hidden");

  document
    .getElementById("loaderText")
    .classList.add("hidden");

  clearInterval(
    window.loaderInterval
  );
}

/* ================= HISTORY ================= */

function updateHistory() {

  const history =
    document.getElementById(
      "history"
    );

  if (!history) return;

  if (
    scanHistory.length === 0
  ) {

    history.innerHTML =
      "No scans yet";

    return;
  }

  history.innerHTML =
  scanHistory
    .slice(-5)
    .reverse()
    .map(
      x => `
      <div class="history-item">
        🌐 ${x.domain}
        <b>${x.score}%</b>
      </div>
    `
    )
    .join("");
}

/* ================= ANALYZE ================= */

async function analyze() {

  let url =
    document
      .getElementById(
        "urlInput"
      )
      .value
      .trim();

  if (!url) {

    showToast(
      "Enter URL first",
      false
    );

    return;
  }

  if (
    !url.startsWith(
      "http"
    )
  ) {

    url =
      "https://" + url;
  }

  const u =
    safeURL(url);

  if (!u) {

    showToast(
      "Invalid URL",
      false
    );

    return;
  }

  showLoader();

  try {

    const domain =
      u.hostname
        .toLowerCase();

    const protocol =
      u.protocol;

    const [
      dns,
      heuristics,
      phish,
    ] =
      await Promise.all([
        dnsCheck(
          domain
        ),

        domainHeuristics(
          domain
        ),

        checkPhishTank(
          url
        ),

      ]);

    const signals =
      runDetectors(
        url,
        domain,
        protocol
      );

    let score =
      computeScore(
        signals
      );

    score +=
      dns.score +
      heuristics.score +
      phish.score;

    score =
      Math.min(
        score,
        100
      );

    scanHistory.push({

      domain,

      score,

      time:
        new Date()
          .toLocaleString()
    });

    updateHistory();

    render(
      url,
      score,
      signals,
      dns,
      phish,
    );

    showToast(
      "Scan completed"
    );

  } catch (e) {

    console.error(
      e
    );

    showToast(
      "Scan failed",
      false
    );

  } finally {

    hideLoader();
  }

  function saveScan(url, risk) {
  let history = JSON.parse(localStorage.getItem("scanHistory") || "[]");

  history.push({
    url,
    risk,
    time: new Date().toISOString()
  });

  localStorage.setItem("scanHistory", JSON.stringify(history));
}

}

/* ================= RENDER ================= */

function render(
  url,
  score,
  signals,
  dns,
  phish,
) {

  drawGraph(score);

  const level =
    getRiskLevel(
      score
    );

  const verdict =
    getVerdict(
      score
    );

  const breakdown =
  signals.length
    ? signals
        .map(
          s =>
            `• ${s.name.padEnd(28)} [${s.score}]`
        )
        .join("\n")
    : "No suspicious indicators detected.";

  const phishStatus =
  phish.status === "UNAVAILABLE"
    ? "UNAVAILABLE (CORS)"
    : phish.detected
      ? (
          phish.verified
            ? "VERIFIED PHISHING"
            : "SUSPICIOUS ENTRY"
        )
      : "NOT FOUND";

 const threatEmoji =
  score >= 80 ? "🔴" :
  score >= 60 ? "🟠" :
  score >= 40 ? "🟡" :
  "🟢";

const recommendation =
  score >= 80
    ? "Immediate action recommended. Avoid visiting this URL."
    : score >= 60
    ? "Potential phishing activity detected."
    : score >= 40
    ? "Proceed with caution and verify legitimacy."
    : "No major threats detected.";

document.getElementById(
  "terminalOutput"
).textContent = `

╔══════════════════════════════════════════════╗
              AI CYBER URL ANALYZER
╚══════════════════════════════════════════════╝

🎯 TARGET URL
──────────────────────────────────────────────
${url}

📊 THREAT ASSESSMENT
──────────────────────────────────────────────
Risk Score    : ${score}%
Threat Level  : ${threatEmoji} ${level}
Verdict       : ${verdict}

💡 Recommendation
──────────────────────────────────────────────
${recommendation}

🔍 DETECTED SIGNALS
──────────────────────────────────────────────
${
breakdown || "No suspicious indicators detected."
}

🌐 DOMAIN INTELLIGENCE
──────────────────────────────────────────────
DNS Records      : ${dns.records.length}

HTTPS Enabled    : ${
url.startsWith("https")
  ? "YES ✓"
  : "NO ✗"
}

Threat Feed Hit  : ${
signals.some(
  s => s.name === "Live Threat Feed"
)
  ? "YES ⚠"
  : "NO ✓"
}

PhishTank        : ${phishStatus}

🛡 SYSTEM STATUS
──────────────────────────────────────────────
Analyzer State   : OPERATIONAL
Threat Feed      : SYNCHRONIZED
Detection Engine : CYBER v2.0
IOC Coverage     : ${
  FEED_CACHE.domains.length
    .toLocaleString()
} Indicators

Security Modules :
✓ URL Heuristics
✓ DNS Intelligence
✓ Brand Spoof Detection
✓ Threat Intelligence

Generated        : ${
  new Date()
    .toLocaleString()
}

══════════════════════════════════════════════
      AI Cyber URL Analyzer © 2026
══════════════════════════════════════════════
`;

document
  .getElementById("result")
  .classList.remove("hidden");
}
/* ================= ENTER KEY ================= */

document
  .getElementById(
    "urlInput"
  )
  .addEventListener(
    "keypress",
    e => {

      if (
        e.key ===
        "Enter"
      ) {

        analyze();
      }
    }
  );

/* ================= INIT ================= */

window.addEventListener(
  "load",
  async () => {

    await loadFeed();

    updateThemeIcon();

    updateHistory();

    console.log(
      "AI Cyber URL Analyzer v1.0 Loaded"
    );
  }
);

function reset() {
  // ===== INPUT FADE OUT =====
  const urlInput = document.getElementById("urlInput");
  if (urlInput) {
    urlInput.classList.add("fade-out");
    setTimeout(() => {
      urlInput.value = "";
      urlInput.classList.remove("fade-out");
    }, 200);
  }

  // ===== RESULT SECTION ANIMATION =====
  const result = document.getElementById("result");
  if (result && !result.classList.contains("hidden")) {
    result.style.transition = "all 0.3s ease";
    result.style.opacity = "0";
    result.style.transform = "translateY(10px)";

    setTimeout(() => {
      result.classList.add("hidden");
      result.style.opacity = "";
      result.style.transform = "";
    }, 300);
  }

  // ===== TERMINAL CLEAR (animated) =====
  const terminal = document.getElementById("terminalOutput");
  if (terminal) {
    terminal.style.opacity = "0";
    setTimeout(() => {
      terminal.textContent = "";
      terminal.style.opacity = "1";
    }, 200);
  }

  // ===== LOADER RESET =====
  const loader = document.getElementById("loader");
  const loaderText = document.getElementById("loaderText");
  const timer = document.getElementById("timer");

  if (loader) loader.classList.add("hidden");
  if (loaderText) loaderText.classList.add("hidden");
  if (timer) timer.textContent = "3";

  // ===== CANVAS CLEAR (smooth fade) =====
  const canvas = document.getElementById("riskGraph");
  if (canvas) {
    const ctx = canvas.getContext("2d");

    // fade-out effect before clearing
    let alpha = 1;

    function fadeCanvas() {
      if (alpha <= 0) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        return;
      }

      ctx.fillStyle = `rgba(17,17,17,${0.1})`;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      alpha -= 0.1;
      requestAnimationFrame(fadeCanvas);
    }

    fadeCanvas();
  }

  // ===== HISTORY: KEEP LOCALSTORAGE =====
  const history = document.getElementById("history");

  // DO NOT clear localStorage — only re-render UI
  const savedHistory = JSON.parse(localStorage.getItem("scanHistory") || "[]");

  if (history) {
    if (savedHistory.length === 0) {
      history.innerHTML = "No scans yet";
    } else {
      history.innerHTML = savedHistory
        .slice(-10)
        .reverse()
        .map(item => `
          <div class="history-item fade-up">
            <strong>${item.url}</strong>
            <span>Risk: ${item.risk}%</span>
          </div>
        `)
        .join("");
    }
  }

  // ===== TOAST =====
  if (typeof showToast === "function") {
    showToast("UI reset completed");
  }
}