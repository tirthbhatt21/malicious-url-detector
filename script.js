const suspiciousKeywords = [
  "login", "verify", "secure", "account",
  "bank", "update", "free", "bonus", "crypto"
];

const knownBrands = [
  "google", "paypal", "amazon",
  "facebook", "instagram", "zudio"
];

function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

function mlConfidence(score) {
  return Math.round(sigmoid((score - 50) / 10) * 100);
}

function severity(score) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  return "Low";
}

function analyze() {
  const input = document.getElementById("urlInput");
  const error = document.getElementById("error");
  const resultBox = document.getElementById("result");

  error.textContent = "";
  resultBox.classList.add("hidden");

  const urlValue = input.value.trim();
  if (!urlValue) {
    error.textContent = "Please enter a URL";
    return;
  }

  let url;
  try {
    url = new URL(urlValue);
  } catch {
    showResult(100, ["Invalid URL format"], [
      { feature: "Invalid URL format", impact: 100 }
    ]);
    return;
  }

  let score = 0;
  const reasons = [];
  const features = [];

  function add(feature, impact, reason) {
    score += impact;
    features.push({ feature, impact });
    reasons.push(reason);
  }

  if (url.protocol !== "https:") {
    add("Non-HTTPS", 15, "URL does not use HTTPS");
  }

  if (urlValue.includes("@")) {
    add("@ Phishing Pattern", 60, "Uses '@' to disguise destination");
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)) {
    add("IP Address URL", 25, "Uses IP address instead of domain");
  }

  suspiciousKeywords.forEach(k => {
    if (urlValue.toLowerCase().includes(k)) {
      add(`Keyword: ${k}`, 8, `Contains suspicious keyword: ${k}`);
    }
  });

  knownBrands.forEach(b => {
    if (
      urlValue.toLowerCase().includes(b) &&
      !url.hostname.toLowerCase().includes(b)
    ) {
      add(`Brand Impersonation: ${b}`, 30, `Possible brand impersonation`);
    }
  });

  score = Math.min(score, 100);
  showResult(score, reasons, features);
}

function showResult(score, reasons, features) {
  const resultBox = document.getElementById("result");
  resultBox.classList.remove("hidden");

  document.getElementById("score").textContent =
    `Score: ${score}%`;

  const sev = severity(score);
  const sevEl = document.getElementById("severity");
  sevEl.textContent = sev;
  sevEl.className = `badge ${sev}`;

  document.getElementById("confidence").textContent =
    `ML Confidence: ${mlConfidence(score)}%`;

  const reasonList = document.getElementById("reasons");
  reasonList.innerHTML = "";
  reasons.forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonList.appendChild(li);
  });

  const featureBox = document.getElementById("features");
  featureBox.innerHTML = "";
  features.forEach(f => {
    const div = document.createElement("div");
    div.className = "feature";
    div.innerHTML = `
      <div>${f.feature} (+${f.impact})</div>
      <div class="bar">
        <div class="fill" style="width:${Math.min(f.impact * 2, 100)}%"></div>
      </div>
    `;
    featureBox.appendChild(div);
  });
}