/* =========================
   TYPES
========================= */

export type Severity = "Low" | "Medium" | "High" | "Critical";

export interface FeatureContribution {
  feature: string;
  impact: number;
}

export interface AnalysisResult {
  isMalicious: boolean;
  score: number; // 0–100
  reasons: string[];

  // ML-style outputs
  mlConfidence: number;
  severity: Severity;

  // Explainability
  featureContributions: FeatureContribution[];
}

/* =========================
   CONSTANTS
========================= */

const suspiciousKeywords = [
  "login",
  "verify",
  "secure",
  "account",
  "bank",
  "update",
  "free",
  "bonus",
  "crypto",
];

const knownBrands = [
  "google",
  "paypal",
  "amazon",
  "facebook",
  "instagram",
  "zudio",
];

/* =========================
   ML HELPERS
========================= */

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

function calculateMLConfidence(score: number): number {
  return Math.round(sigmoid((score - 50) / 10) * 100);
}

function getSeverity(score: number): Severity {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  return "Low";
}

/* =========================
   MAIN ANALYZER (CLIENT-SIDE)
========================= */

export function analyzeURL(inputUrl: string): AnalysisResult {
  let score = 0;
  const reasons: string[] = [];
  const featureContributions: FeatureContribution[] = [];

  const addImpact = (feature: string, impact: number) => {
    score += impact;
    featureContributions.push({ feature, impact });
  };

  let url: URL;

  try {
    url = new URL(inputUrl);
  } catch {
    return {
      isMalicious: true,
      score: 100,
      reasons: ["Invalid URL format"],
      mlConfidence: 99,
      severity: "Critical",
      featureContributions: [
        { feature: "Invalid URL format", impact: 100 },
      ],
    };
  }

  /* =========================
     RULE CHECKS
  ========================= */

  if (url.protocol !== "https:") {
    addImpact("Non-HTTPS Protocol", 15);
    reasons.push("URL does not use HTTPS");
  }

  if (inputUrl.includes("@")) {
    addImpact("@ Symbol Phishing Pattern", 60);
    reasons.push(
      "Uses '@' symbol to disguise real destination domain"
    );
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)) {
    addImpact("IP Address Used Instead of Domain", 25);
    reasons.push("Uses IP address instead of domain name");
  }

  suspiciousKeywords.forEach((word) => {
    if (inputUrl.toLowerCase().includes(word)) {
      addImpact(`Suspicious Keyword: ${word}`, 8);
      reasons.push(`Contains suspicious keyword: ${word}`);
    }
  });

  knownBrands.forEach((brand) => {
    if (
      inputUrl.toLowerCase().includes(brand) &&
      !url.hostname.toLowerCase().includes(brand)
    ) {
      addImpact(`Brand Impersonation: ${brand}`, 30);
      reasons.push(`Possible brand impersonation: ${brand}`);
    }
  });

  /* =========================
     FINAL OUTPUT
  ========================= */

  const normalizedScore = Math.min(score, 100);

  return {
    isMalicious: normalizedScore >= 40,
    score: normalizedScore,
    reasons,
    mlConfidence: calculateMLConfidence(normalizedScore),
    severity: getSeverity(normalizedScore),
    featureContributions: featureContributions.sort(
      (a, b) => b.impact - a.impact
    ),
  };
}