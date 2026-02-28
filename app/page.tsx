"use client";

import { useState, useEffect } from "react";
import {
  analyzeURL,
  type AnalysisResult,
  type FeatureContribution,
} from "@/lib/detector";

/* =========================
   INPUT VALIDATION
========================= */

function validateUrlInput(value: string): string | null {
  if (!value.trim()) return "Please enter a URL";
  if (value.length > 2048) return "URL is too long";
  if (/\s/.test(value)) return "URL must not contain spaces";
  if (!/^https?:\/\//i.test(value))
    return "URL must start with http:// or https://";

  try {
    const parsed = new URL(value);
    if (!parsed.hostname) return "Invalid hostname";
  } catch {
    return "Invalid URL format";
  }

  return null;
}

/* =========================
   ML HELPERS (UI ONLY)
========================= */

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

function calculateConfidence(score: number): number {
  return Math.round(sigmoid((score - 50) / 10) * 100);
}

/* =========================
   COMPONENT
========================= */

export default function Home() {
  const [url, setUrl] = useState("");
  const [inputError, setInputError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);

  /* Stats Counter */
  const [scans, setScans] = useState(0);

  useEffect(() => {
    const saved = localStorage.getItem("total_scans");
    if (saved) setScans(Number(saved));
  }, []);

  const incrementScans = () => {
    const updated = scans + 1;
    setScans(updated);
    localStorage.setItem("total_scans", updated.toString());
  };

  /* =========================
     ANALYZE (CLIENT-SIDE)
  ========================= */

  const analyze = () => {
    const error = validateUrlInput(url);
    if (error) {
      setInputError(error);
      return;
    }

    const scanUrl = url;
    setUrl("");
    setInputError(null);
    setResult(null);
    setLoading(true);

    try {
      const data = analyzeURL(scanUrl);
      setResult(data);
      incrementScans();
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 to-black flex flex-col justify-between p-6">

      <div className="max-w-4xl mx-auto space-y-6 w-full">

        <h1 className="text-3xl font-bold text-white">
          🛡 Advanced URL Security Analyzer
        </h1>

        {/* INPUT */}
        <div className="space-y-2">
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setInputError(null);
              }}
              placeholder="https://example.com"
              className={`flex-1 p-3 rounded-xl bg-gray-900 border ${
                inputError ? "border-red-500" : "border-gray-700"
              } text-white`}
            />
            <button
              onClick={analyze}
              disabled={loading}
              className="bg-blue-600 px-6 py-3 rounded-xl disabled:opacity-50 text-white"
            >
              {loading ? "Scanning..." : "Analyze"}
            </button>
          </div>

          {inputError && (
            <p className="text-xs text-red-400">⚠️ {inputError}</p>
          )}
        </div>

        {/* RESULT */}
        {result && (
          <div className="bg-gray-900 p-6 rounded-xl space-y-4 text-white">
            <div className="flex gap-3 items-center flex-wrap">
              <span>
                <strong>Score:</strong> {result.score}%
              </span>

              <span
                className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  result.severity === "Critical"
                    ? "bg-red-600/30 text-red-300"
                    : result.severity === "High"
                    ? "bg-orange-600/30 text-orange-300"
                    : result.severity === "Medium"
                    ? "bg-yellow-600/30 text-yellow-300"
                    : "bg-green-600/30 text-green-300"
                }`}
              >
                {result.severity}
              </span>

              <span>
                <strong>ML Confidence:</strong>{" "}
                {calculateConfidence(result.score)}%
              </span>
            </div>

            <div>
              <h3 className="font-semibold text-sm mb-1">
                📌 Detection Reasons
              </h3>
              <ul className="list-disc pl-5 text-xs space-y-1">
                {result.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="font-semibold text-sm mb-1">
                🔍 Feature Importance
              </h3>
              {result.featureContributions.map(
                (f: FeatureContribution, i) => (
                  <div key={i} className="mb-2 text-xs">
                    <div className="flex justify-between">
                      <span>{f.feature}</span>
                      <span>+{f.impact}</span>
                    </div>
                    <div className="h-2 bg-gray-700 rounded">
                      <div
                        className="h-2 bg-red-500 rounded"
                        style={{
                          width: `${Math.min(
                            f.impact * 2,
                            100
                          )}%`,
                        }}
                      />
                    </div>
                  </div>
                )
              )}
            </div>
          </div>
        )}
      </div>

      {/* ELITE FOOTER */}
      <footer className="mt-20 relative">
        <div className="h-[3px] w-full bg-gradient-to-r from-cyan-400 via-purple-500 to-pink-500 animate-pulse shadow-[0_0_15px_rgba(139,92,246,0.6)]" />

        <div className="backdrop-blur-xl bg-white/5 border-t border-white/10">
          <div className="max-w-6xl mx-auto px-6 py-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-10 text-sm text-gray-300">

            <div>
              <h2 className="text-white font-bold text-lg mb-2">
                🛡 Advanced URL Security Analyzer
              </h2>
              <p className="text-xs text-gray-400">
                Client-side URL threat analysis using phishing
                heuristics, brand impersonation detection, and
                ML-style confidence scoring.
              </p>
            </div>

            <div>
              <h3 className="text-white font-semibold mb-3">
                Detection Engine
              </h3>
              <ul className="space-y-2 text-xs">
                <li>⚡ Phishing pattern detection</li>
                <li>🎭 Brand impersonation checks</li>
                <li>🔐 HTTPS & protocol validation</li>
                <li>🤖 ML-style confidence scoring</li>
              </ul>
            </div>

            <div>
              <h3 className="text-white font-semibold mb-3">
                Connect
              </h3>
              <ul className="space-y-3 text-xs">
                <li>
                  🌐{" "}
                  <a
                    href="https://tirth-bhatt-developer.web.app/"
                    target="_blank"
                    className="hover:text-white transition hover:underline"
                  >
                    Portfolio
                  </a>
                </li>
                <li>
                  💻{" "}
                  <a
                    href="https://github.com/tirthbhatt21"
                    target="_blank"
                    className="hover:text-white transition hover:underline"
                  >
                    GitHub
                  </a>
                </li>
              </ul>
            </div>

            <div>
              <h3 className="text-white font-semibold mb-3">
                Live Stats
              </h3>
              <p className="flex justify-between text-xs">
                <span>📊 Total Scans</span>
                <span className="text-white font-semibold">
                  {scans}
                </span>
              </p>
            </div>
          </div>

          <div className="border-t border-white/10 text-center py-6 text-xs text-gray-400">
            🧑‍💻 Made by{" "}
            <span className="text-white font-semibold">
              Tirth Bhatt
            </span>{" "}
            — © {new Date().getFullYear()}
          </div>
        </div>
      </footer>
    </main>
  );
}