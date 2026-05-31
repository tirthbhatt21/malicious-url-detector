# 🛡 AI Cyber URL Analyzer

An advanced **client-side phishing detection system** that analyzes URLs using a **multi-layer rule engine**, threat intelligence feeds, DNS checks, and cybersecurity heuristics.

The entire system runs **fully in the browser** and is designed for **static hosting on GitHub Pages**.

---

## 🚀 Live Demo

👉 https://tirthbhatt21.github.io/malicious-url-detector/

---

## 🔍 Features

✔ Live malicious domain feed (GitHub-hosted JSON intelligence list)  
✔ Rule-based phishing detection engine  
✔ DNS resolution anomaly checks (Google DNS API)  
✔ PhishTank integration for known phishing URLs  
✔ URL entropy analysis (randomness detection)  
✔ Brand impersonation detection (Google, PayPal, Amazon, etc.)  
✔ Levenshtein distance-based spoof detection  
✔ Suspicious keyword detection (login, verify, password, bank, etc.)  
✔ URL shortener detection (bit.ly, tinyurl)  
✔ Risky TLD detection (.xyz, .top, .site, etc.)  
✔ Browser fingerprint collection (non-invasive metadata only)  
✔ Risk scoring engine (0–100%)  
✔ Cyber-themed terminal output UI  
✔ Risk visualization graph (Canvas-based)  
✔ Scan history tracking (session-based)

---

## 🧠 Detection Architecture

User URL Input  
↓  
URL Parsing & Normalization  
↓  
Rule Engine (keywords, brand spoofing, structure checks)  
↓  
Threat Intelligence Feed Check  
↓  
DNS Resolution Check (Google DNS)  
↓  
PhishTank Lookup  
↓  
Entropy + Heuristic Scoring  
↓  
Final Risk Score (0–100)  
↓  
Graphical Visualization + Terminal Output


---

## ⚙️ Tech Stack

- HTML5
- CSS3 (Cyberpunk / terminal UI theme)
- Vanilla JavaScript
- Canvas API (risk graph visualization)
- Google DNS API
- GitHub Pages (static hosting)
- GitHub (version control & hosting)

---

## 🔐 Why Client-Side Only?

- No backend required  
- Zero server cost  
- Instant analysis  
- Fully static deployment  
- No API keys needed  
- Easy GitHub Pages hosting  
- Ideal for cybersecurity demos  

---

## ⚠️ Limitations

This tool does NOT include:

- WHOIS domain age lookup  
- VirusTotal or commercial threat APIs  
- Real-time malware sandboxing  
- Backend machine learning inference  
- Continuous threat intelligence streaming  

It focuses on **heuristic + DNS + reputation-based browser intelligence**.

---

## 🧪 Intended Use

- Cybersecurity learning projects  
- Frontend security tool demos  
- Phishing research experiments  
- Portfolio projects  
- GitHub Pages deployments  

---

## 🧑‍💻 Author

**Tirth Bhatt**  
🌐 Portfolio: https://tirthbhatt-developer.web.app/  
💻 GitHub: https://github.com/tirthbhatt21  

---

## 📜 Disclaimer

This tool provides **probabilistic phishing risk scoring** using heuristics and public signals.
