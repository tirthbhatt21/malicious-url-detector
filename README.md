# 🛡 AI Cyber URL Analyzer

An advanced **client-side phishing detection system** that combines **cybersecurity heuristics**, **threat intelligence feeds**, and **URL analysis** to identify malicious and suspicious websites.

The entire project runs **fully in the browser** and is optimized for **static hosting on GitHub Pages**.

---

## 🚀 Live Demo

👉 https://tirthbhatt21.github.io/malicious-url-detector/

---

## 🔍 Features

✔ Threat Intelligence Feed (193K+ IOC entries) <br>
✔ URL Username Obfuscation Detection (`brand.com@malicious.site`) <br>
✔ Brand Impersonation Detection <br>
✔ Suspicious Domain Pattern Analysis <br>
✔ IP-based URL Detection <br>
✔ HTTPS Verification <br>
✔ Entropy-based Domain Analysis <br>
✔ DNS Intelligence Lookup <br>
✔ Subdomain Anomaly Detection <br>
✔ Suspicious TLD Detection (`.top`, `.xyz`, `.cyou`, etc.) <br>
✔ Query Parameter Analysis <br>
✔ Real-time Risk Scoring Engine <br> 
✔ Threat Classification (LOW / MEDIUM / HIGH / CRITICAL) <br>
✔ Terminal-style Cybersecurity Report UI

All analysis is performed **entirely inside the browser**.

---

## 🧠 Detection Engine Overview

The analyzer uses a **hybrid heuristic approach** inspired by modern phishing detection systems.

### Detection Pipeline

User URL <br>
↓ <br>
URL Parsing & Normalization <br>
↓ <br>
Threat Intelligence Feed Check <br>
↓ <br>
Heuristic Analysis <br>
↓ <br>
DNS Intelligence <br>
↓ <br>
Risk Scoring Engine <br>
↓ <br>
Threat Classification

---

## ⚙️ Tech Stack

* HTML5
* CSS3 (Cyber / Hacker UI Theme)
* Vanilla JavaScript
* JSON Threat Intelligence Feed
* GitHub Pages (Static Hosting)

---

## 🔐 Why Client-Side Only?

This architecture ensures:

* 🔒 No API keys exposed
* 💰 Zero backend or server cost
* ⚡ Instant real-time analysis
* 🌍 Fully static & portable deployment
* 🚫 No CORS or network dependency
* 🧪 Ideal for portfolio & research

---

## ⚠️ Limitations

Due to the **static, client-side nature** of the project, the following are intentionally **not included**:

* ❌ WHOIS domain age lookup
* ❌ VirusTotal API integration
* ❌ Live blacklist APIs
* ❌ Server-side validation
* ❌ Dynamic threat intelligence APIs
* ❌ Backend-based model training

This tool focuses on **heuristic and threat intelligence analysis**, not live reputation services.

---

## 📁 Project Structure

```text
├── index.html
├── main.css
├── main.js
├── feed.json
├── link.ico
└── README.md
```

---

## 🛡 Detection Capabilities

The analyzer detects:

* Brand impersonation attacks
* Username obfuscation attacks
* Threat feed matches
* Suspicious domains
* Risky TLDs
* IP-address URLs
* URL entropy anomalies
* HTTPS misuse
* Query abuse patterns

---

## 👨‍💻 Author

**Tirth Bhatt**

🌐 Portfolio: https://tirth-bhatt-developer.web.app/
💻 GitHub: https://github.com/tirthbhatt21

---

## 📜 Disclaimer

This tool is intended for **educational and research purposes only**.

No personal data is collected or transmitted. Analyses are based on heuristic methods and publicly available threat intelligence.
