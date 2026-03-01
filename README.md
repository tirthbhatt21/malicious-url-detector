# 🛡 AI Cyber URL Analyzer

An advanced **client-side phishing detection system** that analyzes URLs using a **trained TensorFlow.js machine learning model** combined with cybersecurity heuristics.

The entire project runs **fully in the browser** and is optimized for **static hosting on GitHub Pages**.

---

## 🚀 Live Demo

👉 https://tirthbhatt21.github.io/malicious-url-detector/

---

## 🔍 Features

✔ Real trained Machine Learning model (TensorFlow.js)  
✔ URL structure and syntax analysis  
✔ IP-based URL detection  
✔ Suspicious character frequency detection  
✔ Digit ratio and entropy analysis  
✔ Subdomain anomaly detection  
✔ URL shortening service detection  
✔ Risky extension detection (`.php`, `.exe`, etc.)  
✔ ML-based phishing probability scoring  
✔ Threat classification (LOW / MEDIUM / HIGH / CRITICAL)  
✔ Terminal-style cyber output UI  

All analysis is performed **entirely inside the browser**.

---

## 🧠 AI Model Overview

- Trained on phishing detection datasets
- Converted from Keras to TensorFlow.js
- Uses feature normalization (`scaler.json`)
- No backend inference required
- No API calls or external services

### Detection Pipeline


User URL<br>
↓
<br>Feature Extraction (Structural Signals)<br>
↓
<br>Normalization (scaler.json)<br>
↓
<br>TensorFlow.js Model<br>
↓
<br>Risk Probability<br>
↓
<br>Threat Level Classification


---

## ⚙️ Tech Stack

- HTML5
- CSS3 (Cyber / Hacker UI Theme)
- Vanilla JavaScript
- TensorFlow.js
- GitHub Pages (Static Hosting)

---

## 🔐 Why Client-Side Only?

This architecture ensures:

- 🔒 No API keys exposed
- 💰 Zero backend or server cost
- ⚡ Instant real-time analysis
- 🌍 Fully static & portable deployment
- 🚫 No CORS or network dependency
- 🧪 Ideal for portfolio & research

---

## ⚠️ Limitations

Due to the **static, client-side nature** of the project, the following are intentionally **not included**:

- ❌ WHOIS domain age lookup
- ❌ DNS reputation checks
- ❌ VirusTotal or blacklist APIs
- ❌ Real-time threat feeds
- ❌ Backend-based retraining
- ❌ Server-side validation

This tool focuses on **structural and statistical URL intelligence**, not live reputation services.

---

## 🧪 Intended Use

This project is suitable for:

- Cybersecurity portfolio demonstrations
- Frontend machine learning showcases
- Educational phishing research
- Browser-based AI experimentation
- GitHub Pages–friendly AI projects

---

## 📁 Project Structure


<br>├── index.html
<br>├── scaler.json
<br>├── /model
<br>│&nbsp;&nbsp;&nbsp;&nbsp;   ├── model.json
<br>│&nbsp;&nbsp;&nbsp;&nbsp;   └── group1-shard1of1.bin

---

## 🧑‍💻 Author

**Tirth Bhatt**  
🌐 Portfolio: https://tirth-bhatt-developer.web.app/  
💻 GitHub: https://github.com/tirthbhatt21  

---

## 📜 Disclaimer

This tool provides **probabilistic phishing detection** based on machine learning and heuristic analysis.  
It does **not guarantee absolute security**.

Always verify suspicious URLs using trusted security platforms and official sources.
