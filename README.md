# Phishing URL Detector — Explainable URL Threat Intelligence Dashboard

A modern, fast, and explainable URL threat detection platform powered by **VirusTotal API v3**, **Explainable AI (XAI)** heuristic analysis, and a sleek cyberpunk cybersecurity dashboard.

Designed for seamless deployment on **Vercel** as a Python Serverless API with an interactive frontend.

---

## ✨ Features

- **🛡️ 70+ Vendor Multi-Engine Consensus**: Aggregates security verdicts from vendors (Kaspersky, Google Safe Browsing, BitDefender, Sophos, etc.).
- **💡 Explainable AI (XAI) Reasoning**: Plain-English explanations of *why* a URL was marked clean, suspicious, or malicious.
- **💾 Saved Links Ledger ("Keep the link")**: All analyzed URLs are automatically saved in local storage. Click any past link in the ledger to instantly view its full scan report without re-querying!
- **📊 Real-time Risk Score Gauge**: Animated radial gauge calculating weighted risk score based on vendor consensus and suspicious indicators.
- **🔬 Lexical & Domain Anatomy Inspector**: Detects IP destinations, `@` symbol credential obfuscation, custom network ports, subdomain depth, excessive hyphens, and phishing keywords.
- **⚡ Instant Cache Optimization**: Queries existing VirusTotal reports first for sub-second responses, falling back to fresh analysis submissions if unknown.

---

## 📁 Project Structure

```
r3/
├── api/
│   └── index.py            # FastAPI serverless application
├── public/
│   ├── index.html          # Interactive cybersecurity dashboard
│   ├── style.css           # High-end dark theme & animations
│   └── app.js              # Client logic & localStorage ledger
├── .env                    # Local environment variables (git-ignored)
├── .env.example            # Sample environment variables template
├── .gitignore              # Git ignore rules
├── requirements.txt        # Python dependencies for Vercel
├── vercel.json             # Vercel routing and serverless build configuration
└── README.md               # Documentation
```

---

## 🚀 How to Deploy to Vercel

### Step 1: Push to GitHub
1. Open terminal in this folder:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Phishing URL Detector dashboard"
   git branch -M main
   ```
2. Create a new repository on your GitHub account.
3. Link your remote and push:
   ```bash
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git push -u origin main
   ```

### Step 2: Deploy on Vercel
1. Go to [vercel.com](https://vercel.com) and log in.
2. Click **Add New...** → **Project**.
3. Import your GitHub repository.
4. Under **Environment Variables**, add:
   - **Key**: `VIRUSTOTAL_API_KEY`
   - **Value**: `your_virustotal_api_key`
5. Click **Deploy**.

Your dashboard and API will be live at `https://your-project.vercel.app`!

---

## 💻 Local Development (Optional)

If you wish to test or run locally:

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Make sure `.env` contains your key:
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

3. Start the local development server:
   ```bash
   python -m uvicorn api.index:app --reload
   ```

4. Open your browser at:
   ```
   http://localhost:8000
   ```

---

## 🔌 API Reference

### POST `/api/analyze`
Analyze any target URL.

**Request:**
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "url": "https://example.com",
  "classification": "SAFE / CLEAN",
  "risk_score": 0.0,
  "malicious": 0,
  "suspicious": 0,
  "harmless": 68,
  "undetected": 22,
  "total_engines": 90,
  "summary": "No active threats detected. Recognized security engines verified this URL as clean and reputable.",
  "features": { ... },
  "reasons": [],
  "positive_signals": ["Uses TLS/HTTPS secure protocol.", "68 security engine(s) reported it as harmless."],
  "malicious_engines": [],
  "suspicious_engines": []
}
```

### GET `/api/health`
Check whether the API key is active and backend is responding.
