import os
import requests
import time
import base64
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Try to load local .env if present (useful for local development)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")
if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k not in os.environ:
                    os.environ[k] = v

PUBLIC_DIR = os.path.join(BASE_DIR, "public")

app = FastAPI(title="Explainable URL Security API")

# Enable CORS for local testing and cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_headers(custom_key: str = None):
    api_key = custom_key or os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="VIRUSTOTAL_API_KEY is not configured in Environment Variables. Please add it to your Vercel settings or .env file."
        )
    return {
        "x-apikey": api_key,
        "accept": "application/json"
    }

# ============================================================
# HELPER: BASIC URL FEATURES
# ============================================================

def extract_url_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    features = {
        "https": url.lower().startswith("https://"),
        "has_ip": False,
        "has_at": "@" in url,
        "has_port": False,
        "url_length": len(url),
        "domain_length": len(domain),
        "subdomains": max(domain.count(".") - 1, 0),
        "hyphens": domain.count("-"),
        "digits": sum(c.isdigit() for c in domain),
        "query_length": len(parsed.query),
        "path_length": len(parsed.path),
        "suspicious_keywords": []
    }

    # Detect IP address
    parts = domain.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(x) <= 255 for x in parts):
                features["has_ip"] = True
        except ValueError:
            pass

    # Detect explicit port
    try:
        if parsed.port is not None:
            features["has_port"] = True
    except ValueError:
        features["has_port"] = True

    # Suspicious keywords
    keywords = [
        "login", "signin", "verify", "verification", "account",
        "secure", "update", "confirm", "password", "bank",
        "payment", "wallet", "credential", "recover"
    ]
    lower_url = url.lower()
    for keyword in keywords:
        if keyword in lower_url:
            features["suspicious_keywords"].append(keyword)

    return features

# ============================================================
# STEP 1: SUBMIT URL
# ============================================================

def submit_url(url, headers):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    data = {"url": url}
    
    response = requests.post(endpoint, headers=headers, data=data, timeout=20)
    
    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code, 
            detail=f"VirusTotal submission failed: {response.text}"
        )
        
    result = response.json()
    return result["data"]["id"]

# ============================================================
# STEP 2: WAIT FOR ANALYSIS
# ============================================================

def wait_for_analysis(analysis_id, headers):
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    # Poll up to 6 times (12 seconds) to avoid Vercel serverless function timeouts
    for attempt in range(6):
        response = requests.get(endpoint, headers=headers, timeout=15)
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Analysis status polling failed: {response.text}"
            )

        data = response.json().get("data", {})
        status = data.get("attributes", {}).get("status")

        if status == "completed":
            return data
            
        time.sleep(2)

    return None

# ============================================================
# STEP 3: CREATE URL ID
# ============================================================

def create_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# ============================================================
# STEP 4: GET URL REPORT
# ============================================================

def get_url_report(url, headers):
    url_id = create_url_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    response = requests.get(endpoint, headers=headers, timeout=15)
    
    if response.status_code == 404:
        return None
    elif response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Could not retrieve URL report: {response.text}"
        )
        
    return response.json().get("data")

# ============================================================
# XAI ENGINE
# ============================================================

def generate_xai(url, report):
    attributes = report.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    analysis_results = attributes.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    total = malicious + suspicious + harmless + undetected + timeout

    if total > 0:
        risk_score = ((malicious * 1.0) + (suspicious * 0.5)) / total
    else:
        risk_score = 0
    risk_score = min(max(risk_score, 0), 1)

    features = extract_url_features(url)
    reasons = []
    positive_signals = []

    if malicious > 0:
        reasons.append(f"{malicious} security engine(s) classified the URL as malicious.")
    if suspicious > 0:
        reasons.append(f"{suspicious} security engine(s) classified the URL as suspicious.")
    if harmless > 0:
        positive_signals.append(f"{harmless} security engine(s) reported it as harmless.")

    if features["has_ip"]:
        reasons.append("The URL directly targets an IP address instead of a standard domain.")
    if features["has_at"]:
        reasons.append("The URL contains an '@' symbol, which can mislead browsers about destination host.")
    if features["has_port"]:
        reasons.append("The URL explicitly targets a non-standard network port.")
    if features["url_length"] > 100:
        reasons.append(f"Unusually long URL structure ({features['url_length']} characters).")
    if features["subdomains"] >= 3:
        reasons.append(f"Excessive subdomain depth detected ({features['subdomains']} subdomains).")
    if features["hyphens"] >= 2:
        reasons.append(f"Domain contains multiple hyphens ({features['hyphens']}), commonly used in typo-squatting.")
    if features["suspicious_keywords"]:
        keywords = ", ".join(features["suspicious_keywords"])
        reasons.append(f"Sensitive credential or banking keywords detected: {keywords}.")
    
    if not features["https"]:
        reasons.append("The URL does not use TLS/HTTPS encryption.")
    else:
        positive_signals.append("Uses TLS/HTTPS secure protocol.")

    malicious_engines = []
    suspicious_engines = []
    
    for engine_name, result in analysis_results.items():
        category = result.get("category", "").lower()
        raw_result = result.get("result", "")
        if category == "malicious":
            malicious_engines.append(f"{engine_name} → {raw_result or 'malicious'}")
        elif category == "suspicious":
            suspicious_engines.append(f"{engine_name} → {raw_result or 'suspicious'}")

    if malicious >= 3 or risk_score >= 0.20:
        classification = "MALICIOUS"
    elif malicious > 0 or suspicious >= 2:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE / CLEAN"

    if classification == "MALICIOUS":
        summary = "VirusTotal flagged high-confidence threats on this URL. Multiple security vendors classified it as malicious or dangerous."
    elif classification == "SUSPICIOUS":
        summary = "The URL triggered security warnings or heuristic anomalies, but lacks full consensus to conclusively flag as malicious."
    else:
        summary = "No active threats detected. Recognized security engines verified this URL as clean and reputable."

    return {
        "url": url,
        "classification": classification,
        "risk_score": round(risk_score * 100, 1),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "total_engines": total,
        "summary": summary,
        "features": features,
        "reasons": reasons[:8],
        "positive_signals": positive_signals[:6],
        "malicious_engines": malicious_engines[:12],
        "suspicious_engines": suspicious_engines[:12],
        "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }

# ============================================================
# API ENDPOINTS
# ============================================================

from typing import Optional

class AnalyzeRequest(BaseModel):
    url: Optional[str] = ""

@app.get("/")
@app.get("/api")
@app.get("/api/")
@app.get("/api/index.py")
def root():
    index_file = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.isfile(index_file):
        return FileResponse(index_file)
    return {"status": "ok", "message": "Explainable URL Security API is running."}

@app.api_route("/api/health", methods=["GET", "HEAD"])
@app.api_route("/api/health/", methods=["GET", "HEAD"])
@app.api_route("/health", methods=["GET", "HEAD"])
@app.api_route("/health/", methods=["GET", "HEAD"])
def health():
    has_key = bool(os.environ.get("VIRUSTOTAL_API_KEY"))
    return {
        "status": "healthy",
        "has_api_key": has_key,
        "message": "VirusTotal API key is configured" if has_key else "Missing VIRUSTOTAL_API_KEY"
    }

@app.post("/api/analyze")
@app.post("/api/analyze/")
@app.post("/analyze")
@app.post("/analyze/")
@app.post("/api/index.py")
def api_analyze_url(request: AnalyzeRequest, req: Request):
    raw_url = (request.url or "").strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    
    # Auto-prepend http if scheme is omitted
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url
        
    custom_key = req.headers.get("x-custom-api-key")
    headers = get_headers(custom_key)
    
    try:
        # Step 1: Check if VirusTotal already has an existing report (instant response)
        report = get_url_report(raw_url, headers)
        
        # Step 2: If no existing report, submit and wait briefly
        if not report:
            analysis_id = submit_url(raw_url, headers)
            wait_for_analysis(analysis_id, headers)
            report = get_url_report(raw_url, headers)
            
        if not report:
            raise HTTPException(
                status_code=504,
                detail="VirusTotal submission queued, but report is still being processed. Please retry in a few seconds."
            )
            
        # Step 3: Run XAI Engine
        result = generate_xai(raw_url, report)
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

