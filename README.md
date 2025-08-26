<h1 align="center">
  <a><img src="https://github.com/nivlevyy/UBE-Ublock_Enhance/blob/main/image/UBE-logo.jpeg" width="300"></a>
<br>
AI-Powered Phishing Detection Extension
<br>
</h1>

## Overview:

This project is an AI-powered phishing detection system integrated directly into the **uBlock Origin** browser extension. It enhances traditional ad-blockers by enabling real-time detection of phishing threats using machine learning. The extension analyzes various website elements including URLs, domain metadata, HTML structure, and JavaScript behavior to identify suspicious activity.

Unlike static blacklists, UBE adds a dynamic intelligence layer. The extension runs a local ML model for instant decisions (privacy-preserving) and then reports suspected URLs in batches to a backend server. The server re-validates with a Python pipeline, writes high-confidence results to a database, and then publish a living phishing list into the extension static block lists. turning “static” blocklists into a dynamically updating feed shared by all users at once, so future hits are blocked before the model even needs to run.

---

## Architecture & Detection Pipeline:

### Client (Browser Extension)
Hooks into navigation events and page activity.
Checks extended static lists first (uBO + optional dynamic list).
If a URL isn’t covered by those static lists, a local model (Web Worker) scores it using staged features.
Visual indicators (icon/badge/banner/notification) warn users in real time.
URLs that look malicious are added to a small local batch queue and periodically flushed to the server with a unique user API KEY.

### Server (Validation + Daily Routine)
Receives batched candidates from many clients.
Re-extracts features (URL, domain/WHOIS/reputation, optional DOM/JS) and scores with a Python model.
Only high-confidence results (by probability threshold) are inserted into the DB.
Optionally publishes a simple newline-separated list to a GitHub repo for easy consumption by uBO or other tools.

Why hybrid (local AI + shared list)?
Static lists alone lag behind new campaigns; cloud-only systems trade away privacy and add latency. UBE runs a light local MODEL first for privacy and speed, then shares intelligence centrally so the broader user base benefits quickly.


### Data flow (end-to-end):
1.  User navigates → extension gathers fast features and runs the local model.
2. If the page looks phishy, its URL is queued client-side.
3. Queue flushes when it reaches a small batch size (e.g., 10) or after a short timer.
4. Server receives the data with a per-user API key and deduplicates URLs into a daily buffer.
5. A daily routine runs: full extraction → model scoring → thresholded inserts into phish_db.
6. The server publishes an updated plain-text list to GitHub (for uBO to subscribe to).

---

## Core Features:

### The ML Model Core Stages:
- **Stage 1**: URL lexical feature analysis .
- **Stage 2**: Domain reputation, WHOIS-based features and more.
- **Stage 3**: HTML and JavaScript structural and behavioral analysis.

### Browser Integration:
- Built as an extension for **Mozilla Firefox**.
- Hooks into browser events to inspect webpages in real time.
- Enhances uBlock Origin's static list with dynamic, intelligent detection.

### Privacy and Performance:
- All detection is performed locally.
- No sensitive data is sent to external servers.
- Optional cloud-based backend for list/model updates (NAS).

---

## Technologies Used:
- **Languages**: JavaScript, Python
- **Machine Learning**: TensorFlow.js, Scikit-learn
- **Frontend**: HTML, CSS, JS (WebExtension APIs)
- **Backend (Optional)**: NAS server for blacklist/model update management
- **Tools**: BeautifulSoup, Whois, Regex, uBlock Origin
---
## Repository Layout (key parts):
- backend/app/server.py — Flask API (/get_api_key, /, /submit_new_phish_urls).
- backend/app/data_handler.py — feature orchestration, validation (label, proba), thresholded DB inserts, daily routine, Git publishing, API-key issuance
- backend/app/models.py — SQLAlchemy models + DB bootstrap
- backend/app/local_extract_all_stages/ — Stage 1/2/3 extractors
- extension/ — all WebExtension code (core, analysis, processing, uBO hooks, worker, assets)

---

## Installation & Usage:

### Running the Server (local)
#### Prereqs
-Python 3.10+
-Virtualenv + dependencies installed (requirements.txt)

**Setup**
```bash
python -m venv .venv
source .venv/bin/activate           # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
#### Recommended local flags:

**Windows PowerShell (local ide terminal is prefered )**
```powershell
$env:DEBUG="1"
$env:UBE_SKIP_PUBLISH="1"
python -m backend.app.server
```

**Linux/macOS(local ide terminal is prefered )**
```bash
export DEBUG=1              # verbose model logs + dev Git behavior
export UBE_SKIP_PUBLISH=1   # don't push to Git during local tests
python -m backend.app.server
```

### Running the Extension (local):
1. Load this extension unpacked:
  - Firefox: about:debugging#/runtime/this-firefox → “Load Temporary Add-on…” → select *manifest.json* from the UBE_final_project_ublock_enhanced/extension
  /uBlock-UBE.firefox.final.
2.click on the ublock  icon (in the top right screen you will have the extension icon)
3.click on the AI button in the bottom left of the pop up window (to activate the ML model to analyze any further pages while browsing)
4.Browse normally, the extension will flag phishing sites in RED and a safe ones in GREEN.

---
Endpoints (quick test by hand)

1) Issue an API key (no auth required)
```bash
curl -s http://localhost:8000/get_api_key
# → {"api_key":"<hex>"}
```

2) Status without a key → 401
```bash
curl -i http://localhost:8000/
```

3) Status with a key → 200
```bash
API_KEY="<paste-from-step-1>"
curl -s -H "X-API-KEY: $API_KEY" http://localhost:8000/
```
4) Returns today's submissions
```bash
API_KEY="<paste-from-step-1>"
curl -s -H "X-API-KEY: $API_KEY" http://localhost:8000/debug/daily_submissions
#gets the daily submitions 
```

5) Returns recent URLs in the database
```bash
API_KEY="<paste-from-step-1>"
curl -s -H "X-API-KEY: $API_KEY" http://localhost:8000/debug/db_recent
#gets the urls that are current in the data base  
```

6) Run full update pipeline :
```bash
API_KEY="<paste-from-step-1>"
curl -s -X POST ‎-H‎ "X-API-KEY: $API_KEY" http://localhost:8000/debug/run_daily
#Run full pipeline including validating the data sent and updating the phishing blocklist in git then when other user's
#activating the extension the extension will block this phishy sites.
```
---

## project pictures:

<h2 align="center">
<strong align="center">UBE Popup:</strong><br>
    <a><img src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/extension.jpeg" width="300"></a>
</h2>

<h1 align="center">
<br>
Analysis: Unsafe
<br>
</h1>

<table align="center" role="presentation" width="100%" border="0" cellpadding="0" cellspacing="0">
  <colgroup>
    <col width="50%">
    <col width="50%">
  </colgroup>
  <tr>
    <th align="center">while browsing (outer)</th>
    <th align="center">when clicked (inner)</th>
  </tr>
  <tr>
    <td align="center" valign="top">
      <a href="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/phishing%20%28red%20indicator%29.jpeg?raw=1">
        <img
          src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/phishing%20%28red%20indicator%29.jpeg?raw=1"
          alt="Unsafe badge while browsing (red indicator)"
          height="500">
      </a>
    </td>
    <td align="center" valign="top">
      <a href="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/phishing.jpeg?raw=1">
        <img
          src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/phishing.jpeg?raw=1"
          alt="uBlock Origin popup with 'Unsafe' banner"
          height="420">
      </a>
    </td>
  </tr>
</table>

<h1 align="center">
<br>
Analysis: safe
<br>
</h1>

<table align="center" role="presentation" width="100%" border="0" cellpadding="0" cellspacing="0">
  <colgroup>
    <col width="50%">
    <col width="50%">
  </colgroup>
  <tr>
    <th align="center">while browsing (outer)</th>
    <th align="center">when clicked (inner)</th>
  </tr>
  <tr>
    <td align="center" valign="top">
      <a href="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/safe(green%20indicator) .jpeg?raw=1">
        <img
          src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/safe(green%20indicator) .jpeg?raw=1"
          alt="Unsafe badge while browsing (red indicator)"
          height="800">
      </a>
    </td>
    <td align="center" valign="top">
      <a href="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/safe.jpeg?raw=1">
        <img
          src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/safe.jpeg?raw=1"
          alt="uBlock Origin popup with 'Unsafe' banner"
          height="420">
      </a>
    </td>
  </tr>
</table>

<h1 align="center">
<br>
Full Analysis View Button & Analysis Screen:
<br>
</h1>

<table align="center" role="presentation" width="100%" border="0" cellpadding="0" cellspacing="0">
  <colgroup>
    <col width="50%">
    <col width="50%">
  </colgroup>
  <tr>
    
  </tr>
  <tr>
    <td align="center" valign="top">
      <a href="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/UBE_analysis button.jpeg?raw=1">
        <img
          src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/UBE_analysis button.jpeg?raw=1"
          alt="Unsafe badge while browsing (red indicator)"
          height="250">
      </a>
    </td>
    <td align="center" valign="top">
      <a href="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/UBE_analysis.jpeg?raw=1">
        <img
          src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/UBE_analysis.jpeg?raw=1"
          alt="uBlock Origin popup with 'Unsafe' banner"
          height="700">
      </a>
    </td>
  </tr>
</table>


<h2 align="center">
<strong align="center">uBlock Origin Block Screen (after phishing confirmation):</strong><br>
    <a><img src="https://github.com/nivlevyy/UBE_final_project_ublock_enhanced/blob/main/image/live blocking.jpeg" width="1000"></a>
</h2>

---
## Future Enhancements:
- Visual/NLP phishing detection (Stage 4)
- Advanced whitelist/blacklist learning
- User feedback mechanism for training data
- Dashboard for managing blocked threats

## License:
This project is licensed under the GPL-3.0 License. See **LICENSE** for details.
