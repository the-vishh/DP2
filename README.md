# PhishGuard AI - Comprehensive Technical Documentation

This document is the canonical, code-accurate guide for the current `DP2` repository.
It covers architecture, setup, runtime behavior, APIs, data flow, testing, troubleshooting,
and known limitations based on what is actually implemented in source.

---

## Table of Contents

1. [Project Summary](#project-summary)
2. [Current Detection Scope](#current-detection-scope)
3. [System Architecture](#system-architecture)
4. [Repository Structure](#repository-structure)
5. [Chrome Extension Layer](#chrome-extension-layer)
6. [Rust API Gateway Layer](#rust-api-gateway-layer)
7. [ML Service Layer (FastAPI)](#ml-service-layer-fastapi)
8. [ML Model Layer](#ml-model-layer)
9. [Security and Privacy Model](#security-and-privacy-model)
10. [Database and Analytics Model](#database-and-analytics-model)
11. [Configuration Reference](#configuration-reference)
12. [End-to-End Data Flow](#end-to-end-data-flow)
13. [Local Setup (Windows / Git Bash)](#local-setup-windows--git-bash)
14. [Running the Full Stack](#running-the-full-stack)
15. [Testing with Dummy Payloads](#testing-with-dummy-payloads)
16. [API Reference](#api-reference)
17. [Scripts and Utilities in Root](#scripts-and-utilities-in-root)
18. [Known Mismatches and Limitations](#known-mismatches-and-limitations)
19. [Troubleshooting Guide](#troubleshooting-guide)
20. [Recommended Next Cleanup Steps](#recommended-next-cleanup-steps)

---

## Project Summary

PhishGuard AI is a multi-layer phishing defense system made of:

- A Chrome Extension (Manifest V3) for client-side behavior and page analysis
- A Rust API gateway (Actix Web) for auth, routing, caching, analytics writes, and service health
- A Python FastAPI ML inference service for URL classification
- A feature/model package under `ml-model` used by the inference service
- A SQLite analytics store (with optional Redis cache)

The extension performs in-browser detections and can call backend ML checks.
The dashboard and popup consume backend analytics and health telemetry.

---

## Current Detection Scope

As currently implemented in `content_script.js`, the active high-level engines are:

- Phase 1: Visual and DOM spoofing checks
- Phase 2: NLP urgency/social engineering heuristics
- Phase 3: Homograph/punycode URL checks
- Phase 4: Obfuscation and anti-evasion checks

Important current-state note:

- The active Web3 interception engine has been removed from runtime detection flow.
- A legacy test file `test-payloads/4_web3_drainer.html` may still exist for historical testing,
  but there is no active Phase 5 runtime engine in `content_script.js`.

---

## System Architecture

```text
Browser Tab
  -> content_script.js / fingerprint_detector.js / network_monitor.js
  -> background.js (service worker)
  -> Rust API Gateway (http://localhost:8080)
       -> Redis cache (optional)
       -> SQLite (backend/phishguard.db)
       -> Python ML service (ML_SERVICE_URL, typically http://127.0.0.1:8888 in current .env)
            -> ml-model/deployment + ml-model/features + model pickle files
```

Control-plane token flow:

- Extension bootstraps token using `/api/control-plane/bootstrap`
- Background stores token in `chrome.storage.local` (`localApiToken`)
- Protected API calls include `X-PhishGuard-Token`
- 401 triggers background token rotation/refresh logic

---

## Repository Structure

```text
DP2/
  manifest.json
  background.js
  content_script.js
  fingerprint_detector.js
  network_monitor.js
  popup-enhanced.html
  popup-enhanced.css
  popup-enhanced.js
  dashboard.html
  app.js
  style.css
  chart.min.js
  index.html

  backend/
    .env
    .env.example
    Cargo.toml
    migrations/
    src/
      main.rs
      handlers/
      middleware/
      services/
      db/
      models/
      crypto/

  ml-service/
    app.py
    requirements.txt
    README.md

  ml-model/
    requirements.txt
    README.md
    deployment/
    features/
    models/

  test-payloads/
    index.html
    1_visual_spoof.html
    2_nlp_spear_phishing.html
    3_clickjack_obfuscation.html
    4_web3_drainer.html
```

---

## Chrome Extension Layer

### 1) Manifest and injection

File: `manifest.json`

- Manifest version: 3
- Default popup: `popup-enhanced.html`
- Background service worker: `background.js` (module)
- Content scripts (all URLs, document_start, all frames):
  - `content_script.js`
  - `fingerprint_detector.js`
  - `network_monitor.js`
- Permissions:
  - `tabs`
  - `activeTab`
  - `storage`
  - `webRequest`
  - `notifications`

### 2) Background service worker

File: `background.js`

Core responsibilities:

- Bootstraps and rotates control-plane API tokens
- Proxies ML URL checks via backend (`/api/check-url`)
- Logs user activity to analytics endpoint (`/api/user/{user_id}/activity`)
- Tracks blacklists and local threat telemetry
- Handles cross-script messages and tab-close command (`closeCurrentTab`)
- Persists extension runtime state to storage every 10 seconds

Configured backend URLs:

- `ML_API_URL = http://localhost:8080/api/check-url`
- `ANALYTICS_API_URL = http://localhost:8080/api/user`
- `CONTROL_PLANE_BOOTSTRAP_URL = http://localhost:8080/api/control-plane/bootstrap`
- `CONTROL_PLANE_ROTATE_URL = http://localhost:8080/api/control-plane/rotate`

### 3) Content behavioral engine

File: `content_script.js`

Core detections include:

- Immediate password prompt timing
- Rapid redirects
- Cross-origin credential form submission
- Suspicious form params
- Suspicious input focus timing
- Clipboard abuse
- Popup abuse and auto-submit checks

Overlay behavior:

- Shows full-screen warning overlays for high-risk events
- Safety Abort button requests immediate tab close via background action `closeCurrentTab`

Additional phase engines (active):

- Visual brand spoofing and hollow DOM checks
- NLP urgency and financial coercion checks
- Homograph/punycode checks
- Script obfuscation/eval bomb checks

### 4) Fingerprinting monitor

File: `fingerprint_detector.js`

Monitors and scores:

- Canvas fingerprinting
- WebGL parameter probing
- Audio fingerprinting
- Font probing
- Storage abuse
- Navigator/screen/battery fingerprint vectors

### 5) Network monitor

File: `network_monitor.js`

Monitors:

- Large POST uploads
- C2-style URL and port patterns
- WebSocket volume
- DNS-over-HTTPS endpoints
- suspicious request headers
- Cross-origin request behavior

### 6) Popup UX

Files:

- `popup-enhanced.html`
- `popup-enhanced.js`
- `popup-enhanced.css`

Behavior:

- Shows quick status, blocked count, and a short recent activity feed
- Polls backend health and user analytics periodically
- Opens full dashboard tab (`dashboard.html`)

### 7) Dashboard UX

Files:

- `dashboard.html`
- `app.js`
- `style.css`

Features:

- Multi-page navigation inside one dashboard document:
  - Dashboard
  - History
  - Analytics
  - Settings
  - Help
- Calls backend global stats, health, and user analytics
- Uses control-plane token from background
- Auto-refresh loop currently set to every 2 seconds in `app.js`

---

## Rust API Gateway Layer

Directory: `backend/`

Main file: `backend/src/main.rs`

Tech stack:

- Actix Web
- Diesel + SQLite + r2d2 pooling
- Optional Redis cache
- Reqwest ML client

Startup behavior:

- Loads config from `.env` (or defaults)
- Initializes cache service (degrades gracefully if Redis unavailable)
- Initializes ML client
- Attempts GeoIP database load (optional)
- Opens DB pool (falls back to in-memory DB if file DB unavailable)
- Creates/ensures control-plane credential storage

Middleware chain:

- Logger
- Compression
- Rate limiting middleware
- API auth middleware

Routing:

- `/` and `/health` are public
- `/api/*` routes are under auth middleware (with bootstrap exception)

---

## ML Service Layer (FastAPI)

Directory: `ml-service/`

Main file: `ml-service/app.py`

Startup behavior:

- Adds `ml-model/deployment` and `ml-model/features` to Python path
- Loads models via `ModelCache`
- Creates `ProductionFeatureExtractor(timeout=3)`
- If model load fails, health endpoint reports unhealthy and predictions return 503/500 paths

Endpoint behavior:

- `GET /` basic metadata
- `GET /health` model readiness
- `POST /api/predict` URL classification with sensitivity mode

Sensitivity thresholds:

- conservative: 0.80
- balanced: 0.50
- aggressive: 0.30

Threat level buckets (confidence-based):

- `>= 0.9` -> CRITICAL
- `>= 0.7` -> HIGH
- `>= 0.5` -> MEDIUM
- `>= 0.3` -> LOW
- `< 0.3` -> SAFE

Important port reality:

- `app.py` prints port 8000 in startup text
- Actual `uvicorn.run(...)` in the same file uses port 8888

---

## ML Model Layer

Directory: `ml-model/`

Relevant runtime pieces:

- `deployment/model_cache.py`
  - Loads `lightgbm_159features.pkl` and `xgboost_159features.pkl`
  - Warms models with dummy inference
  - Ensemble by average probability
- `deployment/production_feature_extractor.py`
  - Uses `UltimateFeatureIntegrator`
  - Produces 159-feature vector
- `features/ultimate_integrator.py`
  - Composes URL, SSL, DNS, content, behavioral, and network extractors

Current model artifacts present in repository:

- `ml-model/models/lightgbm_159features.pkl`
- `ml-model/models/xgboost_159features.pkl`

---

## Security and Privacy Model

1. API access control

- Protected endpoints require `X-PhishGuard-Token`
- Tokens are bootstrapped and rotated via control-plane endpoints
- Bootstrap also validates Origin (`chrome-extension://<extension_id>`)

2. Client-side URL encryption for analytics activity

- Background derives key from user ID hash (Web Crypto)
- URL data encrypted with AES-GCM before activity logging
- Hashes and nonce are sent to backend for indexing/replay checks

3. Replay control

- Analytics activity endpoint validates nonce and client timestamp window

---

## Database and Analytics Model

Primary local DB:

- `backend/phishguard.db` (SQLite)

Analytics schema source:

- `backend/migrations/2025-10-10-000001_create_user_analytics/up_sqlite_complete.sql`

Key tables used by current backend analytics logic:

- `users`
- `user_activity`
- `user_threat_stats`
- `user_threat_sources`
- `control_plane_credentials` (ensured by service-layer helper)

Legacy SQL files at root:

- `database-schema.sql`
- `setup_database.sql`

These include PostgreSQL-oriented definitions and are not the primary path for current SQLite runtime.

---

## Configuration Reference

### Extension constants (`background.js`)

- `ML_API_URL`
- `ANALYTICS_API_URL`
- `CONTROL_PLANE_BOOTSTRAP_URL`
- `CONTROL_PLANE_ROTATE_URL`
- Local whitelist, suspicious ports, exfiltration thresholds

### Backend environment (`backend/.env`)

Current repository `.env` values:

```env
HOST=0.0.0.0
PORT=8080
DATABASE_URL=phishguard.db
ML_SERVICE_URL=http://127.0.0.1:8888
RUST_LOG=info
```

Template (`backend/.env.example`) differs and points ML service to `8000`.
Align these values with your actual ML service port before running.

### ML service

- `ml-service/app.py` starts Uvicorn on port 8888 unless changed in code/command.

---

## End-to-End Data Flow

1. User opens or interacts with a page.
2. Injected extension scripts analyze behavior/network/fingerprinting patterns.
3. Content and monitor scripts send messages to background service worker.
4. Background checks URL via Rust API (`/api/check-url`) with control-plane token.
5. Rust checks Redis cache first; on miss calls ML service (`/api/predict`).
6. ML service extracts 159 features and returns inference response.
7. Rust returns normalized response to extension.
8. Background logs activity to analytics endpoint.
9. Dashboard and popup read health and analytics telemetry and render charts/cards.

---

## Local Setup (Windows / Git Bash)

### Prerequisites

- Chrome/Chromium (for extension)
- Rust toolchain
- Python 3.10+ recommended
- `sqlite3` CLI (recommended for quick DB init)
- Optional: Redis (system runs without it, but without cache)

### 1) Clone and open folder

```bash
cd "c:/Users/Sri Vishnu/DP-2/DP2"
```

### 2) Python environment

```bash
python -m venv .venv
source .venv/Scripts/activate
```

### 3) Install ML runtime dependencies

```bash
cd ml-service
pip install -r requirements.txt
cd ../ml-model
pip install -r requirements.txt
cd ..
```

### 4) Initialize SQLite analytics schema (recommended)

```bash
sqlite3 backend/phishguard.db < backend/migrations/2025-10-10-000001_create_user_analytics/up_sqlite_complete.sql
```

### 5) Verify backend env

Ensure `backend/.env` has `ML_SERVICE_URL` matching your ML service run port.

---

## Running the Full Stack

Open separate terminals.

### Terminal A: ML service

```bash
cd "c:/Users/Sri Vishnu/DP-2/DP2/ml-service"
source ../.venv/Scripts/activate
python app.py
```

By default in current code, this binds to port 8888.

### Terminal B: Rust backend

```bash
cd "c:/Users/Sri Vishnu/DP-2/DP2/backend"
cargo run
```

Expected health endpoint:

- `http://localhost:8080/health`

### Terminal C: test server for HTML payloads

```bash
cd "c:/Users/Sri Vishnu/DP-2/DP2"
python -m http.server 8081
```

### Load extension

1. Open `chrome://extensions`
2. Enable Developer Mode
3. Load unpacked -> select `DP2` folder
4. Use popup to open dashboard (`dashboard.html`)

---

## Testing with Dummy Payloads

Recommended launcher:

- `http://localhost:8081/` (root `index.html` test hub)

Payload files:

- `test-payloads/1_visual_spoof.html`
  - fake PayPal login page
  - expected visual/DOM spoof alerts
- `test-payloads/2_nlp_spear_phishing.html`
  - urgency + wallet language
  - expected NLP urgency detection
- `test-payloads/3_clickjack_obfuscation.html`
  - invisible overlay + eval-heavy script
  - expected anti-evasion and clickjacking indicators

Legacy payload:

- `test-payloads/4_web3_drainer.html`
  - legacy test artifact
  - active Web3 runtime interception is not part of current content-script phase flow

Dashboard refresh behavior:

- Current auto-refresh timer in `app.js` is 2 seconds (`setInterval(..., 2000)`)
- Auto-refresh can be toggled in settings (`dashboardAutoRefresh`)

---

## API Reference

Base URL: `http://localhost:8080`

### Public endpoints

- `GET /`
- `GET /health`

### Control plane

- `POST /api/control-plane/bootstrap`
  - no token required
  - requires valid extension/install identifiers
  - requires Origin matching `chrome-extension://<extension_id>`
- `POST /api/control-plane/rotate`
  - requires existing token + matching identifiers + matching Origin

### Protected endpoints (token required)

- `POST /api/check-url`
- `GET /api/stats`
- `GET /api/stats/global`
- `GET /api/stats/user/{user_id}`
- `GET /api/user/{user_id}/analytics`
- `POST /api/user/{user_id}/activity`
- `GET /api/user/{user_id}/threats/live` (SSE)

Header:

```http
X-PhishGuard-Token: <token>
```

---

## Scripts and Utilities in Root

The root includes multiple utility scripts from iterative development/debugging.
Examples:

- `patch_*.js`
- `remove_web3*.js`
- `fix_*.js`
- `apply_ui.js`
- `generate_best_models.py`

These are not all part of steady-state runtime. They are maintenance/debug aids used to patch,
test, or refactor behavior during development.

---

## Known Mismatches and Limitations

This section intentionally documents current reality from source.

1. Port mismatch risk

- `ml-service/app.py` runs on 8888 by default
- Some docs/templates still reference 8000
- Backend must point `ML_SERVICE_URL` to actual ML port

2. Popup user-id key mismatch

- Popup reads `pg_user_id` with fallback `demo-user`
- Background/dashboard primarily use `userId`
- This can cause analytics identity drift between views

3. Content-to-background action mismatch

- `content_script.js` sends actions like `suspiciousActivity`, `userAction`, `statusReport`
- `background.js` switch handler does not explicitly process these action names
- As a result, some telemetry may log as unknown action in background debug output

4. Duplicate warning map keys

- `content_script.js` warning messages object includes duplicate keys in places
- JavaScript keeps the last duplicate entry; behavior still runs but config is noisy

5. Network blocking caveat in MV3

- `background.js` uses `onBeforeRequest` without blocking mode
- comments already note MV3 enterprise limitation
- returning `{ cancel: true }` is not guaranteed to enforce hard blocking in this mode

6. Legacy Web3 artifacts

- Web3 runtime phase removed from active content-script engines
- legacy test file and older docs/scripts may still mention Phase 5

7. Legacy SQL docs

- root SQL files include PostgreSQL-oriented schema/setup
- active runtime analytics path is SQLite-backed under `backend/`

8. Cache stats currently placeholder

- `backend/src/services/cache.rs` returns `(0,0)` in `get_stats()`
- `/api/stats` hit/miss numbers are not yet true Redis telemetry

---

## Troubleshooting Guide

### A) Dashboard shows backend unreachable

Check:

```bash
curl http://localhost:8080/health
```

If not reachable:

- Ensure Rust backend is running
- Ensure port 8080 is not occupied by another process

### B) Dashboard says auth required / token errors

- Reload extension in `chrome://extensions`
- This re-triggers bootstrap/refresh token paths in background
- Ensure backend is running before extension startup

### C) ML service unavailable in backend health

- Confirm ML service port and backend `ML_SERVICE_URL` match
- If `app.py` is used unmodified, ML likely runs on 8888

### D) Analytics not updating

- Ensure SQLite schema is initialized (run migration SQL into `backend/phishguard.db`)
- Ensure dashboard auto-refresh is enabled
- Verify `GET /api/user/{user_id}/analytics` succeeds with token

### E) Test pages do not trigger warnings

- Reload extension after any script edits
- Open payloads via local HTTP server (not file://)
- Use browser console for content-script and background logs

---

## Recommended Next Cleanup Steps

1. Unify ML port configuration across:
   - `backend/.env`
   - `backend/.env.example`
   - `ml-service/app.py` startup print and actual run port
   - any docs and test pages

2. Unify extension user identity keys:
   - standardize on `userId` in popup, dashboard, and background

3. Add handlers in `background.js` for:
   - `suspiciousActivity`
   - `userAction`
   - `statusReport`
   - `visibilityChange`
   - `popupAttempt`

4. Remove duplicate warning message keys from `content_script.js`.

5. Decide and document final policy for legacy Web3 assets:
   - either remove legacy files/docs or reintroduce as optional feature behind config flag.

6. Implement real cache statistics in `cache.rs` (`INFO`/keyspace metrics) for `/api/stats`.

7. Consolidate and archive one-off patch scripts into a dedicated `scripts/maintenance` folder.

---

If you want, the next step can be a second pass that converts this README into a stricter
developer handbook with separate sections for contributors, API consumers, and security reviewers.
