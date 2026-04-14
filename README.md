# InternShield — Forensic Intelligence Engine v5.0 🛡️🚀

**InternShield** is a high-fidelity forensic platform engineered to detect and neutralize recruitment scams and phishing threats through **Deep Infrastructure Forensics**. It moves beyond simple text analysis into real-time auditing of SSL trust chains, corporate registry footprints, and document metadata.

---

## 🌐 Live Infrastructure (Template)
- **Status**: TEMPLATE_READY
- **Primary URL**: [https://internshield-285066992940.us-central1.run.app](https://internshield-285066992940.us-central1.run.app)
- **Deployment Strategy**: 100% Stateless Dockerized Ops on Google Cloud Run.

---

## 🛡️ "Neural-Shield" Security Posture (v5.0)
InternShield is built on a **Zero-Persistence** security model, making it immune to data breaches through the following layers:

### 1. Forensic Input Validation
- **Mime-Sniffing (Libmagic)**: We do not trust file extensions. The engine inspects binary "magic numbers" to ensure uploaded files are truly PDFs/DOCX and not hidden executables.
- **Payload Capping**: A strict **5MB limit** is enforced on all uploads to prevent storage-exhaustion DoS attacks.
- **XSS Neutralization (Bleach)**: All manual pastes and text inputs are scrubbed of HTML/Script injections before hitting the forensic engine.

### 2. Network & Header Fortification
- **SSL Enforcement (HSTS)**: Rigid 1-year HSTS policy ensuring all traffic is encrypted.
- **CSP (Content-Security-Policy)**: Strictly restrictive policy preventing unauthorized script execution or data exfiltration.
- **Host Lockdown**: Wildcard `ALLOWED_HOSTS` have been removed; only verified Cloud Run and local domains are trusted.

### 3. Abuse Prevention
- **IP-Based Throttling**: Integrated **Rate Limiting** protects your search API quotas (Serper.dev/WHOIS) from automated bot abuse and scraping.
- **Stateless Identity**: Zero database architecture means no user credentials, passwords, or personal metadata are ever stored on-disk.

---

## 🏗️ Core Forensic Modules

### 1. 📄 OFFER_AUDIT (Document Forensics)
- **Integrity Analysis**: Scans uploaded offer letters for linguistic red-flags and infrastructure trust.
- **Metadata Fingerprinting**: Identifies original software source (e.g., flags "Google" offers made in "WPS Office").

### 2. ⚡ LIVE_PASTE (Manual Override)
- **Heuristic Sandbox**: Rapid manual analysis of SMS, WhatsApp, or raw email text in a sanitized environment.

### 3. 📡 OSINT_PROBE (Infrastructure Radar)
- **Community Intelligence**: Scans **Reddit** and **Glassdoor** for scam reports, interview red-flags, and corporate reputation.
- **MCA Verification**: Checks company registration against official Indian registries (CIN validation).
- **Web Intelligence**: Search stream scanning for scam complaints and reports via real-time search clusters.
- **Whois Intelligence**: Detection of recently registered "burner" domains used in phishing.

### 4. 📬 GMAIL_GATEWAY (v5 Roadmap)
- [**STATUS: MAINTENANCE**]
- Currently undergoing a security architectural overhaul to align with Neural-Shield v5 encryption standards.

---

## 🛠️ Technical Implementation

### The Neural Core (`core/`)
- **`analyzer.py`**: The Central Executive. Synthesizes infrastructure and content signals into a unified Risk Score.
- **`domain_checker.py`**: Perimeter forensics (WHOIS history, SSL Trust, DNS propagation).
- **`web_intel.py`**: Real-time OSINT via Serper.dev search clusters.

### The UI Engine (`web_app/`)
- **Brutalist Glassmorphism**: High-contrast, focused HUD designed for forensic analysis.
- **Gevent/Gunicorn**: Optimized for high-concurrency stateless operations on Cloud Run.

---

## ⚙️ Build & Deploy

### Environment Configuration
Ensure these are set in your `.env` or deployment console:
- `SERPER_API_KEY`: Required for Web Intelligence.
- `DJANGO_SECRET_KEY`: Production-grade random string.
- `ALLOWED_HOSTS`: Restricted domain patterns.

### Deployment Commands
```bash
# 1. Build the Forensic Image
gcloud builds submit --tag gcr.io/[PROJECT_ID]/internshield

# 2. Deploy to Cloud Run
gcloud run deploy internshield --image gcr.io/[PROJECT_ID]/internshield --region us-central1 --allow-unauthenticated
```

---

## ⚖️ Legal Disclaimer
- **Heuristics Only**: Intelligence is retrieved via real-time OSINT; users are MANDATED to perform independent verification.
- **No Liability**: InternShield is a heuristic diagnostic tool and accepts no liability for actions taken based on its findings.

**Stay safe. Your discretion is the final defensive layer.**
