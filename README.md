# InternShield — Forensic Intelligence Engine v5.0 🛡️🚀

**InternShield** is a high-fidelity forensic platform engineered to detect and neutralize recruitment scams and phishing threats through **Deep Infrastructure Forensics**. It moves beyond simple text analysis into real-time auditing of SSL trust chains, corporate registry footprints, and document metadata.

---

## 🌐 Live Infrastructure

- **Status**: LIVE
- **Primary URL**: [https://internshield.eastasia.azurecontainerapps.io](https://internshield.eastasia.azurecontainerapps.io)
- **Deployment Strategy**: 100% Stateless Dockerized Ops on **Microsoft Azure Container Apps**
- **Cloud Provider**: Microsoft Azure (East Asia region)
- **Registry**: Azure Container Registry (`internshieldacr.azurecr.io`)

---

## 🏗️ Architecture Overview

```
GitHub (source)
      │
      │  az acr build
      ▼
Azure Container Registry
internshieldacr.azurecr.io/internshield:latest
      │
      │  az containerapp create
      ▼
Azure Container Apps (East Asia)
      │
      ▼
https://internshield.eastasia.azurecontainerapps.io
```

### Infrastructure Components
| Component | Azure Service | Details |
|-----------|--------------|---------|
| Container Registry | Azure Container Registry (Basic) | Stores Docker image |
| Runtime | Azure Container Apps | Serverless, scales to zero |
| Networking | Built-in Azure ingress | HTTPS, auto-TLS |
| Secrets | Container App env vars | Injected at deploy time |

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
- **Host Lockdown**: Only verified Azure Container Apps and local domains are trusted via `ALLOWED_HOSTS`.

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

## 🛠️ Technical Stack

### The Neural Core (`core/`)
- **`analyzer.py`**: The Central Executive. Synthesizes infrastructure and content signals into a unified Risk Score.
- **`domain_checker.py`**: Perimeter forensics (WHOIS history, SSL Trust, DNS propagation).
- **`web_intel.py`**: Real-time OSINT via Serper.dev search clusters.

### The UI Engine (`web_app/`)
- **Brutalist Glassmorphism**: High-contrast, focused HUD designed for forensic analysis.
- **Gevent/Gunicorn**: Optimized for high-concurrency stateless operations on Azure Container Apps.

### Infrastructure
- **Docker**: Multi-stage build (builder + final slim image)
- **Azure Container Registry**: Private Docker image storage
- **Azure Container Apps**: Serverless container runtime, auto-scales to zero
- **WhiteNoise**: Static file serving without a CDN

---

## ⚙️ Build & Deploy (Azure)

### Prerequisites
```bash
# Install Azure CLI
winget install Microsoft.AzureCLI

# Login
az login --use-device-code
```

### Environment Variables Required
Set these in Azure Container Apps (never commit to git):

| Variable | Description |
|----------|-------------|
| `DJANGO_SECRET_KEY` | Strong random secret key |
| `DJANGO_DEBUG` | Set to `False` in production |
| `ALLOWED_HOSTS` | Your Container App domain |
| `CSRF_TRUSTED_ORIGINS` | `https://` + your domain |
| `SERPER_API_KEY` | Required for Web Intelligence |
| `ADMIN_ACCESS_KEY` | Admin dashboard access |
| `PORT` | Set to `8000` |

### Full Deployment Commands
```bash
# 1. Create resource group
az group create --name internshield-rg --location eastasia

# 2. Create container registry
az acr create --resource-group internshield-rg --name internshieldacr --sku Basic --admin-enabled true

# 3. Register required providers
az provider register --namespace Microsoft.ContainerRegistry
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights

# 4. Build and push Docker image
az acr build --registry internshieldacr --image internshield:latest --resource-group internshield-rg --no-logs .

# 5. Create Container Apps environment
az containerapp env create --name internshield-env --resource-group internshield-rg --location eastasia

# 6. Deploy
az containerapp create \
  --name internshield \
  --resource-group internshield-rg \
  --environment internshield-env \
  --image internshieldacr.azurecr.io/internshield:latest \
  --registry-server internshieldacr.azurecr.io \
  --ingress external \
  --target-port 8000 \
  --min-replicas 0 \
  --max-replicas 2 \
  --env-vars \
    DJANGO_SECRET_KEY=your-secret-key \
    DJANGO_DEBUG=False \
    PORT=8000 \
    ALLOWED_HOSTS=your-app.eastasia.azurecontainerapps.io \
    CSRF_TRUSTED_ORIGINS=https://your-app.eastasia.azurecontainerapps.io \
    SERPER_API_KEY=your-serper-key \
    ADMIN_ACCESS_KEY=your-admin-key
```

---

## ⚖️ Legal Disclaimer
- **Heuristics Only**: Intelligence is retrieved via real-time OSINT; users are MANDATED to perform independent verification.
- **No Liability**: InternShield is a heuristic diagnostic tool and accepts no liability for actions taken based on its findings.

**Stay safe. Your discretion is the final defensive layer.**
