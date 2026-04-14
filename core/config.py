"""
InternShield Configuration
===========================
Central config for API keys, thresholds, and known scam patterns.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── Gmail OAuth ──────────────────────────────────────────────────────────────
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
]
# For Production: Use Environment Variables. For Local: Fallback to credentials.json
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GMAIL_CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE", "credentials.json")
GMAIL_TOKEN_FILE = "token.json"

# ─── Optional AI Key (OpenAI) ─────────────────────────────────────────────────
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# ─── Serper.dev OSINT API (Truly Free: 2,500 Searches) ──────────────────────
# Get your free key (No credit card needed): https://serper.dev/signup
SERPER_API_KEY = os.getenv("SERPER_API_KEY", "b6baba4905202adae7f14361279c6727b1f81a1b")
# ─── Risk Thresholds ─────────────────────────────────────────────────────────
RISK_THRESHOLD_HIGH   = 60   # Score >= 60 → HIGH RISK (Red Alert)
RISK_THRESHOLD_MEDIUM = 35   # Score 35–59 → MEDIUM RISK (Warning)
RISK_THRESHOLD_LOW    = 0    # Score < 35  → LOW RISK (Safe)

# ─── Scam Trigger Phrases ────────────────────────────────────────────────────
PRESSURE_TACTICS = [
    "sign by tomorrow", "respond within 24 hours", "limited slots",
    "urgent", "act now", "accept immediately", "deadline today",
    "only a few seats", "respond today", "immediate joining",
    "last chance", "don't miss out", "respond asap", "time-sensitive",
    "sign before", "offer expires", "offer valid for",
    "submit within", "submission deadline", "kindly submit",
    "joining letter will be sent after", "within 6-7 business days",
]

FINANCIAL_RED_FLAGS = [
    "registration fee", "pay to join", "deposit required",
    "security deposit", "refundable deposit", "training fee",
    "material fee", "kit fee", "enrollment fee", "processing fee",
    "advance payment", "token amount", "pay first",
    "rs.500", "rs 500", "₹500", "₹ 500", "500 refundable",
    "2 % processing fee", "2% processing fee",
    "amount will be refunded", "fully refunded upon completion",
    "refunded upon successful completion",
]

FAKE_OFFER_SIGNALS = [
    "work from home guaranteed", "no experience required earn",
    "earn up to", "earn lakhs", "no interview required",
    "selected without interview", "selected based on your profile",
    "100% job guarantee", "placement guaranteed",
    "work 2-3 hours daily", "earn from home",
    "dream job offer", "congratulations you have been selected",
    "we found your resume on naukri", "we found your profile on",
    "your resume has been shortlisted for",
    # Onboarding-before-verification scam patterns
    "you have been designated", "designated for the",
    "moving forward with your onboarding", "onboarding",
    "no formal training will be provided", "self-learning",
    "notarised affidavit", "notarized affidavit",
    "noc from university", "self declaration letter",
    "working from your own device", "work from your own device",
    "powered by emailoctopus", "emailoctopus",
    "do not reply to this mail", "auto-generated mail",
    "document submission link", "tally.so",
    "drive.google.com/file",   # Google Drive used for fake offer docs
]

SUSPICIOUS_DOMAINS = [
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".work", ".pw", ".info", ".biz",
]

LEGITIMATE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "rediffmail.com", "icloud.com",  # These are RED FLAGS for company recruiters
]

FREE_EMAIL_AS_COMPANY_RECRUITER = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "rediffmail.com", "ymail.com", "aol.com",
]

# Bulk/mass email platforms — real companies don't recruit via these
BULK_EMAIL_SENDERS = [
    "emailoctopus", "mailchimp", "sendgrid", "mailer-daemon",
    "bulk-out", "mass-mailer", "mailgun", "sendinblue", "brevo",
]

INDIA_KNOWN_SCAM_KEYWORDS = [
    "mnc company", "fortune 500 company", "top mnc",
    "immediate joining bonus", "work from anywhere",
    "part time full time", "earn 50000", "earn 30000",
    "referral bonus", "joining bonus guaranteed",
    "cyartcareers", "cyart careers",    # known scam domain
    "stipend will be provided after",
    "certificate will be provided",
    "letter of recommendation will be provided",
]

# ─── Unsolicited Assessment / Submission Acknowledgement Scams ────────────────
# Scammers send fake "we received your submission" emails to harvest data / build
# trust before demanding fees. These phrases alone aren't conclusive, but combined
# with no known job-portal reference they become a strong signal.
UNSOLICITED_ACK_SIGNALS = [
    "we have received your submission",
    "we received your submission",
    "received your application",
    "received your assessment",
    "your submission has been received",
    "your application has been received",
    "submission details",
    "reference id",
    "reference number",
    "submitted on",
    "screening assessment",
    "shortlisted for the next round",
    "shortlisted for further process",
    "selected for the next step",
    "we will reach out to you with the next steps",
]

# Known legitimate job portals — if one is mentioned, application is likely real.
KNOWN_JOB_PORTALS = [
    "naukri", "linkedin", "internshala", "indeed", "unstop",
    "shine", "monsterindia", "foundit", "hirist", "glassdoor",
    "angellist", "wellfound", "cutshort", "apna", "freshersworld",
    "letsintern", "twentyninepages", "dare2compete",
]

# ─── MCA India (no public API — handled via web_intelligence.py) ────────────
MCA_PORTAL_URL  = "https://www.mca.gov.in/content/mca/global/en/mca/master-data/MDS.html"
MCA_MANUAL_LINK = "https://efiling.mca.gov.in/efindingnew/companyLlpMasterData"

# ─── Domain Trust APIs ───────────────────────────────────────────────────────
IPQUALITYSCORE_API = os.getenv("IPQUALITYSCORE_API", "")     # optional
VIRUSTOTAL_API     = os.getenv("VIRUSTOTAL_API", "")         # optional
WHOIS_TIMEOUT      = 10   # seconds
CYBER_INTEL_TIMEOUT = 8   # seconds per cyber check (crt.sh, Wayback, HackerTarget)

# ─── Report Output ───────────────────────────────────────────────────────────
REPORTS_DIR = "reports"
MAX_EMAILS_TO_SCAN = 50
EMAIL_SCAN_QUERY = "subject:(internship OR offer letter OR hiring OR job offer OR selected OR shortlisted)"
