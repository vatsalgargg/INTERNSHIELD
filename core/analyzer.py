"""
InternShield — Core Scam Analysis Engine
==========================================
Combines all signals (email body, domain, offer letter) into a final verdict.
"""

import re
from typing import Dict, Any, List

from . import config
from .domain_checker import DomainChecker
from .offer_parser import OfferLetterParser
from .web_intel import WebIntelligence
from .cyber_intel import CyberIntel


class ScamAnalyzer:

    def __init__(self):
        self.domain_checker  = DomainChecker()
        self.offer_parser    = OfferLetterParser()
        self.web_intel       = WebIntelligence()
        self.cyber_intel     = CyberIntel()

    # ──────────────────────────────────────────────────────────────────────────
    # MAIN ENTRY
    # ──────────────────────────────────────────────────────────────────────────
    def analyze_email(self, email: Dict, deep_scan: bool = False,
                      applied_by_user: bool = None) -> Dict[str, Any]:
        """
        Full analysis of a single email dict (from GmailScanner).
        deep_scan=True: also runs Brave Search company OSINT (slower, more thorough).
        applied_by_user: True if user confirms they applied, False if they did not,
                         None if unknown (default — tool infers from content).
        Returns a comprehensive result dict with risk score & verdict.
        """
        body  = (email.get("body", "") or "").lower()
        html  = (email.get("html", "") or "").lower()
        full  = body + " " + html
        subj  = (email.get("subject", "") or "").lower()
        links = email.get("links", [])

        # ── Section scores (each 0-100) ──────────────────────────────────────
        sender_score  = self._analyze_sender(email)
        content_score = self._analyze_content(full, subj)
        link_score    = self._analyze_links(links)

        # ── Domain deep scan ────────────────────────────────────────────────────
        domain_result = {}
        domain_score  = 0
        sender_domain = email.get("sender_domain", "")
        if sender_domain and sender_domain not in config.FREE_EMAIL_AS_COMPANY_RECRUITER:
            domain_result = self.domain_checker.analyze(sender_domain)
            domain_score  = domain_result.get("domain_score", 0)

        # ── Cybersecurity intelligence layer ─────────────────────────────────
        cyber_result = {}
        cyber_score  = 0
        if sender_domain and sender_domain not in config.FREE_EMAIL_AS_COMPANY_RECRUITER:
            cyber_result = self.cyber_intel.analyze_domain(sender_domain)
            cyber_score  = cyber_result.get("cyber_score", 0)

        # ── Aggregate signals ──────────────────────────────────────────────────
        signals = []
        signals += sender_score["signals"]
        signals += content_score["signals"]
        signals += link_score["signals"]
        signals += domain_result.get("risk_signals", [])
        signals += cyber_result.get("risk_signals", [])

        # ── Unsolicited ack check ────────────────────────────────────────────────────
        ack_result = self._check_unsolicited_ack(full, subj, applied_by_user)
        signals   += ack_result["signals"]

        # ── Weighted final risk score ─────────────────────────────────────────
        final_score = int(
            sender_score["score"]  * 0.25 +
            content_score["score"] * 0.40 +
            domain_score           * 0.20 +
            link_score["score"]    * 0.15
        )
        final_score = min(final_score, 100)

        # ── Hard floors — certain signals guarantee minimum risk level ─────────
        # A payment demand is a near-certain scam: force into HIGH RISK
        if content_score.get("financial_hits", 0) > 0:
            final_score = max(final_score, config.RISK_THRESHOLD_HIGH)
        # Bulk email platform alone forces MEDIUM
        elif content_score.get("bulk_hit", False):
            final_score = max(final_score, config.RISK_THRESHOLD_MEDIUM)
        # User explicitly said they did NOT apply + ack email detected
        if ack_result.get("is_unsolicited"):
            final_score = max(final_score, config.RISK_THRESHOLD_MEDIUM + 15)

        verdict  = self._verdict(final_score)
        category = self._categorize(full, subj)

        # ── Extract company name for MCA check ────────────────────────────────
        company_name = self._extract_company_from_email(full, subj)
        mca_result   = {}
        if company_name:
            mca_result = self.domain_checker.check_mca_registration(company_name)
            if not mca_result.get("found"):
                signals.append(f"Company '{company_name}' NOT found in MCA database")
                final_score = min(final_score + 15, 100)

        # ── Deep Web OSINT (Brave Search) — runs when deep_scan=True ──────────
        # Auto-enables for high-risk emails even when not explicitly requested.
        web_intel_result = {}
        should_deep_scan  = deep_scan or final_score >= config.RISK_THRESHOLD_HIGH
        if should_deep_scan and company_name:
            web_intel_result = self.web_intel.investigate_company(
                company_name, domain=sender_domain
            )
            signals += web_intel_result.get("risk_signals", [])
            web_risk  = web_intel_result.get("overall_web_risk", 0)
            final_score = min(final_score + int(web_risk * 0.20), 100)

        # Re-compute verdict after deep scan may have raised the score
        verdict = self._verdict(final_score)

        return {
            "email_id":        email.get("id", ""),
            "subject":         email.get("subject", ""),
            "sender":          email.get("sender", ""),
            "sender_email":    email.get("sender_email", ""),
            "sender_domain":   sender_domain,
            "date":            email.get("date", ""),
            "attachments":     email.get("attachments", []),
            "risk_score":      final_score,
            "verdict":         verdict,
            "category":        category,
            "company_name":    company_name,
            "signals":         list(dict.fromkeys(signals)),  # deduplicate
            "sender_analysis":    sender_score,
            "content_analysis":   content_score,
            "domain_analysis":    domain_result,
            "link_analysis":      link_score,
            "cyber_analysis":     cyber_result,        # NEW
            "mca_result":         mca_result,
            "web_intel_result":   web_intel_result,
            "checklist":          self._build_checklist(email, domain_result, mca_result, cyber_result, final_score),
        }

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """Analyze a standalone offer letter file."""
        result = self.offer_parser.parse(filepath)
        score  = result.get("offer_score", 0)

        # Domain check on any embedded emails
        contacts = result.get("contact_info", {})
        for email_addr in contacts.get("emails", []):
            domain = email_addr.split("@")[-1]
            dr     = self.domain_checker.analyze(domain)
            result["domain_check_" + domain] = dr
            score = min(score + dr.get("domain_score", 0) // 2, 100)

        result["final_score"] = score
        result["verdict"]     = self._verdict(score)
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # SENDER ANALYSIS
    # ──────────────────────────────────────────────────────────────────────────
    def _analyze_sender(self, email: Dict) -> Dict:
        score   = 0
        signals = []
        sender_domain = email.get("sender_domain", "")
        sender_email  = email.get("sender_email", "")
        reputation    = {}

        if sender_domain in config.FREE_EMAIL_AS_COMPANY_RECRUITER:
            score += 40
            signals.append(
                f"Recruiter using free email service ({sender_domain}) instead of company domain"
            )

        if not sender_email or "@" not in sender_email:
            score += 30
            signals.append("Invalid or missing sender email address")
        else:
            # ── IPQS Email Reputation Check ────────────────────────────────────
            reputation = self.domain_checker.check_email_reputation(sender_email)
            if reputation.get("valid") is False:
                score += 20
                signals.append(f"Sender email address ({sender_email}) is flagged as INVALID or inactive")
            
            if reputation.get("disposable"):
                score += 40
                signals.append("CRITICAL: Recruiter is using a DISPOSABLE/temporary email service")
            
            if reputation.get("fraud_score", 0) >= 75:
                score += 30
                signals.append(f"IPQS flagging this email address as high-risk (Fraud Score: {reputation['fraud_score']})")

        # Random-looking email (lots of numbers/random chars)
        local = sender_email.split("@")[0] if "@" in sender_email else ""
        if re.search(r'\d{4,}', local):
            score += 15
            signals.append(f"Sender email looks randomly generated: {sender_email}")

        # Spoofed display name
        sender_display = email.get("sender", "")
        if sender_domain and sender_domain not in sender_display.lower():
            score += 10
            signals.append("Sender display name does not match email domain (possible spoofing)")

        # Suspicious TLD in sender domain (e.g. cyartcareers.info)
        if sender_domain:
            for tld in config.SUSPICIOUS_DOMAINS:
                if sender_domain.endswith(tld):
                    score += 25
                    signals.append(f"Sender domain uses suspicious TLD: {sender_domain}")
                    break

        return {"score": min(score, 100), "signals": signals, "reputation": reputation}

    def _analyze_content(self, full_text: str, subject: str) -> Dict:
        """Analyzes the email body and subject for forensic red flags."""
        score = 0
        signals = []
        financial_hits = 0
        bulk_hit = False

        # 1. Financial Red Flags (High Weight)
        for phrase in config.FINANCIAL_RED_FLAGS:
            if phrase in full_text:
                score += 35
                financial_hits += 1
                signals.append(f"Financial Red Flag: Request for payment/deposit ('{phrase}')")

        # 2. Pressure Tactics
        for phrase in config.PRESSURE_TACTICS:
            if phrase in full_text:
                score += 15
                signals.append(f"Pressure Tactic: Artificial urgency detected ('{phrase}')")
                break

        # 3. Fake Offer Signals
        for phrase in config.FAKE_OFFER_SIGNALS:
            if phrase in full_text:
                score += 20
                signals.append(f"Fake Offer Signal: Suspicious onboarding/selection pattern ('{phrase}')")

        # 4. Bulk Sender Check (Recruiters don't use Mailchimp/Octopus/etc)
        for platform in config.BULK_EMAIL_SENDERS:
            if platform in full_text:
                score += 25
                bulk_hit = True
                signals.append(f"Bulk Platform Detected: Recruiter using mass-mailing service ({platform})")
                break

        # 5. 🧠 LINGUISTIC ANOMALY DETECTION (AI Style)
        ling_result = self._analyze_linguistics(full_text)
        score += ling_result["score"]
        signals += ling_result["signals"]

        return {
            "score": min(score, 100), 
            "signals": signals, 
            "financial_hits": financial_hits, 
            "bulk_hit": bulk_hit
        }

    def _analyze_linguistics(self, text: str) -> Dict:
        """Detects LLM-generated and overly formal scam boilerplates."""
        score = 0
        signals = []
        
        # 1. "Too Perfect" Formalism (Common in LLM scam templates)
        formal_scam_phrases = [
            "assuring you of our best co-operation",
            "acknowledge the receipt of this email",
            "kindly perusal",
            "undersigned",
            "strictly confidential and privileged"
        ]
        for phrase in formal_scam_phrases:
            if phrase in text.lower():
                score += 10
                signals.append(f"AI/Template Phrasing: Overly formal/archaic language detected ('{phrase}')")

        # 2. Generic Role Description (Scammers use generic roles to cast a wide net)
        generic_work_phrases = [
            "handle tasks assigned by management",
            "perform duties as per company needs",
            "work under the supervision of superiors",
            "reliable and hardworking candidate"
        ]
        if sum(1 for p in generic_work_phrases if p in text.lower()) >= 2:
            score += 15
            signals.append("Non-Specific Role: Job description is suspiciously generic/vague")

        return {"score": score, "signals": signals}

    # ──────────────────────────────────────────────────────────────────────────
    # LINK ANALYSIS
    # ──────────────────────────────────────────────────────────────────────────
    def _analyze_links(self, links: List[str]) -> Dict:
        score   = 0
        signals = []

        for link in links:
            link_lower = link.lower()
            for tld in config.SUSPICIOUS_DOMAINS:
                if tld in link_lower:
                    score += 20
                    signals.append(f"Suspicious TLD in link: {link}")
                    break

            # URL shorteners
            shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "cutt.ly", "rebrand.ly"]
            if any(s in link_lower for s in shorteners):
                score += 15
                signals.append(f"URL shortener used (hides real destination): {link}")

            # IP-based URLs
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link):
                score += 35
                signals.append(f"IP-based URL (no domain name): {link}")

        return {"score": min(score, 100), "signals": signals}

    # ──────────────────────────────────────────────────────────────────────────
    # UNSOLICITED ACK DETECTION
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _check_unsolicited_ack(full_text: str, subject: str,
                               applied_by_user: bool = None) -> Dict:
        """
        Detects fake 'submission/application received' acknowledgement emails
        sent to people who never applied to that company.

        Logic:
          1. Check if the email contains 'ack signals' (submission received, etc.)
          2. Check if a known job portal is referenced (Naukri, LinkedIn, etc.)
             If yes → user probably did apply; lower suspicion.
          3. If applied_by_user is explicitly False → definite scam signal.
          4. Return is_unsolicited=True when the combination is suspicious.
        """
        combined  = full_text + " " + subject.lower()
        signals   = []
        score_add = 0

        # Count how many ack phrases hit
        ack_hits = sum(
            1 for phrase in config.UNSOLICITED_ACK_SIGNALS
            if phrase in combined
        )

        if ack_hits == 0:
            return {"signals": [], "is_unsolicited": False}

        # Check if a legitimate job portal is referenced
        portal_mentioned = any(p in combined for p in config.KNOWN_JOB_PORTALS)

        is_unsolicited = False

        if applied_by_user is False:
            # User explicitly says they did NOT apply — clear scam signal
            is_unsolicited = True
            score_add += 40
            signals.append(
                "User confirmed they did NOT apply to this company — "
                "unsolicited 'submission received' email is a SCAM tactic"
            )
        elif applied_by_user is None and not portal_mentioned:
            # Tool can't confirm — but email looks like an ack with no portal ref
            is_unsolicited = True
            score_add += 20
            signals.append(
                "Email looks like a submission acknowledgement but NO known job "
                "portal (Naukri/LinkedIn/Internshala etc.) is mentioned — "
                "could be unsolicited. Did you actually apply here?"
            )
        elif portal_mentioned:
            # Portal mentioned → probably legit; just note it
            signals.append(
                "Submission acknowledgement email — job portal referenced, "
                "likely from a real application."
            )

        return {"signals": signals, "is_unsolicited": is_unsolicited, "score_add": score_add}

    # ──────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _verdict(score: int) -> str:
        if score >= config.RISK_THRESHOLD_HIGH:
            return "🔴 HIGH RISK — LIKELY SCAM"
        elif score >= config.RISK_THRESHOLD_MEDIUM:
            return "🟡 MEDIUM RISK — SUSPICIOUS"
        else:
            return "🟢 LOW RISK — APPEARS LEGITIMATE"

    @staticmethod
    def _categorize(text: str, subject: str) -> str:
        combined = text + " " + subject
        if any(k in combined for k in ["pay", "fee", "deposit", "registration fee"]):
            return "PAY-TO-WORK SCAM"
        elif any(k in combined for k in ["share bank", "account number", "banking details"]):
            return "BANK DETAILS PHISHING"
        elif any(k in combined for k in ["aadhar", "pan card", "kyc", "identity"]):
            return "IDENTITY THEFT ATTEMPT"
        elif "congratulations" in combined:
            return "UNSOLICITED FAKE OFFER"
        elif any(k in combined for k in ["internship", "intern"]):
            return "FAKE INTERNSHIP"
        else:
            return "SUSPICIOUS JOB OFFER"

    @staticmethod
    def _extract_company_from_email(text: str, subject: str) -> str:
        combined = subject + " " + text
        # 1. Primary patterns (business entities)
        patterns = [
            r"([A-Z][A-Za-z\s&.,]+(?:Pvt\.?\s*Ltd\.?|LLC|Inc\.?|Ltd\.?|LLP|Technologies|Solutions|Services|Systems|Consulting|Group|Corp\.?))",
            r"from\s+([A-Z][A-Za-z\s&.,]{3,40})",
            # Pattern for "Company <email@domain.com>"
            r"([A-Z][A-Za-z0-9\s&.,]{2,40})\s*<[\w.+-]+@[\w.-]+\.\w+>",
            # Signature patterns: After "CEO" or "Founder"
            r"(?:CEO|Founder|Director|Manager),\s*([A-Z][A-Za-z\s&.,]{2,40})",
        ]
        for pat in patterns:
            m = re.search(pat, combined)
            if m:
                extracted = m.group(1).strip()
                # Basic cleaning
                extracted = re.sub(r'\s+', ' ', extracted)
                return extracted
        return ""

    @staticmethod
    def _build_checklist(email: Dict, domain: Dict, mca: Dict,
                         cyber: Dict, score: int) -> List[Dict]:
        """Build an actionable safety checklist."""
        mca_status = "Found" if mca.get("found") else "Not Found / Unverified"
        mca_source = mca.get("source", "")

        # Pull cyber details
        cyber_details = cyber.get("details", {})
        spf_dmarc     = cyber_details.get("spf_dmarc", {})
        ssl_det       = cyber_details.get("ssl", {})
        cert_age      = ssl_det.get("cert_age_days")
        cert_date     = ssl_det.get("first_cert_date", "N/A")
        spf_ok        = spf_dmarc.get("spf_found", None)
        dmarc_ok      = spf_dmarc.get("dmarc_found", None)

        spf_status = (
            "✅ SPF record found" if spf_ok
            else ("❌ No SPF record — major red flag" if spf_ok is False
                  else "⚠️ Not checked")
        )
        dmarc_status = (
            "✅ DMARC record found" if dmarc_ok
            else ("❌ No DMARC record" if dmarc_ok is False
                  else "⚠️ Not checked")
        )
        ssl_status = (
            f"❌ Cert only {cert_age} days old (first issued {cert_date})" if cert_age is not None and cert_age < 180
            else (f"✅ Established cert ({cert_age} days old)" if cert_age is not None
                  else "⚠️ Not checked")
        )

        checks = [
            {
                "item":   "MCA Registration (India)",
                "status": "✅ Found" if mca.get("found") else "❌ Not Found / Unverified",
                "action": f"Manually verify at {config.MCA_MANUAL_LINK}",
            },
            {
                "item":   "Recruiter uses company email",
                "status": "❌ Free email used" if any(
                    email.get("sender_domain", "") == d
                    for d in config.FREE_EMAIL_AS_COMPANY_RECRUITER
                ) else "✅ Company domain email",
                "action": "Verify recruiter's email domain matches the company website",
            },
            {
                "item":   "Domain Age",
                "status": f"❌ Young domain ({domain.get('age_days', 'N/A')} days)" if domain.get('is_young') else ("✅ Established domain" if domain else "⚠️ Not checked"),
                "action": "Use whois.domaintools.com to check when the domain was registered",
            },
            {
                "item":   "SPF Email Authentication",
                "status": spf_status,
                "action": "Run: nslookup -type=TXT <domain> to check SPF record",
            },
            {
                "item":   "DMARC Email Policy",
                "status": dmarc_status,
                "action": "Run: nslookup -type=TXT _dmarc.<domain> to check DMARC",
            },
            {
                "item":   "SSL Certificate Age",
                "status": ssl_status,
                "action": f"Check https://crt.sh/?q={email.get('sender_domain','')}&output=json",
            },
            {
                "item":   "No payment requested",
                "status": "❌ Payment mentioned in email" if score >= 60 else "✅ No payment demanded",
                "action": "NEVER pay any fee to get a job or internship",
            },
            {
                "item":   "LinkedIn company page",
                "status": "⚠️ Not verified",
                "action": "Search LinkedIn for the company and check if real employees exist",
            },
            {
                "item":   "No pressure tactics",
                "status": "✅ Clean" if score < 35 else "❌ Pressure tactics detected",
                "action": "Legitimate companies don't pressure you to accept same day",
            },
            {
                "item":   "Request video call verification",
                "status": "⚠️ Manual Step",
                "action": "Ask for a video call with the hiring manager before accepting",
            },
        ]
        return checks

