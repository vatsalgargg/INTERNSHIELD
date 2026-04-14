"""
InternShield — Domain & Company Intelligence
==============================================
Checks domain age, WHOIS, trust scores, MCA registration, and DNS abuse flags.
"""

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import requests
import whois
import dns.resolver

from . import config


class DomainChecker:

    TIMEOUT = 8

    def analyze(self, domain: str) -> Dict[str, Any]:
        """Full domain intelligence scan. Returns a dict of findings."""
        result = {
            "domain":          domain,
            "whois":           {},
            "age_days":        None,
            "is_young":        False,
            "suspicious_tld":  False,
            "ip_info":         {},
            "mx_records":      [],
            "has_valid_mx":    False,
            "ssl_info":        {},
            "virustotal":      {},
            "ipqs":            {},
            "risk_signals":    [],
            "domain_score":    0,   # 0-100 — higher = riskier
        }

        result["suspicious_tld"] = self._check_tld(domain)
        if result["suspicious_tld"]:
            result["risk_signals"].append("Suspicious/cheap TLD (e.g., .xyz .top .tk)")

        result["whois"]    = self._whois_lookup(domain)
        result["age_days"] = self._calculate_age(result["whois"])

        # 🔐 SSL CERTIFICATE INSPECTION (with WWW Fallback)
        result["ssl_info"] = self._check_ssl_cert(domain)
        if result["ssl_info"].get("error") and not domain.startswith("www."):
            # Try www fallback
            www_domain = f"www.{domain}"
            fallback_ssl = self._check_ssl_cert(www_domain)
            if not fallback_ssl.get("error"):
                result["ssl_info"] = fallback_ssl
                result["ssl_info"]["note"] = "Detected via WWW fallback"

        if result["ssl_info"].get("error"):
            # Don't flag as risk if it's just a timeout, but note it
            pass
        elif result["ssl_info"].get("issuer"):
            issuer = result["ssl_info"]["issuer"].lower()
            if "let's encrypt" in issuer:
                result["risk_signals"].append("Uses free/automated SSL (Let's Encrypt) — common for temp scam sites")
            
            days_to_expiry = result["ssl_info"].get("days_to_expiry")
            if days_to_expiry is not None and days_to_expiry < 30:
                result["risk_signals"].append(f"SSL certificate expires very soon ({days_to_expiry} days)")

        if result["age_days"] is not None:
            if result["age_days"] < 180:
                result["is_young"] = True
                result["risk_signals"].append(
                    f"Domain is very young ({result['age_days']} days old — registered recently)"
                )
            elif result["age_days"] < 365:
                result["risk_signals"].append(
                    f"Domain is less than 1 year old ({result['age_days']} days)"
                )

        result["ip_info"] = self._resolve_ip(domain)
        mx = self._check_mx(domain)
        result["mx_records"]   = mx
        result["has_valid_mx"] = len(mx) > 0
        if not result["has_valid_mx"]:
            result["risk_signals"].append("No valid MX records — domain cannot receive email")

        if config.VIRUSTOTAL_API:
            result["virustotal"] = self._virustotal_check(domain)
            if result["virustotal"].get("malicious", 0) > 0:
                result["risk_signals"].append(
                    f"VirusTotal flagged domain as malicious ({result['virustotal']['malicious']} engines)"
                )

        if config.IPQUALITYSCORE_API:
            result["ipqs"] = self._ipqs_check(domain)
            score = result["ipqs"].get("fraud_score", 0)
            if score >= 75:
                result["risk_signals"].append(f"IPQualityScore fraud score: {score}/100")
            
            if result["ipqs"].get("phishing"):
                result["risk_signals"].append("CRITICAL: IPQS flagged this domain as a PHISHING site")
            if result["ipqs"].get("malware"):
                result["risk_signals"].append("CRITICAL: IPQS flagged this domain as hosting MALWARE")

        result["domain_score"] = self._compute_domain_score(result)
        return result

    # ─────────────────────────────────────────────────────────────────────────────
    # API DELEGATIONS
    # ─────────────────────────────────────────────────────────────────────────────
    def check_mca_registration(self, company_name: str) -> Dict[str, Any]:
        from .web_intel import WebIntelligence
        wi     = WebIntelligence()
        result = wi.search_mca_registration(company_name)
        return {
            "company_name": company_name,
            "found":        result.get("found", False),
            "status":       result.get("status", "Unknown"),
            "cin":          result.get("cin", ""),
            "source":       result.get("source", ""),
            "note":         result.get("details", ""),
            "manual_url":   config.MCA_MANUAL_LINK,
        }

    def check_linkedin_presence(self, company_name: str) -> Dict[str, Any]:
        from .web_intel import WebIntelligence
        wi = WebIntelligence()
        return wi.check_linkedin(company_name)

    def check_email_reputation(self, email_address: str) -> Dict[str, Any]:
        if not config.IPQUALITYSCORE_API: return {"checked": False}
        try:
            key = config.IPQUALITYSCORE_API
            url = f"https://www.ipqualityscore.com/api/json/email/{key}/{email_address}"
            resp = requests.get(url, timeout=self.TIMEOUT)
            data = resp.json()
            data["checked"] = True
            return data
        except Exception: return {"checked": False, "error": True}

    # ──────────────────────────────────────────────────────────────────────────
    # INTERNAL HELPERS
    # ──────────────────────────────────────────────────────────────────────────
    def _check_tld(self, domain: str) -> bool:
        for tld in config.SUSPICIOUS_DOMAINS:
            if domain.endswith(tld): return True
        return False

    def _whois_lookup(self, domain: str) -> Dict:
        try:
            w = whois.whois(domain)
            return {
                "registrar":       w.registrar,
                "creation_date":   w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers":    list(w.name_servers or []),
                "country":         w.country,
            }
        except Exception: return {}

    def _calculate_age(self, whois_data: Dict) -> Optional[int]:
        creation = whois_data.get("creation_date")
        if not creation: return None
        
        # Handle lists (some registrars return multiple dates)
        if isinstance(creation, list):
            # Take the earliest date
            valid_dates = [d for d in creation if isinstance(d, datetime)]
            if not valid_dates: return None
            dt = min(valid_dates)
        elif isinstance(creation, datetime):
            dt = creation
        elif isinstance(creation, str):
            # Fallback for string dates
            try:
                raw = creation.strip().strip("[]").split(",")[0].strip()
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
                    try:
                        dt = datetime.strptime(raw[:19], fmt)
                        break
                    except ValueError: continue
                else: return None
            except Exception: return None
        else:
            return None

        # Calculate days
        now = datetime.now()
        # Ensure 'now' is offset-naive if 'dt' is naive, or both are aware
        if dt.tzinfo is not None and now.tzinfo is None:
            now = datetime.now(timezone.utc)
        elif dt.tzinfo is None and now.tzinfo is not None:
            dt = dt.replace(tzinfo=timezone.utc)
            
        return abs((now - dt).days)

    def _resolve_ip(self, domain: str) -> Dict:
        try:
            ip = socket.gethostbyname(domain)
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=self.TIMEOUT)
            return resp.json()
        except Exception: return {}

    def _check_mx(self, domain: str) -> list:
        try:
            records = dns.resolver.resolve(domain, "MX")
            return [str(r.exchange) for r in records]
        except Exception: return []

    def _check_ssl_cert(self, domain: str) -> Dict[str, Any]:
        """Extracts SSL certificate details (Issuer, Expiry) with SNI support."""
        try:
            context = ssl.create_default_context()
            # Explicitly set SNI via server_hostname
            with socket.create_connection((domain, 443), timeout=self.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Handle issuer extraction more robustly
                    issuer_info = cert.get('issuer', [])
                    issuer_dict = {}
                    for item in issuer_info:
                        if isinstance(item, tuple) and len(item) > 0:
                            entry = item[0]
                            if len(entry) >= 2:
                                issuer_dict[entry[0]] = entry[1]
                                
                    common_name = issuer_dict.get('commonName', 'Unknown Issuer')
                    
                    # Expiry calculation
                    not_after_str = cert.get('notAfter')
                    expiry = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    days_to_expiry = (expiry - datetime.now()).days
                    
                    return {
                        "issuer": common_name,
                        "expiry": not_after_str,
                        "days_to_expiry": days_to_expiry,
                        "subject": dict(x[0] for x in cert.get('subject', [])).get('commonName', domain)
                    }
        except Exception as e:
            return {"error": str(e)}

    def _virustotal_check(self, domain: str) -> Dict:
        headers = {"x-apikey": config.VIRUSTOTAL_API}
        try:
            url  = f"https://www.virustotal.com/api/v3/domains/{domain}"
            resp = requests.get(url, headers=headers, timeout=self.TIMEOUT)
            if resp.status_code == 200:
                data  = resp.json()
                return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        except Exception: pass
        return {}

    def _ipqs_check(self, domain: str) -> Dict:
        try:
            key  = config.IPQUALITYSCORE_API
            url  = f"https://ipqualityscore.com/api/json/url/{key}/{domain}"
            resp = requests.get(url, params={'strictness': 0}, timeout=self.TIMEOUT)
            return resp.json()
        except Exception: return {}

    def _compute_domain_score(self, result: Dict) -> int:
        score = 0
        if result["suspicious_tld"]:      score += 30
        if result["is_young"]:             score += 35
        if not result["has_valid_mx"]:     score += 20
        
        # SSL Scoring
        ssl_info = result.get("ssl_info", {})
        if ssl_info.get("issuer") and "let's encrypt" in ssl_info["issuer"].lower():
            score += 15
        if ssl_info.get("days_to_expiry", 100) < 15:
            score += 10

        vt = result["virustotal"]
        if vt.get("malicious", 0) > 0:    score += 40
        ipqs = result["ipqs"]
        fs = ipqs.get("fraud_score", 0)
        score += int(fs * 0.3)
        return min(score, 100)
