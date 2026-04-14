"""
╔══════════════════════════════════════════════════════════════╗
║   InternShield — Cybersecurity Intelligence Layer            ║
║   4 real-time, unfakeable checks against any sender domain   ║
║                                                              ║
║   1. SSL Cert Age       — crt.sh (free, no key)              ║
║   2. SPF + DMARC        — DNS queries (dnspython)            ║
║   3. Wayback First Seen — CDX API (free, no key)             ║
║   4. Reverse IP Count   — HackerTarget (free tier)           ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

import requests
import dns.resolver
import dns.exception

from . import config

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "InternShield/2.0 scam-detector"})


class CyberIntel:
    """
    Runs real-time cybersecurity checks against a sender domain.
    Every check is independent — if one times out, others still run.
    """

    TIMEOUT = getattr(config, "CYBER_INTEL_TIMEOUT", 8)

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC ENTRY
    # ──────────────────────────────────────────────────────────────────────────
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Run all 4 cyber checks for *domain*.
        Returns a dict with:
          cyber_score   : 0-100 aggregate risk score
          risk_signals  : list of human-readable findings
          details       : raw check results for the HTML report
        """
        if not domain or "." not in domain:
            return {"cyber_score": 0, "risk_signals": [], "details": {}}

        ssl_result    = self._check_ssl_cert(domain)
        spf_result    = self._check_spf_dmarc(domain)
        wayback_result = self._check_wayback(domain)
        revip_result  = self._check_reverse_ip(domain)

        signals: List[str] = []
        raw_score = 0

        for result in [ssl_result, spf_result, wayback_result, revip_result]:
            raw_score += result.get("score", 0)
            signals   += result.get("signals", [])

        cyber_score = min(raw_score, 100)

        return {
            "cyber_score":  cyber_score,
            "risk_signals": signals,
            "details": {
                "ssl":     ssl_result,
                "spf_dmarc": spf_result,
                "wayback": wayback_result,
                "reverse_ip": revip_result,
            },
        }

    # ──────────────────────────────────────────────────────────────────────────
    # CHECK 1: SSL CERTIFICATE AGE  (crt.sh REST API)
    # ──────────────────────────────────────────────────────────────────────────
    def _check_ssl_cert(self, domain: str) -> Dict:
        """
        Queries crt.sh for all SSL certs ever issued for the domain.
        The *earliest* issuance date shows when the domain first went live.
        """
        score   = 0
        signals = []
        details: Dict[str, Any] = {"checked": True}

        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            resp = _SESSION.get(url, timeout=self.TIMEOUT)
            resp.raise_for_status()
            certs = resp.json()

            if not certs:
                score += 15
                signals.append(
                    f"No SSL certificate found for {domain} — legitimate "
                    "companies always have HTTPS"
                )
                details["no_cert"] = True
                return {"score": score, "signals": signals, **details}

            # Find the earliest issued cert
            dates = []
            issuers = []
            for c in certs:
                raw = c.get("not_before", "")
                if raw:
                    try:
                        # Format: "2024-01-15T12:00:00"
                        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        dates.append(dt)
                    except ValueError:
                        pass
                issuer = c.get("issuer_name", "")
                if issuer:
                    issuers.append(issuer.lower())

            if not dates:
                details["parse_error"] = True
                return {"score": score, "signals": signals, **details}

            earliest   = min(dates)
            now        = datetime.now(timezone.utc)
            age_days   = (now - earliest).days

            details["first_cert_date"] = earliest.strftime("%Y-%m-%d")
            details["cert_age_days"]   = age_days
            details["issuers"]         = list(set(issuers))[:3]

            # Scoring based on cert age
            if age_days < 30:
                score += 35
                signals.append(
                    f"SSL cert for {domain} issued only {age_days} day(s) ago — "
                    "brand new domain pretending to be an established company"
                )
            elif age_days < 90:
                score += 25
                signals.append(
                    f"SSL cert for {domain} is only {age_days} days old — "
                    "very recently set up"
                )
            elif age_days < 180:
                score += 15
                signals.append(
                    f"SSL cert for {domain} is {age_days} days old — "
                    "domain established less than 6 months ago"
                )

            # Let's Encrypt = free, zero-friction cert (combined signal)
            le_used = any("let's encrypt" in i or "letsencrypt" in i for i in issuers)
            details["lets_encrypt"] = le_used
            if le_used and age_days < 365:
                score += 10
                signals.append(
                    f"Free Let's Encrypt cert on a <1yr domain ({domain}) — "
                    "low barrier to spin up a fake recruiter site"
                )

        except requests.exceptions.Timeout:
            logger.debug("crt.sh timed out for %s", domain)
            details["timeout"] = True
        except Exception as exc:
            logger.debug("SSL cert check failed for %s: %s", domain, exc)
            details["error"] = str(exc)

        return {"score": min(score, 50), "signals": signals, **details}

    # ──────────────────────────────────────────────────────────────────────────
    # CHECK 2: SPF + DMARC EMAIL AUTHENTICATION RECORDS
    # ──────────────────────────────────────────────────────────────────────────
    def _check_spf_dmarc(self, domain: str) -> Dict:
        """
        Checks email authentication DNS records.
        Every real company has SPF and DMARC.
        Their absence is one of the strongest scam signals.
        """
        score   = 0
        signals = []
        details: Dict[str, Any] = {"checked": True}

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        # ── SPF ────────────────────────────────────────────────────────────────
        spf_record  = None
        spf_found   = False
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(p.decode() if isinstance(p, bytes) else p
                              for p in rdata.strings)
                if txt.startswith("v=spf1"):
                    spf_found  = True
                    spf_record = txt
                    break
        except (dns.exception.DNSException, Exception):
            pass

        details["spf_found"]  = spf_found
        details["spf_record"] = spf_record

        if not spf_found:
            score += 30
            signals.append(
                f"NO SPF record on {domain} — every legitimate company "
                "email domain has one; its absence strongly suggests a fake domain"
            )
        elif spf_record and "+all" in spf_record:
            # +all = anyone can send email claiming to be from this domain
            score += 15
            signals.append(
                f"SPF record for {domain} uses '+all' (permissive) — "
                "allows anyone to spoof this domain"
            )

        # ── DMARC ─────────────────────────────────────────────────────────────
        dmarc_record = None
        dmarc_found  = False
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt = "".join(p.decode() if isinstance(p, bytes) else p
                              for p in rdata.strings)
                if txt.startswith("v=DMARC1"):
                    dmarc_found  = True
                    dmarc_record = txt
                    break
        except (dns.exception.DNSException, Exception):
            pass

        details["dmarc_found"]  = dmarc_found
        details["dmarc_record"] = dmarc_record

        if not dmarc_found:
            score += 20
            signals.append(
                f"NO DMARC record on {domain} — professional companies "
                "always configure DMARC to protect their brand from spoofing"
            )

        # Hard combo: both missing = almost certainly a fly-by-night domain
        if not spf_found and not dmarc_found:
            score += 10  # extra combo penalty
            signals.append(
                f"CRITICAL: {domain} has NEITHER SPF nor DMARC — "
                "this combination is extremely rare for legitimate recruiters"
            )

        # ── DKIM (check if selector 'default' exists as a heuristic) ──────────
        dkim_found = False
        for selector in ("default", "google", "mail", "smtp", "selector1", "k1"):
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                resolver.resolve(dkim_domain, "TXT")
                dkim_found = True
                break
            except Exception:
                pass

        details["dkim_found"] = dkim_found
        if not dkim_found:
            # DKIM alone not conclusive (many selectors possible), so small bonus
            score += 5
            signals.append(
                f"No common DKIM selector found for {domain} — "
                "email authentication setup appears incomplete"
            )

        return {"score": min(score, 60), "signals": signals, **details}

    # ──────────────────────────────────────────────────────────────────────────
    # CHECK 3: WAYBACK MACHINE FIRST-SEEN DATE  (CDX API)
    # ──────────────────────────────────────────────────────────────────────────
    def _check_wayback(self, domain: str) -> Dict:
        """
        Checks the Internet Archive's CDX API for the earliest snapshot
        of the domain. A company claiming years of experience but archived
        only 2 months ago is a major red flag.
        """
        score   = 0
        signals = []
        details: Dict[str, Any] = {"checked": True}

        try:
            # CDX: get the very first snapshot ever taken
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={domain}&output=json&limit=1&fl=timestamp"
                f"&from=19960101000000&fastLatest=false"
            )
            resp = _SESSION.get(url, timeout=self.TIMEOUT)
            resp.raise_for_status()
            rows = resp.json()

            # rows[0] is the header ["timestamp"], rows[1] is first result
            if not rows or len(rows) < 2:
                score += 20
                signals.append(
                    f"{domain} has NEVER been archived by the Wayback Machine — "
                    "completely new web presence, no history as a company"
                )
                details["never_archived"] = True
                return {"score": score, "signals": signals, **details}

            timestamp_str = rows[1][0]  # e.g. "20240203121500"
            first_seen = datetime.strptime(timestamp_str[:8], "%Y%m%d")
            first_seen = first_seen.replace(tzinfo=timezone.utc)
            now        = datetime.now(timezone.utc)
            age_days   = (now - first_seen).days

            details["first_archived"]   = first_seen.strftime("%Y-%m-%d")
            details["web_presence_days"] = age_days

            if age_days < 60:
                score += 30
                signals.append(
                    f"First web archive of {domain}: {first_seen.strftime('%b %Y')} "
                    f"({age_days} days ago) — brand new site claiming to be a company"
                )
            elif age_days < 180:
                score += 20
                signals.append(
                    f"First web archive of {domain}: {first_seen.strftime('%b %Y')} "
                    f"(~{age_days // 30} months ago) — very recently established"
                )
            elif age_days < 365:
                score += 10
                signals.append(
                    f"First web archive of {domain}: {first_seen.strftime('%b %Y')} "
                    f"— less than 1 year of web presence"
                )
            else:
                details["established"] = True  # no score penalty

        except requests.exceptions.Timeout:
            logger.debug("Wayback Machine timed out for %s", domain)
            details["timeout"] = True
        except Exception as exc:
            logger.debug("Wayback check failed for %s: %s", domain, exc)
            details["error"] = str(exc)

        return {"score": min(score, 40), "signals": signals, **details}

    # ──────────────────────────────────────────────────────────────────────────
    # CHECK 4: REVERSE IP — HOW MANY DOMAINS SHARE THIS IP?
    # ──────────────────────────────────────────────────────────────────────────
    def _check_reverse_ip(self, domain: str) -> Dict:
        """
        Resolves domain → IP, then queries HackerTarget's free reverse-IP API.
        Scam farms host hundreds of fake company domains on a single cheap IP.
        """
        score   = 0
        signals = []
        details: Dict[str, Any] = {"checked": True}

        try:
            # Resolve to IP
            ip = socket.gethostbyname(domain)
            details["ip"] = ip

            # Skip private / reserved IPs
            if ip.startswith(("10.", "172.", "192.168.", "127.")):
                return {"score": 0, "signals": [], **details}

            url  = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            resp = _SESSION.get(url, timeout=self.TIMEOUT)
            resp.raise_for_status()
            text = resp.text.strip()

            # HackerTarget returns "error" or "API count exceeded" on problems
            if "error" in text.lower() or "api" in text.lower():
                details["api_limit"] = True
                return {"score": 0, "signals": [], **details}

            co_domains = [d.strip() for d in text.splitlines() if d.strip()]
            count = len(co_domains)
            details["shared_ip_domain_count"] = count
            details["sample_shared_domains"]  = co_domains[:5]

            if count > 500:
                score += 25
                signals.append(
                    f"{domain} shares its IP ({ip}) with over {count} other domains "
                    "— classic scam-farm bulk hosting"
                )
            elif count > 150:
                score += 15
                signals.append(
                    f"{domain} shares its IP ({ip}) with {count} other domains "
                    "— high-density shared hosting typical of disposable scam sites"
                )
            elif count > 50:
                score += 8
                signals.append(
                    f"{domain} shares its IP ({ip}) with {count} other domains "
                    "— suspicious shared hosting"
                )

        except socket.gaierror:
            score += 10
            signals.append(
                f"Cannot resolve {domain} to an IP address — "
                "domain may not be properly configured or may not exist"
            )
            details["no_dns"] = True
        except requests.exceptions.Timeout:
            logger.debug("Reverse IP timed out for %s", domain)
            details["timeout"] = True
        except Exception as exc:
            logger.debug("Reverse IP check failed for %s: %s", domain, exc)
            details["error"] = str(exc)

        return {"score": min(score, 30), "signals": signals, **details}
