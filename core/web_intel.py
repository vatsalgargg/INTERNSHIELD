"""
InternShield — Web Intelligence Module
========================================
Uses Serper.dev API for:
  - Company reputation & news search
  - LinkedIn employee verification
  - Scam complaints / reviews lookup
  - MCA public record search
  - General OSINT on suspicious senders

Requires:
  SERPER_API_KEY
"""

import re
import json
import requests
from typing import Dict, Any, List, Optional

from . import config

class WebIntelligence:
    """
    Real web search intelligence using Serper.dev (Google Search API).
    """

    SERPER_URL = "https://google.serper.dev/search"
    REQUEST_TIMEOUT = 10

    def __init__(self):
        self.api_key = config.SERPER_API_KEY
        self.last_error_code = None 

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC INTERFACE
    # ──────────────────────────────────────────────────────────────────────────

    def _is_indian_entity(self, company_name: str, domain: str) -> bool:
        """
        Determines using heuristics if a company is Indian.
        """
        # 1. Indian TLDs are always Indian
        if domain:
            indian_tlds = [".in", ".co.in", ".ind.in", ".net.in", ".org.in", ".gen.in", ".firm.in"]
            if any(domain.endswith(t) for t in indian_tlds):
                return True

            # 2. Known Foreign TLDs are not Indian
            foreign_tlds = [".jp", ".us", ".uk", ".au", ".ca", ".de", ".fr", ".cn", ".ru", ".br"]
            if any(domain.endswith(t) for t in foreign_tlds):
                return False

        # 3. Explicit Indian name markers
        name_lower = company_name.lower()
        indian_markers = [
            "india", "bharat", "pvt ltd", "private limited", "pvt. ltd.", "pvt.ltd", 
            "pvt.ltd.", "llp", "limited liability partnership"
        ]
        if any(m in name_lower for m in indian_markers):
            return True

        # 4. If it's a .com/.net/.org and doesn't have Indian markers, 
        # assume it's global/foreign to avoid false positive MCA flags.
        return False

    def investigate_company(self, company_name: str, domain: str = "") -> Dict[str, Any]:
        """
        Full OSINT sweep on a company.
        """
        self.last_error_code = None 
        
        result = {
            "company_name":       company_name,
            "domain":             domain,
            "mca_web_result":     {},
            "linkedin_result":    {},
            "scam_reports":       {},
            "news_results":       [],
            "overall_web_risk":   0,
            "risk_signals":       [],
            "sources_checked":    [],
            "search_status":      "ok"
        }

        # 1. API Verification
        api_ready = bool(self.api_key)

        # Warm-up search to check API health (only if api_ready)
        if api_ready:
            self._serper_search("health check")

        # 2. Check if Company is Indian
        is_indian = self._is_indian_entity(company_name, domain)

        # 2. MCA Registration
        if api_ready:
            result["mca_web_result"]  = self.search_mca_registration(company_name)
            result["sources_checked"].append("Ministry of Corporate Affairs")
        else:
            result["mca_web_result"] = {"found": False, "skipped": True, "details": "Serper API Key Missing"}
            result["sources_checked"].append("MCA Web Search (Skipped - Key Missing)")

        # 4. LinkedIn presence
        if api_ready:
            result["linkedin_result"] = self.check_linkedin(company_name, domain)
            result["sources_checked"].append("LinkedIn")
        else:
            result["linkedin_result"] = {"found": False, "is_suspicious": False, "snippet": "Skipped - API Key Missing"}

        # 5. Reddit & Glassdoor Community Intel
        if api_ready:
            result["community_reviews"] = self.check_community_reviews(company_name)
            result["sources_checked"].append("Reddit & Glassdoor")
        else:
            result["community_reviews"] = {"reddit": [], "glassdoor": [], "skipped": True}

        # 6. Check if search actually failed
        if self.last_error_code in [403, 401]:
            result["search_status"] = "auth_error"
        elif self.last_error_code == 429:
            result["search_status"] = "rate_limit"

        # Aggregate risk
        risk_score, signals = self._compute_risk(result, api_ready)
        result["overall_web_risk"] = risk_score
        result["risk_signals"]     = signals
        result["is_indian_flag"]   = is_indian
        
        return result

    def check_community_reviews(self, company_name: str) -> Dict[str, Any]:
        """
        Retrieves company reviews from Reddit and Glassdoor using site-specific searches.
        """
        community = {
            "reddit": [],
            "glassdoor": [],
            "scam_sentiment_detected": False,
            "snippet_count": 0
        }

        # 1. Reddit Search: targeted for scams/reviews
        reddit_query = f'site:reddit.com "{company_name}" scam OR reviews OR legit'
        reddit_results = self._serper_search(reddit_query)
        for res in reddit_results[:3]: # Top 3 snippets
            community["reddit"].append({
                "title": res.get("title", ""),
                "snippet": res.get("snippet", ""),
                "link": res.get("link", "")
            })
            if any(k in res.get("snippet", "").lower() for k in ["scam", "fake", "predatory", "fraud"]):
                community["scam_sentiment_detected"] = True

        # 2. Glassdoor Search: targeted for salary/interviews/reviews
        # We try .co.in first for Indian context, fallback or include .com
        gd_query = f'site:glassdoor.co.in OR site:glassdoor.com "{company_name}" reviews OR "working at"'
        gd_results = self._serper_search(gd_query)
        for res in gd_results[:3]:
            community["glassdoor"].append({
                "title": res.get("title", ""),
                "snippet": res.get("snippet", ""),
                "link": res.get("link", "")
            })

        community["snippet_count"] = len(community["reddit"]) + len(community["glassdoor"])
        return community

    def search_mca_registration(self, company_name: str) -> Dict[str, Any]:
        """
        Search for company registration on MCA (India).
        """
        result = {
            "found":      False,
            "skipped":    False,
            "source":     "",
            "details":    "",
            "search_url": config.MCA_MANUAL_LINK,
        }

        # Robust search: site:mca.gov.in {Name} Master Data
        # We remove quotes to allow variations (e.g. Bando vs Bando Chemical)
        # Professional search across official portal and trusted aggregators (Tofler, ZaubaCorp, InstaFinancials)
        # These sites are much more reliably indexed than the official mca.gov.in
        query   = f'{company_name} (site:mca.gov.in OR site:zaubacorp.com OR site:tofler.in OR site:instafinancials.com) Master Data'
        results = self._serper_search(query)
        
        # Fallback: Try Name with quotes only if no results
        if not results:
            query = f'site:mca.gov.in "{company_name}"'
            results = self._serper_search(query)
        
        if self.last_error_code:
            result["skipped"] = True
            result["details"] = "Serper API Error (Check configuration)"
            return result

        if results:
            top = results[0]
            link = top.get("link", "").lower()
            
            # Identify the source
            source_name = "MCA Records"
            if "zaubacorp" in link: source_name = "ZaubaCorp"
            elif "tofler" in link: source_name = "Tofler"
            elif "instafinancials" in link: source_name = "InstaFinancials"
            elif "mca.gov.in" in link: source_name = "Official MCA Portal"
            
            # CIN extraction
            cin_match = re.search(r'\b[UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b', top.get("snippet", "") + " " + link)
            
            # STRICT VERIFICATION: We only trigger 'found' if we have a CIN or very high confidence
            is_high_confidence = cin_match is not None
            
            result["found"]      = is_high_confidence
            result["source"]     = f"Serper Search → {source_name}"
            result["details"]    = top.get("snippet", "")
            result["search_url"] = top.get("link", result["search_url"])
            
            if cin_match:
                result["cin"] = cin_match.group(0)
            else:
                result["cin"] = ""
                # If no CIN, we mark it as a potential match but NOT verified
                result["potential_match"] = True
        else:
            result["details"] = "No matching Indian corporate records found"
        return result

    def check_linkedin(self, company_name: str, domain: str = "") -> Dict[str, Any]:
        """
        Check LinkedIn presence.
        Try Name first, then fallback to Domain.
        """
        result = {
            "found":            False,
            "url":              f"https://www.linkedin.com/search/results/companies/?keywords={requests.utils.quote(company_name)}",
            "snippet":          "",
            "employee_signals": [],
            "is_suspicious":    False,
        }

        # Try 1: Specific Company Profile
        query   = f'site:linkedin.com/company "{company_name}"'
        results = self._serper_search(query)

        # Try 2: Broad LinkedIn Search (sometimes pages aren't under /company/ prefix reliably)
        if not results:
            query = f'site:linkedin.com "{company_name}" about employees'
            results = self._serper_search(query)

        # Try 3: Fallback to Domain if no results for name
        if not results and domain:
             query = f'site:linkedin.com/company "{domain}"'
             results = self._serper_search(query)

        if results:
            top = results[0]
            result["found"]   = True
            result["url"]     = top.get("link", result["url"])
            result["snippet"] = top.get("snippet", "")

            snip_lower = result["snippet"].lower()
            if any(k in snip_lower for k in ["followers", "employees", "connections", "workers"]):
                result["employee_signals"].append("LinkedIn page exists with employee/follower metrics")
            
            if re.search(r'\b(0|1)\b\s+employee', snip_lower):
                result["is_suspicious"] = True
                result["employee_signals"].append("Company claims abnormally low employee count (0-1) — likely shell company")
        else:
            if not self.last_error_code:
                result["is_suspicious"] = True
                result["snippet"] = "Company NOT found on LinkedIn — legitimacy red flag"

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # SERPER.DEV SEARCH
    # ──────────────────────────────────────────────────────────────────────────

    def _serper_search(self, query: str) -> List[Dict]:
        """
        Call Serper.dev API.
        Docs: https://serper.dev/
        """
        if not self.api_key:
            return []

        headers = {
            'X-API-KEY': self.api_key,
            'Content-Type': 'application/json'
        }
        payload = json.dumps({"q": query})

        try:
            resp = requests.post(
                self.SERPER_URL,
                headers=headers,
                data=payload,
                timeout=self.REQUEST_TIMEOUT,
            )
            
            if resp.status_code == 200:
                data = resp.json()
                # Serper returns 'organic' results
                return data.get("organic", [])
            else:
                self.last_error_code = resp.status_code
        except Exception:
            pass
        return []

    # ──────────────────────────────────────────────────────────────────────────
    # RISK AGGREGATION
    # ──────────────────────────────────────────────────────────────────────────

    def _compute_risk(self, result: Dict, api_ready: bool) -> tuple:
        score   = 0
        signals = []

        status = result.get("search_status")
        if not api_ready:
            signals.append("Missing Serper API Key — OSINT Web Intelligence was completely skipped.")
            return score, signals
        
        if status == "auth_error":
            signals.append("⚠️ Serper API 'Unauthorized' — Please check your SERPER_API_KEY in config.py.")
            return score, signals 
        
        if status == "rate_limit":
            signals.append("⚠️ Serper rate limit reached — please upgrade your free tier.")
            return score, signals

        mca = result.get("mca_web_result", {})
        is_indian = self._is_indian_entity(result.get("company_name", ""), result.get("domain", ""))
        
        if mca.get("found"):
            signals.append(f"✅ Verified Registration: {mca.get('source')} (CIN found)")
        elif mca.get("skipped"):
            signals.append(mca.get("details", "OSINT check skipped"))
        else:
            # Not found on MCA
            if is_indian:
                # Strong evidence it's Indian, but no record found -> Red Flag
                score += 25
                signals.append(f"❌ Missing Registration: Company claims to be Indian (or uses .in domain) but was NOT found in corporate records.")
            else:
                # Ambiguous or likely global entity -> No penalty
                signals.append(f"ℹ️ Global Entity Check: No Indian record found (typical for non-Indian companies).")

        li = result.get("linkedin_result", {})
        if not li.get("found"):
            if not self.last_error_code:
                score += 20
                signals.append("Company has NO clear LinkedIn presence — major legitimacy red flag")
        elif li.get("is_suspicious"):
            score += 10
            signals.append("LinkedIn profile exists but claims 0-1 employees (suspicious/shell company signature)")

        comm = result.get("community_reviews", {})
        if comm.get("scam_sentiment_detected"):
            score += 25
            signals.append("🚨 COMMUNITY ALERT: Negative sentiment/scam reports found on Reddit/Community forums.")

        return min(score, 100), signals
