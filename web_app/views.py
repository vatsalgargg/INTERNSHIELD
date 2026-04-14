import os
import tempfile
import logging
import traceback
import bleach
import magic
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseForbidden
from django.core.files.storage import FileSystemStorage
# Fallback for version differences in django-ratelimit
try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    try:
        from ratelimit.decorators import ratelimit
    except ImportError:
        # Fallback to no-op if ratelimit is completely missing (should not happen in prod)
        def ratelimit(*args, **kwargs):
            return lambda f: f

# Import the existing tools from the parent directory / project root
from core import (
    ScamAnalyzer, 
    DomainChecker, 
    WebIntelligence, 
    GmailScanner, 
    config
)

logger = logging.getLogger(__name__)

def index(request):
    """Render the dashboard/homepage."""
    return render(request, 'web_app/index.html')

def scan_gmail(request):
    """Scan the user's Gmail inbox - Feature NOW 'COMING SOON' for stability."""
    return render(request, 'web_app/scan_gmail.html', {
        'coming_soon': True,
        'feature_name': 'GMAIL_INBOX_GATEWAY'
    })

def gmail_auth(request):
    """OAuth Initiate - Disabled"""
    return HttpResponseForbidden("This feature is currently under maintenance. Stay tuned for Neural-Shield v5.")

def gmail_callback(request):
    """OAuth Callback - Disabled"""
    return HttpResponseForbidden("Access Denied: Feature Disabled.")

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def analyze_offer(request):
    """Upload and analyze a PDF/DOCX offer letter."""
    if request.method == 'POST' and request.FILES.get('offer_letter'):
        file = request.FILES['offer_letter']
        
        # 🛡️ Security Check: File Size (5MB limit)
        if file.size > 5 * 1024 * 1024:
            logger.warning(f"Security Alert: Large file upload attempt from {request.META.get('REMOTE_ADDR')}")
            return render(request, 'web_app/offer_results.html', {
                'result': {'error': "FORBIDDEN: Payload too large. Limit is 5MB.", 'dashoffset': 502.6}
            })

        fs = FileSystemStorage(location='/tmp')
        filename = None
        
        try:
            filename = fs.save(file.name, file)
            filepath = fs.path(filename)
            
            # 🛡️ Security Check: Mime-type Sniffing
            mime = magic.from_file(filepath, mime=True)
            allowed_mimes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
            if mime not in allowed_mimes:
                logger.warning(f"Security Alert: Invalid mime type {mime} from {request.META.get('REMOTE_ADDR')}")
                return render(request, 'web_app/offer_results.html', {
                    'result': {'error': "FORBIDDEN: Protocol mismatch. Only PDF/DOCX accepted.", 'dashoffset': 502.6}
                })

            analyzer = ScamAnalyzer()
            result = analyzer.analyze_file(filepath)
            
            score = result.get('final_score', 0)
            result['dashoffset'] = 502.6 * (1 - (score / 100))
            
            return render(request, 'web_app/offer_results.html', {'result': result})
            
        except Exception as e:
            logger.error(f"Forensic Lab Error: {str(e)}")
            return render(request, 'web_app/offer_results.html', {
                'result': {
                    'error': f"Internal Analysis Error",
                    'risk_score': 0,
                    'dashoffset': 502.6,
                    'risk_signals': ["SYSTEM_EXCEPTION_CAUGHT: Analysis process failed."]
                }
            })
        finally:
            if filename:
                try:
                    fs.delete(filename)
                except Exception: pass
        
    return render(request, 'web_app/analyze_offer.html')

@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def paste_email(request):
    """Paste and analyze raw email text."""
    if request.method == 'POST':
        # 🛡️ Sanitization: Bleach raw text
        raw_input = request.POST.get('raw_email', '')
        raw_text = bleach.clean(raw_input, tags=[], strip=True) 
        
        did_apply = request.POST.get('did_apply', 'unknown')
        
        try:
            import re
            from datetime import datetime
            
            # Extract metadata safely
            sender_match = re.search(r'From:\s*(.+)', raw_text, re.IGNORECASE)
            subj_match   = re.search(r'Subject:\s*(.+)', raw_text, re.IGNORECASE)
            
            sender  = sender_match.group(1).strip() if sender_match else ""
            subject = subj_match.group(1).strip()   if subj_match   else ""

            email_addr_match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', raw_text)
            email_addr       = email_addr_match.group(0) if email_addr_match else ""
            
            if not sender and email_addr: sender = email_addr
            elif not sender: sender = "Unknown"

            if not subject:
                lines = [l.strip() for l in raw_text.split('\n') if l.strip()]
                subject = lines[0][:100] if lines else "Pasted Email"

            domain = email_addr.split("@")[-1] if "@" in email_addr else ""

            email_dict = {
                "id":            "pasted",
                "subject":       subject,
                "sender":        sender,
                "sender_email":  email_addr,
                "sender_domain": domain,
                "date":          datetime.now().strftime("%Y-%m-%d"),
                "body":          raw_text,
                "html":          "",
                "attachments":   [],
                "links":         re.findall(r'https?://[^\s\'"<>]+', raw_text),
            }
            
            applied_by_user = True if did_apply == "yes" else (False if did_apply == "no" else None)
            
            analyzer = ScamAnalyzer()
            result = analyzer.analyze_email(email_dict, applied_by_user=applied_by_user)
            
            score = result.get('risk_score', 0)
            result['dashoffset'] = 502.6 * (1 - (score / 100))
            
            return render(request, 'web_app/gmail_results.html', {'results': [result]})
            
        except Exception as e:
            logger.error(f"Live Paste Error: {str(e)}")
            return render(request, 'web_app/gmail_results.html', {
                'results': [{
                    'error': f"Processing Error",
                    'subject': "Internal Error",
                    'risk_score': 0,
                    'dashoffset': 502.6,
                    'signals': ["The system encountered an error parsing this packet."]
                }]
            })
        
    return render(request, 'web_app/paste_email.html')

@ratelimit(key='ip', rate='15/m', method='POST', block=True)
def check_domain(request):
    """Check a company domain and MCA status."""
    if request.method == 'POST':
        # 🛡️ Sanitization
        name = bleach.clean(request.POST.get('company_name', '').strip(), tags=[], strip=True)
        domain = bleach.clean(request.POST.get('company_domain', '').strip(), tags=[], strip=True)
        
        checker = DomainChecker()
        wi = WebIntelligence()
        
        domain_result = None
        osint = None
        
        try:
            if domain:
                domain_result = checker.analyze(domain)
            if name:
                osint = wi.investigate_company(name, domain=domain)
                if osint and osint.get("scam_reports", {}).get("complaints_found"):
                    snippets = osint["scam_reports"].get("snippets", [])
                    sources = osint["scam_reports"].get("sources", [])
                    osint["scam_reports"]["zipped_evidence"] = list(zip(snippets, sources))[:4]
                
            return render(request, 'web_app/domain_results.html', {
                'company_name': name,
                'domain': domain,
                'domain_result': domain_result,
                'osint': osint
            })
        except Exception as e:
            logger.error(f"OSINT Error: {str(e)}")
            return render(request, 'web_app/domain_results.html', {'error': "Search stream interrupted."})
        
    return render(request, 'web_app/check_domain.html')
