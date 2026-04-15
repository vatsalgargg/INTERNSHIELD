import time
from django.core.cache import cache

class VisitorTrackingMiddleware:
    """
    Forensic Intelligence Middleware
    Tracks real-time visitors in a stateless memory buffer.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # We don't track the admin dashboard itself to avoid infinite feedback for auto-refreshing stats
        if request.path.startswith('/admin-forensics/') or request.path.startswith('/static/'):
            return self.get_response(request)

        # 1. Increment Neural-Shield Detection Counter
        # We use hits as a proxy for "system operations"
        hits = cache.get('system_hits', 0)
        cache.set('system_hits', hits + 1, timeout=None)

        # 2. Capture Forensic Packet (Visitor Metadata)
        ip = self._get_client_ip(request)
        ua = request.META.get('HTTP_USER_AGENT', 'Unknown')
        
        # Simplified UA for the HUD
        ua_summary = "Terminal/Bot"
        if "Mobi" in ua: ua_summary = "Mobile"
        elif "Windows" in ua or "Macintosh" in ua or "Linux" in ua: ua_summary = "Desktop"

        log_entry = {
            'ip': self._mask_ip(ip),
            'method': request.method,
            'path': request.path,
            'ua': ua_summary,
            'time': time.strftime('%H:%M:%S'),
        }

        # 3. Update Volatile History Buffer
        history = cache.get('visitor_history', [])
        history.insert(0, log_entry)
        cache.set('visitor_history', history[:100], timeout=None) # Store last 100 packets

        response = self.get_response(request)
        return response

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _mask_ip(self, ip):
        """Mask IP for forensic privacy (Neural-Shield standard)."""
        if not ip: return "?.?.?.?"
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.xxx.xxx"
        return "IPv6_HIDDEN"
