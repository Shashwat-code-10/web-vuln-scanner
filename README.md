# web-vuln-scanner

GUI-based Python tool to check websites for common HTTP security header, HTTPS, and cookie misconfigurations.

## Checks
- HTTP vs HTTPS encryption
- Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Server banner leaks (Server, X-Powered-By)
- Cookie flags (Secure, HttpOnly)

## Setup & Run
Run these commands in your terminal:

    pip install -r requirements.txt
    python scanner.py

Output saves to scan_report.txt.
