# web-vuln-scanner

GUI-based web configuration vulnerability scanner available as both a live browser web app and a Python desktop GUI tool.

## Live Web App
Run directly in your browser without any setup:
https://shashwat-code-10.github.io/web-vuln-scanner/

## Checks
- HTTP vs HTTPS encryption
- Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Server banner leaks (Server, X-Powered-By)
- Cookie flags (Secure, HttpOnly) & DNS security records (SPF, CAA)

## Desktop GUI Setup & Run
    pip install -r requirements.txt
    python scanner.py

Output saves to scan_report.txt. For educational and authorized testing only.
