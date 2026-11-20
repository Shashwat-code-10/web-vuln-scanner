import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
from datetime import datetime

HEADERS_TO_CHECK = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]

def run_scan():
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a target URL.")
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"Scanning {url} ...\n\n")
    root.update()

    issues = []

    try:
        res = requests.get(url, timeout=10)
        headers = res.headers

        if not res.url.startswith("https://"):
            issues.append("[HIGH] Not using HTTPS")

        for h in HEADERS_TO_CHECK:
            if h not in headers:
                issues.append(f"[MEDIUM] Missing header: {h}")

        for h in ["Server", "X-Powered-By"]:
            if h in headers:
                issues.append(f"[LOW] Exposed {h} header: {headers[h]}")

        for cookie in res.cookies:
            if not cookie.secure:
                issues.append(f"[MEDIUM] Cookie '{cookie.name}' missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append(f"[MEDIUM] Cookie '{cookie.name}' missing HttpOnly flag")

    except requests.exceptions.RequestException as e:
        output_box.insert(tk.END, f"Error connecting to {url}:\n{e}\n")
        return

    output_box.insert(tk.END, f"Done. Found {len(issues)} issue(s):\n\n")
    for issue in issues:
        output_box.insert(tk.END, f" - {issue}\n")

    with open("scan_report.txt", "w") as f:
        f.write(f"Target: {url}\nTime: {datetime.now()}\n\n")
        if issues:
            for issue in issues:
                f.write(issue + "\n")
        else:
            f.write("No basic issues found.\n")

    output_box.insert(tk.END, "\nSaved results to scan_report.txt\n")

root = tk.Tk()
root.title("Web Vulnerability Scanner")
root.geometry("580x400")
root.configure(padx=15, pady=15)

top_frame = tk.Frame(root)
top_frame.pack(fill=tk.X, pady=(0, 10))

tk.Label(top_frame, text="Target URL:").pack(side=tk.LEFT)
url_entry = tk.Entry(top_frame, width=40)
url_entry.pack(side=tk.LEFT, padx=8, expand=True, fill=tk.X)
url_entry.insert(0, "example.com")

scan_btn = tk.Button(top_frame, text="Start Scan", command=run_scan, bg="#2563eb", fg="white", padx=12)
scan_btn.pack(side=tk.RIGHT)

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=18, font=("Consolas", 10))
output_box.pack(fill=tk.BOTH, expand=True)

root.mainloop()
