import socket
import ssl
import requests
# Attempt to import python-whois
try:
    import whois as _whois_module
except Exception:
    _whois_module = None

import os
import sys
import smtplib
import subprocess
import shutil
import re
import time

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# For screenshots
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# --------------------------
# Universal Paths
# --------------------------
if getattr(sys, "frozen", False):
    BASE_DIR = sys._MEIPASS          # read-only bundle dir
    APP_DIR = os.path.dirname(sys.executable)  # folder where exe lives (writable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = BASE_DIR

SAVE_PATH = os.path.join(APP_DIR, "reports")

# --------------------------
# Fix WHOIS data path
# --------------------------
def fix_whois_data_path():
    if not _whois_module:
        return
    try:
        if hasattr(sys, "_MEIPASS"):
            datadir = os.path.join(sys._MEIPASS, "whois", "data")
        else:
            datadir = os.path.join(os.path.dirname(_whois_module.__file__), "data")

        suffix_file = os.path.join(datadir, "public_suffix_list.dat")
        if os.path.exists(suffix_file):
            _whois_module.validTlds = _whois_module.load_file(suffix_file)
    except Exception as e:
        print(f"[!] WHOIS data path fix failed: {e}")

fix_whois_data_path()

# --------------------------
# Email Function
# --------------------------
def send_email_report(sender_email, sender_password, recipient_email, pdf_path):
    try:
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = recipient_email
        msg["Subject"] = "Cybersecurity Recon Report"

        body = "Hello,\n\nPlease find attached the recon report.\n\nRegards,\nCyber Recon Tool"
        msg.attach(MIMEText(body, "plain"))

        with open(pdf_path, "rb") as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(pdf_path))
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(pdf_path)}"'
            msg.attach(part)

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()

        return "[+] Email sent successfully!"
    except Exception as e:
        return f"[!] Email sending failed: {e}"

# --------------------------
# nslookup
# --------------------------
def run_nslookup(hostname):
    if not shutil.which("nslookup"):
        return "[!] nslookup tool not found on this system."
    try:
        proc = subprocess.run(["nslookup", hostname], capture_output=True, text=True, timeout=10)
        out = proc.stdout.strip()
        if not out:
            out = proc.stderr.strip() or "No output from nslookup."
        return out
    except Exception as e:
        return f"[!] nslookup failed: {e}"

# --------------------------
# Banner grab
# --------------------------
def banner_grab(host, ports=(80, 443, 22, 21, 8080)):
    banners = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            res = sock.connect_ex((host, port))
            if res != 0:
                sock.close()
                continue
            if port in (80, 8080):
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                    resp = sock.recv(4096).decode(errors="ignore")
                    banners[port] = resp.split("\r\n\r\n", 1)[0]
                except Exception:
                    banners[port] = "Open (couldn't read HTTP banner)"
            elif port == 443:
                try:
                    ctx = ssl.create_default_context()
                    ss = ctx.wrap_socket(sock, server_hostname=host)
                    ss.settimeout(3.0)
                    ss.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                    resp = ss.recv(4096).decode(errors="ignore")
                    banners[port] = resp.split("\r\n\r\n", 1)[0]
                    ss.close()
                except Exception:
                    banners[port] = "Open (SSL but couldn't read banner)"
            else:
                try:
                    sock.settimeout(2.0)
                    data = sock.recv(4096)
                    banners[port] = data.decode(errors="ignore").strip() if data else "Open (no banner)"
                except Exception:
                    banners[port] = "Open (no readable banner)"
            sock.close()
        except Exception as e:
            banners[port] = f"error: {e}"
    return banners

# --------------------------
# Tech detection
# --------------------------
def detect_technologies(hostname):
    techs = set()
    try:
        url = "http://" + hostname
        resp = requests.get(url, timeout=6, allow_redirects=True)
        headers = resp.headers
        body = resp.text
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")
        if server:
            techs.add(f"Server header: {server}")
            if "apache" in server.lower(): techs.add("Apache")
            if "nginx" in server.lower(): techs.add("nginx")
        if x_powered:
            techs.add(f"X-Powered-By: {x_powered}")
            if "php" in x_powered.lower(): techs.add("PHP")
        if re.search(r'wp-content|wp-includes', body, re.I):
            techs.add("WordPress")
        return {"guesses": sorted(techs), "headers": {k: headers[k] for k in ("Server", "X-Powered-By") if k in headers}}
    except Exception as e:
        return {"error": f"Tech detection failed: {e}"}

# --------------------------
# WHOIS helper
# --------------------------
def get_whois(hostname):
    if _whois_module:
        try:
            if hasattr(_whois_module, "whois"):
                w = _whois_module.whois(hostname)
                return str(w)
            else:
                return "[!] Installed 'whois' module missing whois() function."
        except Exception as e:
            return f"[!] python-whois query failed: {e}"

    if shutil.which("whois"):
        try:
            proc = subprocess.run(["whois", hostname], capture_output=True, text=True, timeout=15)
            out = proc.stdout.strip()
            return out if out else "[!] whois command returned no output."
        except Exception as e:
            return f"[!] system whois failed: {e}"

    return "[!] WHOIS not available: install python-whois or system whois."

# --------------------------
# Screenshot helper (fixed)
# --------------------------
def capture_screenshot(url, save_path, hostname):
    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1280,1024")

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)

        driver.get(url)

        screenshot_path = os.path.join(save_path, f"{hostname}_screenshot.png")
        driver.save_screenshot(screenshot_path)
        driver.quit()
        return screenshot_path
    except Exception as e:
        return f"[!] Screenshot failed: {e}"

# --------------------------
# Main Recon
# --------------------------
def run_full_recon(target_url, save_path):
    results = []
    start_time = time.strftime("%Y-%m-%d %H:%M:%S")
    results.append(f"[+] Recon started: {start_time}")
    results.append(f"[+] Target: {target_url}\n")

    hostname = target_url.replace("https://", "").replace("http://", "").split("/")[0]

    # DNS resolution
    try:
        ip = socket.gethostbyname(hostname)
        results.append(f"[+] IP Address: {ip}")
    except Exception as e:
        results.append(f"[!] DNS failed: {e}")
        ip = "N/A"

    results.append("\n[+] nslookup output:")
    results.append(run_nslookup(hostname))

    results.append("\n[+] WHOIS Information:")
    results.append(get_whois(hostname))

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            results.append("\n[+] SSL Certificate:")
            results.append(str(cert))
    except Exception as e:
        results.append(f"[!] SSL failed: {e}")

    open_ports = []
    for port in [21, 22, 80, 443, 8080, 3306]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if ip != "N/A" and sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    results.append("\n[+] Open Ports:")
    results.append(str(open_ports if open_ports else "None"))

    try:
        r = requests.get("http://" + hostname, timeout=6)
        results.append("\n[+] HTTP Headers:")
        results.append(str(dict(r.headers)))
    except Exception as e:
        results.append(f"[!] HTTP failed: {e}")

    results.append("\n[+] Technology fingerprints:")
    techs = detect_technologies(hostname)
    if "error" in techs:
        results.append(techs["error"])
    else:
        if techs.get("headers"):
            results.append(f"Header hints: {techs['headers']}")
        guesses = techs.get("guesses", [])
        results.append(f"Guesses: {', '.join(guesses) if guesses else 'None'}")

    results.append("\n[+] Banner grab:")
    banners = banner_grab(hostname)
    for p, b in banners.items():
        results.append(f"Port {p}: {b}")

    # Screenshot
    results.append("\n[+] Website Screenshot:")
    screenshot_path = capture_screenshot("http://" + hostname, save_path, hostname)
    if isinstance(screenshot_path, str) and os.path.exists(screenshot_path):
        results.append(f"[+] Screenshot saved: {screenshot_path}")
    else:
        results.append(str(screenshot_path))

    results.append("\n[✔] Recon Completed!")

    os.makedirs(save_path, exist_ok=True)
    pdf_filename = os.path.join(save_path, f"{hostname}_report.pdf")

    try:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(pdf_filename, pagesize=A4)
        story = []
        story.append(Paragraph("Cybersecurity Recon Report", styles["Title"]))
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(f"Target: {target_url}", styles["Normal"]))
        story.append(Paragraph(f"Generated: {start_time}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))
        for entry in results:
            story.append(Paragraph(str(entry).replace("\n", "<br/>"), styles["Normal"]))
            story.append(Spacer(1, 0.12 * inch))

        # Add screenshot inside PDF
        if isinstance(screenshot_path, str) and os.path.exists(screenshot_path):
            story.append(Spacer(1, 0.3 * inch))
            story.append(Paragraph("Website Screenshot:", styles["Heading2"]))
            story.append(RLImage(screenshot_path, width=400, height=300))

        doc.build(story)
        results.append(f"\n[+] PDF Report saved: {pdf_filename}")
    except Exception as e:
        results.append(f"[!] PDF save failed: {e}")

    return "\n".join(results), pdf_filename
