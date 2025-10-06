#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import time
import sys
import os
import nmap
import dns.resolver
from playwright.sync_api import sync_playwright


# ---- Subdomain Enumeration ----
def enumerate_subdomains(domain, wordlist=["www", "admin", "login", "api", "dev", "test", "mail", "ftp"]):
    print(f"\n[+] Enumerating subdomains for {domain}")
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    for sub in wordlist:
        try:
            full_domain = f"{sub}.{domain}"
            answers = resolver.resolve(full_domain, 'A')
            for rdata in answers:
                print(f"    [+] Found: {full_domain} -> {rdata}")
                found.append(full_domain)
        except Exception:
            pass
    return found


# ---- Screenshot Capture ----
def capture_screenshots(urls, output_dir="screenshots"):
    print(f"\n[+] Capturing screenshots for {len(urls)} URLs")
    os.makedirs(output_dir, exist_ok=True)
    screenshot_files = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        for idx, url in enumerate(urls):
            try:
                page = context.new_page()
                page.goto(url, timeout=10000)
                filename = os.path.join(output_dir, f"screenshot_{idx+1}.png")
                page.screenshot(path=filename, full_page=True)
                screenshot_files.append(os.path.abspath(filename))
                print(f"    [Screenshot] Saved: {filename}")
            except Exception as e:
                print(f"    [!] Failed to capture {url}: {e}")
        browser.close()
    return screenshot_files


# ---- Brute-force Login Testing ----
def brute_force_login(forms, wordlist=["admin", "password", "123456", "guest"], max_attempts=5):
    print("\n[+] Attempting brute-force login on discovered forms")
    successes = []
    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        if not any(inp.lower() in ["user", "username", "email"] for inp in inputs) or not any(inp.lower() in ["pass", "password"] for inp in inputs):
            continue

        print(f"    [Testing] {action}")
        count = 0
        for user in wordlist:
            for pwd in wordlist:
                if count >= max_attempts:
                    break
                data = {}
                for inp in inputs:
                    if "user" in inp.lower() or "email" in inp.lower():
                        data[inp] = user
                    elif "pass" in inp.lower():
                        data[inp] = pwd
                    else:
                        data[inp] = "test"

                try:
                    if method == "POST":
                        res = requests.post(action, data=data, timeout=5)
                    else:
                        res = requests.get(action, params=data, timeout=5)
                    if res.status_code == 200 and ("dashboard" in res.text.lower() or "logout" in res.text.lower()):
                        print(f"        [SUCCESS] {user}:{pwd}")
                        successes.append({"form": action, "credentials": f"{user}:{pwd}"})
                        break
                except Exception:
                    pass
                count += 1
    return successes


# ---- ZAP Integration Class ----
class ZAPScanner:
    def __init__(self, zap_api_url="http://127.0.0.1:8080", apikey=None):
        self.zap_api_url = zap_api_url.rstrip('/')
        self.apikey = apikey

    def access_url(self, url):
        try:
            params = {"url": url}
            if self.apikey:
                params["apikey"] = self.apikey
            requests.get(f"{self.zap_api_url}/JSON/core/action/accessUrl/", params=params, timeout=5)
            print(f"[+] Accessed URL: {url}")
        except Exception as e:
            print(f"[!] Failed to access {url}: {e}")

    def start_active_scan(self, url):
        try:
            params = {"url": url}
            if self.apikey:
                params["apikey"] = self.apikey
            res = requests.get(f"{self.zap_api_url}/JSON/ascan/action/scan/", params=params, timeout=10)
            scan_id = res.json().get("scan", "")
            print(f"[+] Started active scan on {url} with scan ID: {scan_id}")
            return scan_id
        except Exception as e:
            print(f"[!] Failed to start scan on {url}: {e}")
            return None

    def wait_for_scan(self, scan_id):
        while True:
            try:
                params = {"scanId": scan_id}
                if self.apikey:
                    params["apikey"] = self.apikey
                res = requests.get(f"{self.zap_api_url}/JSON/ascan/view/status/", params=params, timeout=5)
                status = res.json().get("status", "0")
                print(f"[+] Scan progress: {status}%")
                if int(status) >= 100:
                    break
                time.sleep(5)
            except Exception as e:
                print(f"[!] Error polling scan status: {e}")
                break

    def get_alerts(self, baseurl=None):
        try:
            params = {}
            if self.apikey:
                params["apikey"] = self.apikey
            if baseurl:
                params["baseurl"] = baseurl
            res = requests.get(f"{self.zap_api_url}/JSON/core/view/alerts/", params=params, timeout=10)
            raw_alerts = res.json().get("alerts", [])
            
            filtered_alerts = []
            for alert in raw_alerts:
                filtered_alert = {
                    "alert": alert.get("alert", ""),
                    "risk": alert.get("risk", ""),
                    "url": alert.get("url", ""),
                    "param": alert.get("param", ""),
                    "attack": alert.get("attack", ""),
                    "evidence": alert.get("evidence", ""),
                    "cweid": alert.get("cweid", ""),
                    "confidence": alert.get("confidence", "")
                }
                if any(value for value in filtered_alert.values()):
                    filtered_alerts.append(filtered_alert)
            return filtered_alerts
        except Exception as e:
            print(f"[!] Failed to fetch alerts: {e}")
            return []


# ---- Smart Crawler Class ----
class SmartCrawler:
    def __init__(self, base_url, max_pages=30):
        self.base_url = base_url.rstrip('/')
        self.visited = set()
        self.to_visit = [base_url]
        self.forms = []
        self.max_pages = max_pages

    def is_valid(self, url):
        try:
            return urlparse(url).netloc == urlparse(self.base_url).netloc
        except Exception:
            return False

    def normalize_url(self, url):
        parsed = urlparse(url)
        query = sorted(q.split('=') for q in parsed.query.split("&") if q)
        normalized_query = "&".join("=".join(pair) for pair in query)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{normalized_query}" if normalized_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self):
        page_count = 0
        while self.to_visit and page_count < self.max_pages:
            url = self.to_visit.pop(0)
            url = self.normalize_url(url)
            if url in self.visited:
                continue

            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                response = requests.get(url, timeout=10, headers=headers)
                if response.status_code != 200 or 'text/html' not in response.headers.get('Content-Type', ''):
                    continue
            except Exception:
                continue

            print(f"[+] Crawling: {url}")
            self.visited.add(url)
            soup = BeautifulSoup(response.text, "lxml")

            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link["href"])
                full_url = full_url.split('#')[0]
                norm_url = self.normalize_url(full_url)
                if self.is_valid(norm_url) and norm_url not in self.visited and norm_url not in self.to_visit:
                    self.to_visit.append(norm_url)

            for form in soup.find_all("form", action=True):
                form_action = urljoin(url, form.get("action"))
                method = form.get("method", "GET").upper()
                inputs = [inp.get("name") for inp in form.find_all(["input", "textarea", "select"]) if inp.get("name")]
                self.forms.append({
                    "page": url,
                    "action": form_action,
                    "method": method,
                    "inputs": inputs
                })
                print(f"    [Form found] {form_action}")
            page_count += 1

        self.show_summary()
        nmap_res = self.scan_network()
        return nmap_res

    def show_summary(self):
        print("\n[+] Crawl finished. Discovered URLs:")
        for u in sorted(self.visited):
            print(" -", u)

        if self.forms:
            print("\n[+] Forms discovered:")
            for form in self.forms:
                print(f" - Page: {form['page']}")
                print(f"   Action: {form['action']}")
                print(f"   Method: {form['method']}")
                print(f"   Inputs: {', '.join(form['inputs']) if form['inputs'] else '(none)'}")

    def get_discovered_hosts(self):
        hosts = set()
        for u in sorted(self.visited):
            try:
                host = urlparse(u).netloc.split(':')[0]
                if host:
                    hosts.add(host)
            except Exception:
                continue
        if not hosts:
            try:
                hosts.add(urlparse(self.base_url).netloc.split(':')[0])
            except Exception:
                pass
        return sorted(hosts)

    def scan_network(self, hosts=None, nmap_args='-sV -T4'):
        if hosts is None:
            hosts = self.get_discovered_hosts()
        if isinstance(hosts, str):
            hosts = [hosts]

        if not hosts:
            print("[!] No hosts found to scan.")
            return []

        hosts_str = " ".join(hosts)
        print(f"\n[+] Running Nmap: {hosts_str}")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=hosts_str, arguments=nmap_args)
        except Exception as e:
            print(f"[!] Nmap execution error: {e}")
            return []

        scan_data = []
        for host in nm.all_hosts():
            hostname = nm[host].hostname() or ""
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    service = nm[host][proto][port]
                    scan_data.append({
                        "host": host,
                        "hostname": hostname,
                        "port": int(port),
                        "protocol": proto,
                        "state": service.get("state", ""),
                        "service": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", "")
                    })
        return scan_data

    def save_combined_results(self, nmap_data=None, zap_alerts=None, subdomains=None, screenshots=None, brute_results=None, filename="result.json"):
        payload = {
            "base_url": self.base_url,
            "discovered_urls": sorted(self.visited),
            "forms_found": self.forms,
            "nmap": nmap_data or [],
            "zap_alerts": zap_alerts or [],
            "subdomains": subdomains or [],
            "screenshots": screenshots or [],
            "brute_force_successes": brute_results or []
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
        print(f"\n[+] Combined results saved to {filename}")


# ---- HTML Report Generator ----
def generate_html_report(data, zap_alerts, output_html="report.html"):
    html_content = f"""
    <html>
    <head><title>Security Report</title></head>
    <body>
        <h1>Security Scan Report</h1>
        <h2>Target: {data.get('base_url')}</h2>
        
        <h3>Discovered URLs</h3>
        <ul>
    """
    for url in data.get("discovered_urls", []):
        html_content += f"<li>{url}</li>"
    html_content += "</ul>"

    html_content += "<h3>Forms Found</h3><ul>"
    for form in data.get("forms_found", []):
        html_content += f"<li>{form['page']} -> {form['action']} ({form['method']})</li>"
    html_content += "</ul>"

    html_content += "<h3>ZAP Alerts</h3><ul>"
    for alert in zap_alerts:
        html_content += f"<li><b>{alert['alert']}</b> ({alert['risk']}) - {alert['url']}</li>"
    html_content += "</ul>"

    html_content += "<h3>Subdomains Found</h3><ul>"
    for sub in data.get("subdomains", []):
        html_content += f"<li>{sub}</li>"
    html_content += "</ul>"

    html_content += "<h3>Screenshots</h3><ul>"
    for shot in data.get("screenshots", []):
        html_content += f'<li><img src="{shot}" width="400"></li>'
    html_content += "</ul>"

    html_content += "<h3>Brute-force Successes</h3><ul>"
    for bf in data.get("brute_force_successes", []):
        html_content += f"<li>{bf['form']} => {bf['credentials']}</li>"
    html_content += "</ul></body></html>"

    with open(output_html, "w") as f:
        f.write(html_content)
    print(f"[+] HTML report saved to {output_html}")


# ---- PDF Report Generator Using Playwright ----
def generate_pdf_report(html_file, pdf_file):
    print(f"\n[+] Generating PDF report using Playwright...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"file://{os.path.abspath(html_file)}")
        page.pdf(path=pdf_file, format='A4')
        browser.close()
    print(f"[+] PDF report saved to {pdf_file}")


# ---- Modular Scan Runner ----
def run_full_scan(target_url):
    """Run full WebHawk scan pipeline."""
    import os
    from urllib.parse import urlparse

    def normalize_input_target(raw):
        raw = (raw or "").strip()
        if not raw:
            return None
        if not raw.startswith(("http://", "https://")):
            raw = "http://" + raw
        parsed = urlparse(raw)
        if not parsed.netloc:
            return None
        return raw.rstrip("/")

    target = normalize_input_target(target_url)
    if not target:
        raise ValueError("Invalid URL")

    safe_target = urlparse(target).netloc.replace(":", "_")
    json_output = f"{safe_target}.json"
    html_output = f"{safe_target}.html"
    pdf_output = f"{safe_target}.pdf"

    domain = urlparse(target).netloc.split(':')[0]

    # Run modules
    subdomains = enumerate_subdomains(domain)
    crawler = SmartCrawler(target, max_pages=10)  # Reduced for speed
    nmap_res = crawler.crawl()
    screenshots = capture_screenshots(list(crawler.visited)[:5])  # Limit screenshots
    brute_results = brute_force_login(crawler.forms[:2])  # Limit forms

    # Mock ZAP alerts
    zap_alerts = [{"alert": "Sample XSS", "risk": "High", "url": target}]

    # Save result
    crawler.save_combined_results(
        nmap_data=nmap_res,
        zap_alerts=zap_alerts,
        subdomains=subdomains,
        screenshots=screenshots,
        brute_results=brute_results,
        filename=json_output
    )

    # Generate reports
    generate_html_report({
        "base_url": target,
        "discovered_urls": sorted(crawler.visited),
        "forms_found": crawler.forms,
        "subdomains": subdomains,
        "screenshots": screenshots,
        "brute_force_successes": brute_results
    }, zap_alerts, html_output)

    generate_pdf_report(html_output, pdf_output)

    return {
        "json": f"/{json_output}",
        "html": f"/{html_output}",
        "pdf": f"/{pdf_output}"
    }
