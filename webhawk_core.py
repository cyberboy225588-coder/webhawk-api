# webhawk_core.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import time
import os
import nmap
import dns.resolver
from playwright.sync_api import sync_playwright
import sys

# [COPY ALL YOUR FUNCTIONS HERE: enumerate_subdomains, capture_screenshots, brute_force_login, ZAPScanner, SmartCrawler, generate_html_report, generate_pdf_report]

# Wrap main logic in a function
def run_webhawk_scan(target_url):
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

    ZAP_API_KEY = os.environ.get("MY_ZAP_KEY", "rmp7gikep1dmo5gr6anc2q7sn5")

    safe_target = urlparse(target).netloc.replace(":", "_")
    json_output = f"{safe_target}.json"
    html_output = f"{safe_target}.html"
    pdf_output = f"{safe_target}.pdf"

    domain = urlparse(target).netloc.split(':')[0]

    subdomains = enumerate_subdomains(domain)
    crawler = SmartCrawler(target, max_pages=20)
    nmap_res = crawler.crawl()
    screenshots = capture_screenshots(sorted(crawler.visited))
    brute_results = brute_force_login(crawler.forms)

    zap_alerts = []
    try:
        zap_url = "http://127.0.0.1:8080"
        params = {"apikey": ZAP_API_KEY} if ZAP_API_KEY else {}
        resp = requests.get(f"{zap_url}/JSON/core/view/version/", params=params, timeout=4)
        if resp.status_code == 200:
            zap = ZAPScanner(zap_api_url=zap_url, apikey=ZAP_API_KEY)
            for u in sorted(crawler.visited):
                zap.access_url(u)
            scan_id = zap.start_active_scan(crawler.base_url)
            if scan_id:
                zap.wait_for_scan(scan_id)
            zap_alerts = zap.get_alerts(baseurl=crawler.base_url)
    except Exception as e:
        print(f"[!] ZAP error: {e}")

    crawler.save_combined_results(
        nmap_data=nmap_res,
        zap_alerts=zap_alerts,
        subdomains=subdomains,
        screenshots=screenshots,
        brute_results=brute_results,
        filename=json_output
    )

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
        "json": os.path.abspath(json_output),
        "html": os.path.abspath(html_output),
        "pdf": os.path.abspath(pdf_output)
    }
