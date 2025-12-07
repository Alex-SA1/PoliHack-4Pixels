import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin
import datetime
import socket
import ssl
import base64
import difflib
from backend.image_scanner import ImageSecurityScanner


try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class WebPageScanner:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.soup = None
        self.html_content = ""

        self.report = {
            "score": 0,
            "verdict": "PENDING",
            "findings": [],
            "technical_details": {},
            "images_scanned": 0,
            "suspicious_images": 0,
            "image_reports": [],
            "image_links": []
        }

    def _add_finding(self, score, title, description, reports=[]):
        self.report["score"] += score

        if reports == []:
            self.report["findings"].append({
                "severity": "HIGH" if score >= 20 else ("MEDIUM" if score >= 10 else "LOW"),
                "title": title,
                "description": description
            })
        else:
            self.report["findings"].append({
                "severity": "HIGH" if score >= 20 else ("MEDIUM" if score >= 10 else "LOW"),
                "title": title,
                "description": description,
                "reports": reports
            })

    def _fetch_page(self):
        try:
            # using browser for site connection
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/115.0.0.0 Safari/537.36'}
            response = requests.get(
                self.url, headers=headers, timeout=8, allow_redirects=True)
            self.html_content = response.text
            self.soup = BeautifulSoup(self.html_content, 'html.parser')
            return True

        except Exception as e:
            self.report["status"] = "failed"
            self.report["error"] = str(e)
            return False

    def _analyze_content_semantics(self):
        text = self.soup.get_text().lower()

        # Inginerie sociala
        urgency_words = ['urgent', 'suspend', 'restricted', 'unauthorized',
                         'immediately', 'verify', 'lock', 'blocat', 'expira']
        hits = [w for w in urgency_words if w in text]
        if len(hits) >= 7:
            self._add_finding(20, "Social Engineering Language",
                              f"The website uses alerting terms: {', '.join(hits[:3])}...")

        # Copyright fals
        if "copyright" in text:
            current_year = datetime.datetime.now().year

            if str(current_year) not in text and str(current_year-1) not in text:
                self._add_finding(10, "Copyright not updated",
                                  "The footer doesn't contain the current year! The website may have malicious intentions!")

    def _analyze_forms_advanced(self):
        forms = self.soup.find_all('form')
        for form in forms:
            action = form.get('action', '').lower()
            method = form.get('method', 'get').lower()

   
            html_form = str(form).lower()
            sensitive_keywords = ['password', 'cvv',
                                  'card', 'social security', 'cnp', 'passport']
            is_sensitive = any(k in html_form for k in sensitive_keywords)

            if is_sensitive:
                if self.parsed_url.scheme == 'http':
                    self._add_finding(40, "Sensitive form over HTTP",
                                      "Critical data transfer over insecure connection.")

                if action == "" or action == "#":
                    self._add_finding(
                        20, "Form with empty action", "Data can be intercepted with JS onSubmit.")
                elif action.startswith("http"):
                    action_domain = urlparse(action).netloc
                    if action_domain != self.domain:
                        self._add_finding(30, "Data Exfiltration Cross-Domain",
                                          f"The form is sending data to another domain: {action_domain}")

    def _analyze_obfuscation(self):
        scripts = self.soup.find_all('script')
        for script in scripts:
            content = script.string or script.get('src', '')
            if not content:
                continue

            b64_matches = re.findall(r'[A-Za-z0-9+/=]{50,}', content)
            for match in b64_matches:
                try:
                    decoded = base64.b64decode(match).decode(
                        'utf-8', errors='ignore')
                    if "<script" in decoded or "eval(" in decoded or "http" in decoded:
                        self._add_finding(
                            45, "Malicious Base64 Payload", "Hidden executable inside of a base64 encoded string.")
                        break
                except:
                    pass

            if len(re.findall(r'\\x[0-9A-Fa-f]{2}', content)) > 20:
                self._add_finding(
                    25, "Obfuscated JS (Hex)", "The script uses hexadecimal encoding to hide code.")

    def _check_trap_links(self):
        links = self.soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            text = link.get_text().strip()

            if "login" in text.lower() or "signin" in text.lower():
                if self.domain not in href and href.startswith("http"):
                    self._add_finding(
                        15, "External Login Link", f"The button '{text}' references an external website.")

    def _scan_images(self):
        images = self.soup.find_all("img")

        if not images:
            return

        scanned_results = []
        suspicious_images = 0

        for img in images:
            src = img.get("src")
            if not src:
                continue

            img_url = urljoin(self.url, src)

            scanner = ImageSecurityScanner(img_url)
            result = scanner.run()
            scanned_results.append(result)

            if result["is_malicious"]:
                suspicious_images += 1
                self._add_finding(
                    25,
                    "Suspicious image detected",
                    f"The image {img_url} seems malicious",
                    result
                )
                self.report["image_links"].append(img_url)

        self.report["images_scanned"] = len(scanned_results)
        self.report["suspicious_images"] = suspicious_images
        self.report["image_reports"] = scanned_results

        if suspicious_images > 0:
            self._add_finding(
                15,
                "The website contains possible dangerous images",
                f"{suspicious_images} images have signs of steganography or embedded code."
            )

    def run(self):
        if not self._fetch_page():
            return self.report

        self._analyze_content_semantics()
        self._analyze_forms_advanced()
        self._analyze_obfuscation()
        self._check_trap_links()

        self._scan_images()

        score = self.report["score"]
        score = 100 - score

        if score >= 65:
            self.report["verdict"] = "Safe"
        elif score >= 35:
            self.report["verdict"] = "Suspicious"
        else:
            self.report["verdict"] = "Malicious"

        self.report["score"] = max(0, score)
        self.report["status"] = "success"

        return self.report
