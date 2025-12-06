import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin
import datetime
import socket
import ssl
import base64
import difflib
from image_scanner import ImageSecurityScanner

# Încercăm importul modulelor opționale
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
        
        # Lista brandurilor des țintite pentru Typosquatting
        self.high_value_targets = [
            'google', 'facebook', 'paypal', 'apple', 'microsoft', 
            'netflix', 'amazon', 'bancatransilvania', 'ing', 'revolut', 'brd'
        ]
        
        self.report = {
            "target": url,
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_score": 0,
            "verdict": "PENDING",
            "findings": [],
            "technical_details": {}
        }

    def _add_finding(self, score, title, description):
        """Adaugă o problemă în raport și crește scorul"""
        self.report["risk_score"] += score
        self.report["findings"].append({
            "type": "RISK" if score > 0 else "INFO",
            "severity": "HIGH" if score >= 20 else ("MEDIUM" if score >= 10 else "LOW"), 
            "title": title,
            "description": description
        })

    def _fetch_page(self):
        try:
            # Folosim un User-Agent credibil de Chrome
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/115.0.0.0 Safari/537.36'}
            response = requests.get(self.url, headers=headers, timeout=8, allow_redirects=True)
            self.html_content = response.text
            self.soup = BeautifulSoup(self.html_content, 'html.parser')
            
            # Verificăm dacă am fost redirecționați (chaining redirects)
            if len(response.history) > 1:
                self._add_finding(10, "Redirect Chain Detectat", f"URL-ul a trecut prin {len(response.history)} redirect-uri până la destinație.")
            
            return True
        except Exception as e:
            self.report["status"] = "failed"
            self.report["error"] = str(e)
            return False

    # ---------------------------------------------------------
    # LAYER 1: NETWORK & INFRASTRUCTURE
    # ---------------------------------------------------------
    
    def _check_ssl_cert(self):
        """Verifică validitatea certificatului SSL"""
        if self.parsed_url.scheme != 'https':
            return # HTTP e deja penalizat în alte funcții

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(3.0)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                
                # Verificăm data expirării
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.datetime.utcnow()).days
                
                if days_left < 5:
                    self._add_finding(15, "Certificat SSL Expiră Curând", f"Certificatul expiră în {days_left} zile. Site-urile de phishing folosesc adesea cert-uri scurte (Let's Encrypt) care sunt pe cale să expire.")
                
                # Verificăm emitentul (Ex: R3 / Let's Encrypt e ok, dar des folosit la phishing)
                issuer = dict(x[0] for x in cert['issuer'])
                self.report["technical_details"]["ssl_issuer"] = issuer.get('organizationName', 'Unknown')

        except Exception as e:
            self._add_finding(10, "Eroare SSL Handshake", f"Nu s-a putut verifica certificatul: {str(e)}")

    def _check_domain_reputation(self):
        """WHOIS + Typosquatting + Homographs"""
        # A. WHOIS (Vechime)
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(self.domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list): creation_date = creation_date[0]
                
                if creation_date:
                    age = (datetime.datetime.now() - creation_date).days
                    self.report["technical_details"]["domain_age_days"] = age
                    if age < 14:
                        self._add_finding(50, "Domeniu CRITIC de nou", f"Domeniul are doar {age} zile vechime! (Phishing probabil)")
                    elif age < 60:
                        self._add_finding(25, "Domeniu foarte nou", f"Domeniul are sub 2 luni vechime ({age} zile).")
            except:
                pass # Whois fails often, ignore silently

        # B. Typosquatting (ex: g0ogle.com)
        domain_clean = self.domain.replace("www.", "").split('.')[0]
        for brand in self.high_value_targets:
            ratio = difflib.SequenceMatcher(None, domain_clean, brand).ratio()
            # Dacă seamănă 80%-99% (dar nu e identic), e suspect
            if 0.80 <= ratio < 1.0:
                self._add_finding(40, "Posibil Typosquatting", f"Domeniul '{domain_clean}' seamănă suspect de mult cu brandul '{brand}' ({int(ratio*100)}% match).")

        # C. IDN Homograph Attack (Caractere chirilice amestecate cu latine)
        try:
            # Încercăm să codăm domeniul în IDNA. Dacă diferă lungimea sau apar caractere ciudate la decodare
            if self.domain.encode('idna') != self.domain.encode('ascii'):
                self._add_finding(35, "IDN Homograph Detected", "Domeniul folosește caractere internaționale (Punycode) pentru a imita un alt site.")
        except:
            pass

    # ---------------------------------------------------------
    # LAYER 2: CONTENT & SOCIAL ENGINEERING
    # ---------------------------------------------------------

    def _analyze_content_semantics(self):
        text = self.soup.get_text().lower()
        
        # Cuvinte de panică
        urgency_words = ['urgent', 'suspend', 'restricted', 'unauthorized', 'immediately', 'verify', 'lock', 'blocat', 'expira']
        hits = [w for w in urgency_words if w in text]
        if len(hits) >= 2:
            self._add_finding(20, "Limbaj de Inginerie Socială", f"Site-ul folosește termeni de urgență: {', '.join(hits[:3])}...")

        # Copyright fals
        if "copyright" in text:
            current_year = datetime.datetime.now().year
            # Dacă site-ul are copyright vechi sau viitor (neconfigurat)
            if str(current_year) not in text and str(current_year-1) not in text:
                 self._add_finding(10, "Copyright neactualizat", "Footer-ul nu conține anul curent, posibil șablon copiat.")

    # ---------------------------------------------------------
    # LAYER 3: CODE ANALYSIS (JS & HTML)
    # ---------------------------------------------------------

    def _analyze_forms_advanced(self):
        forms = self.soup.find_all('form')
        for form in forms:
            action = form.get('action', '').lower()
            method = form.get('method', 'get').lower()
            
            # Verificăm input-uri
            html_form = str(form).lower()
            sensitive_keywords = ['password', 'cvv', 'card', 'social security', 'cnp', 'passport']
            is_sensitive = any(k in html_form for k in sensitive_keywords)

            if is_sensitive:
                if self.parsed_url.scheme == 'http':
                    self._add_finding(40, "Formular Sensibil pe HTTP", "Se cer date critice pe o conexiune necriptată.")
                
                # Check action URL
                if action == "" or action == "#":
                     self._add_finding(20, "Formular cu acțiune goală", "Datele pot fi interceptate prin JS onSubmit.")
                elif action.startswith("http"):
                    action_domain = urlparse(action).netloc
                    if action_domain != self.domain:
                        self._add_finding(30, "Exfiltrare Date Cross-Domain", f"Formularul trimite date către un alt domeniu: {action_domain}")

    def _analyze_obfuscation(self):
        scripts = self.soup.find_all('script')
        for script in scripts:
            content = script.string or script.get('src', '')
            if not content: continue

            # 1. Base64 Decoding Check
            # Căutăm string-uri lungi care par a fi Base64
            b64_matches = re.findall(r'[A-Za-z0-9+/=]{50,}', content)
            for match in b64_matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if "<script" in decoded or "eval(" in decoded or "http" in decoded:
                        self._add_finding(45, "Payload Base64 Malițios", "Am decodat un string Base64 și am găsit cod executabil ascuns.")
                        break
                except:
                    pass

            # 2. Hex Encoding
            if len(re.findall(r'\\x[0-9A-Fa-f]{2}', content)) > 20:
                self._add_finding(25, "JS Obfuscat (Hex)", "Scriptul folosește codare hexazecimală excesivă pentru a ascunde cod.")

    def _check_trap_links(self):
        """Verifică link-uri unde textul contrazice destinația"""
        links = self.soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            text = link.get_text().strip()
            
            # Anti-phishing logic
            if "login" in text.lower() or "signin" in text.lower():
                if self.domain not in href and href.startswith("http"):
                     self._add_finding(15, "Link de Login Extern", f"Butonul '{text}' duce către un site extern.")

        # ---------------------------------------------------------
    # LAYER 4: IMAGE SECURITY SCAN
    # ---------------------------------------------------------
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

            # Make absolute URL
            img_url = urljoin(self.url, src)

            scanner = ImageSecurityScanner(img_url)
            result = scanner.run()
            scanned_results.append(result)

            # If image itself is malicious → add to main report
            if result["is_malicious"]:
                suspicious_images += 1
                self._add_finding(
                    25,
                    "Imagine suspectă detectată",
                    f"Imaginea {img_url} pare malițioasă: {result['findings']}"
                )

        # Add technical details
        self.report["technical_details"]["images_scanned"] = len(scanned_results)
        self.report["technical_details"]["suspicious_images"] = suspicious_images
        self.report["technical_details"]["image_reports"] = scanned_results

        # If ANY malicious image → page becomes suspicious
        if suspicious_images > 0:
            self._add_finding(
                15,
                "Site-ul conține imagini potențial periculoase",
                f"{suspicious_images} imagini au semne de steganografie sau cod embedat."
            )


    def run(self):
        # 1. Fetch
        if not self._fetch_page():
            return self.report

        # 2. Analyze
        self._check_ssl_cert()
        self._check_domain_reputation()
        self._analyze_content_semantics()
        self._analyze_forms_advanced()
        self._analyze_obfuscation()
        self._check_trap_links()
        self._scan_images()

        # 3. Final Verdict Calculation
        score = self.report["risk_score"]
        if score >= 65:
            self.report["verdict"] = "MALICIOUS"
        elif score >= 35:
            self.report["verdict"] = "SUSPICIOUS"
        else:
            self.report["verdict"] = "SAFE"

        # Capăm scorul la 100
        self.report["risk_score"] = min(score, 100)
        self.report["status"] = "success"
        
        return self.report