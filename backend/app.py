from webpage_scanner import WebPageScanner
from urllib.parse import unquote, urlparse
import base64
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse, unquote
import re
import socket
import ssl
import requests
from datetime import datetime
import whois
import ipaddress

app = Flask(__name__)


def is_ip_address(domain):  # Vosi
    # Functie extinsa pentru detectarea adreselor IP valide.

    # Eliminam portul
    if ":" in domain and domain.count(":") == 1:
        possible_ip, possible_port = domain.split(":")
        if possible_port.isdigit():
            try:
                ipaddress.ip_address(possible_ip)
                return True
            except:
                # arunca exceptie dac a nu e valid
                return False


def suspicious_tld(domain):  # Vosi
    # Verifica daca TLD-ul unui domeniu este de incredere folosind o lista alba (whitelist).

    safe_tlds = {
        "com", "org", "net", "edu", "gov", "mil", "int",
        "co", "us", "uk", "de", "fr", "ca", "au", "nl",
        "es", "it", "ch", "se", "no", "fi", "dk",
        "ro", "eu", "io", "ai", "me", "dev", "app"
    }

    parts = domain.lower().split(".")

    # Domeniu invalid
    if len(parts) < 2:
        return {
            "is_suspicious": True,
            "tld": None,
            "reason": "Domeniu invalid"
        }

    tld = parts[-1]
    if tld in safe_tlds:
        return {
            "is_suspicious": False,
            "reason": "TLD se afla in lista alba"
        }
    else:
        return {
            "is_suspicious": True,
            "reason": "TLD neobisnuit sau necunoscut"
        }


def domain_age_days(domain):
    """
    - formate diferite WHOIS
    - liste de date
    - string-uri, datetime-uri, None
    - timezone-uri
    - erori WHOIS sau TLD-uri problematice
    """

    try:
        w = whois.whois(domain)
        creation = w.creation_date

        if not creation:
            return None

        if isinstance(creation, list):
            creation = [c for c in creation if c is not None]
            if len(creation) == 0:
                return None
            creation = min(creation)

        if isinstance(creation, str):
            try:
                creation = datetime.fromisoformat(
                    creation.replace("Z", "+00:00"))
            except:
                fmts = [
                    "%Y-%m-%d",
                    "%Y-%m-%d %H:%M:%S",
                    "%d-%b-%Y",
                    "%Y.%m.%d"
                ]
                for fmt in fmts:
                    try:
                        creation = datetime.strptime(creation, fmt)
                        break
                    except:
                        pass

        if not isinstance(creation, datetime):
            return None

        # Caz D: Data are timezone o convertim la UTC fara timezone
        if creation.tzinfo is not None:
            creation = creation.astimezone(tz=None).replace(tzinfo=None)

        # 3  Calculam vechimea in zile
        return (datetime.utcnow() - creation).days

    except Exception as e:
        return None


def get_ssl_status(domain):
    """
    Extended SSL validation:
    - Detects invalid certificates
    - Detects expired certificates
    - Detects self-signed certificates
    - Detects hostname mismatch
    - Works with IP addresses (skips hostname check)
    - Returns detailed structured result
    """

    result = {
        "status": "invalid",
        "issuer": None,
        "subject": None,
        "expires_in_days": None,
        "reason": None
    }

    try:
        ctx = ssl.create_default_context()

        # Do NOT check hostname if domain is IP
        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
            ctx.check_hostname = False
        except:
            pass

        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=None if is_ip else domain) as s:
            s.settimeout(4)
            s.connect((domain, 443))
            cert = s.getpeercert()

        if not cert:
            result["reason"] = "Could not retrieve SSL certificate"
            return result

        # Extract helpful fields
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        result["subject"] = dict(x[0] for x in cert.get("subject", []))

        # --- CHECK EXPIRATION ---
        from datetime import datetime
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days
        result["expires_in_days"] = days_left

        if days_left < 0:
            result["reason"] = "Certificate expired"
            return result
        if days_left < 10:
            result["reason"] = "Certificate expiring soon"
            result["status"] = "weak"
            return result

        # --- CHECK HOSTNAME MATCH (unless it's IP) ---
        if not is_ip:
            try:
                ssl.match_hostname(cert, domain)
            except ssl.CertificateError:
                result["reason"] = "Certificate does not match domain"
                return result

        # --- CHECK SELF-SIGNED ---
        issuer_cn = result["issuer"].get("commonName", "")
        subject_cn = result["subject"].get("commonName", "")

        if issuer_cn == subject_cn:
            result["reason"] = "Self-signed certificate"
            result["status"] = "weak"
            return result

        # Passed all checks
        result["status"] = "valid"
        return result

    except ssl.SSLError as e:
        result["reason"] = f"SSL error: {str(e)}"
        return result

    except socket.timeout:
        result["reason"] = "Connection timeout"
        return result

    except Exception as e:
        result["reason"] = f"Connection error: {str(e)}"
        return result


def get_redirect_chain(url):  # Florin

    session = requests.Session()

    # Se mimeaza un Browser real pentru sa nu fi blocati de Firewall
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    chain_data = []

    try:

        # Primim Request-ul
        response = session.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers=headers,
            stream=True  # Se initializeaza conexiunea si citeste headers

        )

        # 1. Iteram prin istoric (redirect-urile intermediare)
        for hop in response.history:
            chain_data.append({
                "url": hop.url,
                "status_code": hop.status_code,
                "type": "redirect"
            })

        # 2. Adaugam destinatia finala
        chain_data.append({
            "url": response.url,
            "status_code": response.status_code,
            "type": "final"
        })

        # Inchidem conexiunea explicit pentru ca am folosit stream=True
        response.close()

        return {"success": True, "chain": chain_data}

    except requests.exceptions.Timeout:
        return {"success": False, "error": "Timeout", "chain": chain_data}

    except requests.exceptions.TooManyRedirects:
        return {"success": False, "error": "Redirect Loop Detected", "chain": chain_data}

    except requests.exceptions.SSLError:
        return {"success": False, "error": "SSL Certificate Error", "chain": chain_data}

    # Orice alta eroare de retea
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e), "chain": chain_data}

    finally:
        session.close()


def expand_short_url(url):

    try:
        session = requests.Session()
        # Este CRITIC să avem User-Agent, altfel bit.ly/tinyurl pot bloca cererea
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # allow_redirects=True face toată magia: urmărește automat lanțul până la capăt
        # timeout=10 este important pentru lanțuri lungi
        response = session.head(url, allow_redirects=True, timeout=10)

        final_url = response.url

        # Verificăm dacă URL-ul final e diferit de cel inițial
        if final_url != url:
            return {
                "is_shortened": True,
                "original_url": url,
                "expanded_url": final_url,
                "message": "Link expandat cu succes (Redirect detectat)."
            }
        else:
            return {
                "is_shortened": False,
                "original_url": url,
                "expanded_url": url,
                "message": "Link-ul nu a făcut redirect (este direct destinația)."
            }

    except requests.exceptions.Timeout:
        return {"is_shortened": False, "error": "Timeout", "expanded_url": url}
    except Exception as e:
        return {"is_shortened": False, "error": str(e), "expanded_url": url}


def decode_url_fully(url):
    # Functie care decodeaza complet un URL:

    decoded_once = unquote(url)
    decoded_twice = unquote(decoded_once)

    double_encoded = decoded_once != decoded_twice

    return decoded_twice, double_encoded


def extract_base64_from_url(url):
    """
    Extrage potentiale string-uri Base64 din URL,
    de obicei in parametrii (?token=, ?data=, ?redirect=)
    """

    base64_candidates = []

    parsed = urlparse(url)
    query = parsed.query

    if not query:
        return base64_candidates

    for param in query.split("&"):
        if "=" not in param:
            continue
        key, value = param.split("=", 1)

        # verificam daca lungimea e suficienta pt Base64
        if len(value) > 12:
            try:
                decoded = base64.b64decode(value + "===", validate=True)
                decoded_text = decoded.decode("utf-8", errors="ignore")
                base64_candidates.append({
                    "parameter": key,
                    "encoded": value,
                    "decoded": decoded_text
                })
            except Exception:
                pass

    return base64_candidates


def analyze_decoded_url(url):
    """
    Combina tot:
    - decodeaza URL complet
    - verifica dublu encoding
    - verifica secvente periculoase
    - verifica Base64
    """

    decoded_url, double_encoded = decode_url_fully(url)
    base64_hits = extract_base64_from_url(url)

    suspicious = []

    if double_encoded:
        suspicious.append("URL contine dublu encoding (obfuscare posibila)")

    dangerous_keywords = ["login", "verify", "reset",
                          "update", "secure", "wallet", "bank"]

    for word in dangerous_keywords and word not in url:
        if word in decoded_url.lower():
            suspicious.append(f"URL conține cuvant suspect: '{word}'")

    if "<script" in decoded_url.lower():
        suspicious.append("URL contine cod <script> ascuns (posibil XSS)")

    if "javascript:" in decoded_url.lower():
        suspicious.append(
            "URL foloseste schema javascript: (extrem de periculos)")

    if "@@" in decoded_url:
        suspicious.append("URL contine @@ (pattern folosit in atacuri)")

    if len(base64_hits) > 0:
        suspicious.append("URL contine payload Base64 in parametri")

    return {
        "original_url": url,
        "decoded_url": decoded_url,
        "double_encoded": double_encoded,
        "base64_payloads": base64_hits,
        "suspicious": suspicious,
        "is_safe": len(suspicious) == 0
    }


# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------


def is_critical(decoded_analysis, domain, ssl_status, domain_age, redirect_info):
    """
    Detecteaza indicatori critici de phishing/malware.
    Daca este True → site periculos indiferent de scor.
    """

    critical_keywords = ["bank", "transfer", "wallet",
                         "payment", "invoice", "secure-login"]

    decoded_url = decoded_analysis["decoded_url"].lower()

    # 1. Cuvinte critice in URL
    for word in critical_keywords:
        if word in decoded_url:
            return True

    # 2. JavaScript sau <script> in URL
    if "javascript:" in decoded_url:
        return True
    if "<script" in decoded_url:
        return True

    # 3. Double encoding + cuvinte critice
    if decoded_analysis["double_encoded"]:
        for word in critical_keywords:
            if word in decoded_url:
                return True

    # 4. Base64 contine cuvinte critice
    for payload in decoded_analysis["base64_payloads"]:
        decoded_text = payload["decoded"].lower()
        for word in critical_keywords:
            if word in decoded_text:
                return True

    # 5. Domeniu extrem de nou
    if domain_age is not None and domain_age < 5:
        return True

    # 6. IP address + cuvant critic
    if is_ip_address(domain):
        for word in critical_keywords:
            if word in decoded_url:
                return True

    # 7. Redirect final catre URL periculos
    if redirect_info["success"]:
        final_url = redirect_info["chain"][-1]["url"].lower()
        for word in critical_keywords:
            if word in final_url:
                return True

    return False


def calculate_trust_score(url, domain, ssl_status, domain_age, tld_info, decoded_analysis, redirect_info):

    if is_critical(decoded_analysis, domain, ssl_status, domain_age, redirect_info):
        return 0, "Dangerous", ["Critical Threat Detected"]

    score = 100
    badges = []
    penalties = 0

    # 1. SSL
    if ssl_status == "invalid":
        penalties += 25   # reduced from 35
    else:
        badges.append("SSL Valid")

    # 2. TLD
    if tld_info["is_suspicious"]:
        penalties += 15   # reduced from 20
    else:
        badges.append("TLD Sigur")

    # 3. Domain age
    if domain_age is None:
        penalties += 5
    elif domain_age < 5:
        penalties += 25
    elif domain_age < 30:
        penalties += 15
    elif domain_age < 180:
        penalties += 10
    else:
        badges.append("Domeniu Vechi")

    # 4. Double encoding
    if decoded_analysis["double_encoded"]:
        penalties += 20

    # 5. Suspicious keywords
    penalties += min(30, len(decoded_analysis["suspicious"]) * 10)
    # safety cap (max 30)

    # 6. Base64 payload
    if len(decoded_analysis["base64_payloads"]) > 0:
        penalties += 20

    # 7. IP address usage
    if is_ip_address(domain):
        penalties += 15

    # 8. Redirect chain
    if redirect_info["success"]:
        hop_count = len(redirect_info["chain"])
        if hop_count > 6:
            penalties += 15
        elif hop_count > 4:
            penalties += 10
        elif hop_count > 2:
            penalties += 5

    # 9. Final score
    score = max(0, min(100, 100 - penalties))

    # 10. Trust level
    if score >= 90:
        trust_level = "Excellent"
    elif score >= 70:
        trust_level = "Good"
    elif score >= 40:
        trust_level = "Caution"
    else:
        trust_level = "Dangerous"

    return score, trust_level, badges


def analyze_url(url):

    # Analizeaza complet un URL si genereaza un Trust Score.

    parsed = urlparse(url)
    domain = parsed.netloc
    decoded = unquote(url)

    basic_suspicious = []

    if len(url) > 120:
        basic_suspicious.append("URL prea lung (posibila ofuscare)")

    if is_ip_address(domain):
        basic_suspicious.append("URL foloseste IP direct")

    # TLD
    tld_info = suspicious_tld(domain)
    if tld_info["is_suspicious"]:
        basic_suspicious.append(f"TLD suspect ({tld_info['reason']})")

 # ------------------------------------------------
    if "%" in url:
        basic_suspicious.append("URL contine caractere codate")

    if "@" in url:
        basic_suspicious.append("URL contine @ (tehnica de phishing)")
 # ------------------------------------------------

    # add
    ssl_status = get_ssl_status(domain)
    if ssl_status == "invalid":
        basic_suspicious.append("Certificat SSL invalid sau lipsa")

    age_days = domain_age_days(domain)
    if age_days is not None and age_days < 30:
        basic_suspicious.append(f"Domeniu foarte nou ({age_days} zile)")

    # ----------------------------------------------------
    # 4. Redirect chain
    # ----------------------------------------------------
    redirects = get_redirect_chain(url)

    # ----------------------------------------------------
    # 5. Decodare URL avansata
    # ----------------------------------------------------
    decoded_analysis = analyze_decoded_url(url)

    # ----------------------------------------------------
    # 6. Calcul Trust Score (include critical override)
    # ----------------------------------------------------
    trust_score, trust_level, badges = calculate_trust_score(
        url=url,
        domain=domain,
        ssl_status=ssl_status,
        domain_age=age_days,
        tld_info=tld_info,
        decoded_analysis=decoded_analysis,
        redirect_info=redirects
    )

    return {
        "url": url,
        "decoded_url": decoded,
        "domain": domain,

        # Rezultate analiza
        "ssl_status": ssl_status,
        "domain_age_days": age_days,
        "tld_info": tld_info,
        "redirect_chain": redirects,
        "decoded_analysis": decoded_analysis,


        "trust_score": trust_score,
        "trust_level": trust_level,
        "badges": badges,


        "basic_suspicious": basic_suspicious,


        "is_valid": trust_level != "Dangerous"  # True daca NU este Dangerous
    }


def analize_link_page(url):

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    scanner = WebPageScanner(url)
    return scanner.run()


@app.route("/process-url", methods=['POST'])
def process_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400

    # Run full analysis
    result = analyze_url(url)
    print(result)

    return jsonify(result)


@app.route("/website-details", methods=['GET'])
def website_details():
    
    
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
