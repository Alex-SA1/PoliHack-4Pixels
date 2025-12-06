from webpage_scanner import WebPageScanner
from urllib.parse import unquote, urlparse, parse_qs, urlencode, urlunparse
import base64
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from urllib.parse import urlparse, unquote
import re
import socket
import ssl
import requests
from datetime import datetime
import whois
import ipaddress
from flask_cors import CORS
from playwright.sync_api import sync_playwright

app = Flask(__name__)
app.secret_key = '48e32d79b7d336c4fec79ee00c46f48bac7a726fb8f8ba0f60100388b1ee8866'
CORS(app)


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
        }

    tld = parts[-1]
    if tld in safe_tlds:
        return {
            "is_suspicious": False,
        }
    else:
        return {
            "is_suspicious": True,
        }


def domain_age_days(domain):
    # calculam formate diferite ale datei

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

        # Data are timezone o convertim la UTC fara timezone
        if creation.tzinfo is not None:
            creation = creation.astimezone(tz=None).replace(tzinfo=None)

        # Calculam vechimea in zile
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

        # don't check hostname if domain is IP
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

        # extract additional fields
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        result["subject"] = dict(x[0] for x in cert.get("subject", []))

        # expiration check
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

        # hostname check
        if not is_ip:
            try:
                ssl.match_hostname(cert, domain)
            except ssl.CertificateError:
                result["reason"] = "Certificate does not match domain"
                return result

        # self-signed checking
        issuer_cn = result["issuer"].get("commonName", "")
        subject_cn = result["subject"].get("commonName", "")

        if issuer_cn == subject_cn:
            result["reason"] = "Self-signed certificate"
            result["status"] = "weak"
            return result

        # all checks are passed
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

    # mimare Browser real pentru a evita firewall blocking
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    chain_data = []

    try:
        # request on session pt a incepe redirect chain-ul
        response = session.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers=headers,
            stream=True  # init conexiune
        )

        # iterare istoric redirects
        for hop in response.history:
            chain_data.append({
                "url": hop.url,
                "status_code": hop.status_code,
                "type": "redirect"
            })

        # adaugare link final
        chain_data.append({
            "url": response.url,
            "status_code": response.status_code,
            "type": "final"
        })

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

        # setare user-agent, altfel bit.ly/tinyurl poate bloca cererea
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

    for word in dangerous_keywords:
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


def is_tracking_param(key):
    TRACKING_PARAMETERS = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term",
        "utm_content", "ref", "referrer", "gclid", "fbclid"
    }
    key = key.lower()
    return (
        key in TRACKING_PARAMETERS or
        key.startswith("utm_") or
        key.startswith("fbclid") or
        key.startswith("gclid") or
        key.startswith("msclkid") or
        key.startswith("_hs_") or
        key.startswith("pk_")
    )


def url_query_params(url):

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    clean_params = {
        key: val for key, val in query_params.items()
        if not is_tracking_param(key)
    }

    tracking_params = {
        key: val for key, val in query_params.items()
        if is_tracking_param(key)
    }

    clean_query = urlencode(clean_params, doseq=True)
    clean_url = urlunparse(parsed._replace(query=clean_query))

    return clean_url, tracking_params


def analyze_http_requests(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        requests = []

        # Track requests
        page.on("request", lambda request: requests.append(request))
        page.goto(url)

        browser.close()
        return len(requests)


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
    reasons = []
    penalties = 0

    # ip adress
    if len(url) > 200:
        penalties += 3
        reasons.append("URL prea lung (posibila ofuscare)")

    if is_ip_address(domain):
        penalties += 5
        reasons.append("URL foloseste IP direct")

    # TLD
    if tld_info["is_suspicious"]:
        penalties += 15
        reasons.append("TLD contine secventa de caractere suspecte")

    # Domain age in days
    if domain_age is None:
        penalties += 5
        reasons.append("Domeniul nu are o data de creare")
    elif domain_age < 5:
        penalties += 25
        reasons.append("Domeniul este nou")
    elif domain_age < 30:
        penalties += 15
        reasons.append("Domeniul este relativ nou")
    elif domain_age < 80:
        penalties += 10
        reasons.append("Domeniul nu este foarte vechi")

    # SSL
    if ssl_status == "invalid":
        penalties += 25
        reasons.append("Certificat SSL invalid sau expirat")
    # if ssl_status["expires_in_days"] < 1:
    #     penalties += 7
    #     reasons.append("Site neglijat")
    # elif ssl_status["expires_in_days"] < 5:
    #     penalties += 3
    #     reasons.append("Site neglijat")

    # TLD
    if tld_info["is_suspicious"]:
        penalties += 15
        reasons.append("TLD contine secventa de caractere suspecte")

    # Redirect chain
    if redirect_info["success"]:
        hop_count = len(redirect_info["chain"])
        if hop_count > 6:
            penalties += 15
            reasons.append("URL-ul contine peste 6 redirecturi")
        elif hop_count > 4:
            penalties += 10
            reasons.append("URL-ul contine peste 4 redirecturi")
        elif hop_count > 2:
            penalties += 5
            reasons.append("URL-ul contine peste 2 redirecturi")

# -------------------------

    # expand short

    # 4. Double encoding
    if decoded_analysis["double_encoded"]:
        penalties += 20
        reasons.append("URL este dublu encodat")

    penalties_for_keywords = min(30, len(decoded_analysis["suspicious"]) * 10)
    if penalties_for_keywords > 0:
        penalties += penalties_for_keywords
        reasons.append("URL-ul contine cuvinte suspecte")

    # 6. Base64 payload
    if len(decoded_analysis["base64_payloads"]) > 0:
        penalties += 20
        reasons.append("URL-ul contine secvente in Base64")

    score = 100 - penalties
    if score < 0:
        score = 0

    if score >= 90:
        trust_level = "Excellent"
    elif score >= 70:
        trust_level = "Good"
    elif score >= 40:
        trust_level = "Caution"
    elif score > 0:
        trust_level = "Dangerous"
    else:
        trust_level = "Extremely Dangerous"

    return score, trust_level, reasons


def analyze_url(url):

    # Analizeaza complet un URL si genereaza un Trust Score.

    parsed = urlparse(url)
    domain = parsed.netloc
    decoded = unquote(url)

    # Calcul Trust Score
    trust_score, trust_level, reasons = calculate_trust_score(
        url=url,
        domain=domain,
        ssl_status=get_ssl_status(domain),
        domain_age=domain_age_days(domain),
        tld_info=suspicious_tld(domain),
        decoded_analysis=analyze_decoded_url(url),
        redirect_info=get_redirect_chain(url)
    )

    clean_url, tracking_params = url_query_params(url)

    return {
        "trust_score": trust_score,
        "trust_level": trust_level,
        "reasons": reasons,
        "clean_url": clean_url,
        "tracking_parameters": tracking_params,
    } | analize_link_page(url)


def analize_link_page(url):  # Florin page scanner

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    scanner = WebPageScanner(url)
    return scanner.run()


def return_url_analysis(url):
    """
    Full URL security analysis.
    Expands short URLs, performs domain checks, SSL checks,
    URL obfuscation detection, redirect chain analysis,
    and webpage content scanning.
    """

    if not url:
        return {"error": "No URL provided"}

    # 1. Expand shortened URLs (bit.ly, tinyurl…)
    expanded = expand_short_url(url)
    final_url = expanded.get("expanded_url", url)

    # 2. URL decoding & Base64 analysis
    decoded_analysis = analyze_decoded_url(final_url)

    # 3. Parse domain
    parsed = urlparse(final_url)
    domain = parsed.netloc

    # 4. Domain age
    age_days = domain_age_days(domain)

    # 5. TLD analysis
    tld_info = suspicious_tld(domain)

    # 6. SSL status
    ssl_info = get_ssl_status(domain)

    # 7. Redirect chain
    redirect_info = get_redirect_chain(final_url)

    # 8. Trust Score (based on URL-level factors)
    trust_score, trust_level, badges = calculate_trust_score(
        url=final_url,
        domain=domain,
        ssl_status=ssl_info["status"],
        domain_age=age_days,
        tld_info=tld_info,
        decoded_analysis=decoded_analysis,
        redirect_info=redirect_info
    )

    # 9. HTML + JS scanner
    webpage_result = WebPageScanner(final_url).run()

    # 10. Merge results into ONE unified object
    return {
        "original_url": url,
        "expanded_url": final_url,
        "decoded_analysis": decoded_analysis,
        "redirect_chain": redirect_info,
        "domain_age_days": age_days,
        "ssl": ssl_info,
        "tld_info": tld_info,

        "trust_score": trust_score,
        "trust_level": trust_level,
        "badges": badges,

        "webpage_scan": webpage_result,
        "shortener_info": expanded,

        "is_valid": trust_level != "Dangerous"
    }


def return_webpage_analysis(url):
    """
    Master function that performs a FULL webpage scan:
    - HTML analysis (forms, JS obfuscation, social engineering)
    - Network/SSL/domain reputation
    - Image security analysis (steganography, polyglot images, malicious SVG)

    Returns a JSON-serializable dictionary.
    """
    if not url or not isinstance(url, str):
        return {
            "status": "error",
            "error": "Invalid or missing URL",
            "risk_score": 100,
            "verdict": "UNAVAILABLE"
        }

    try:
        scanner = WebPageScanner(url)
        result = scanner.run()

        return {
            "status": "success",
            "url": url,
            "verdict": result.get("verdict"),
            "risk_score": result.get("risk_score"),
            "scan_time": result.get("scan_time"),
            "findings": result.get("findings"),
            "technical_details": result.get("technical_details")
        }

    except Exception as e:
        return {
            "status": "error",
            "url": url,
            "error": str(e),
            "risk_score": 100,
            "verdict": "UNAVAILABLE"
        }


@app.route("/processor", methods=['GET'])
def processor():
    url = request.args.get("hoveredUrl")

    if not url:
        return jsonify({"error": "Missing 'hoveredUrl' parameter"}), 400

    url_analysis = return_url_analysis(url)               # URL-level analysis
    # Full webpage scan (HTML + JS + images)
    webpage_analysis = return_webpage_analysis(url)

    session["url_analysis"] = url_analysis
    session["webpage_analysis"] = webpage_analysis

    # Debug print in terminal
    print("\n=== URL ANALYSIS ===")
    print(url_analysis)
    print("\n=== WEBPAGE ANALYSIS ===")
    print(webpage_analysis)

    # Redirect to the UI page
    return redirect(url_for("website_details"))


@app.route("/website-details", methods=['GET'])
def website_details():
    my_data = session.get('my_data', 'No data available')
    sergiu = session.get('name')
    print("Woooooooooooooow" + my_data)

    context_data = {
        'name': 'Sergiulica',
        'age': -18
    }

    return render_template('index.html', context=context_data)


if __name__ == "__main__":
    app.run(debug=True)
