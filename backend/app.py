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


def is_ip_address(domain):
    # Functie extinsa pentru detectarea adreselor IP valide.

    if ":" in domain and domain.count(":") == 1:
        possible_ip, possible_port = domain.split(":")
        if possible_port.isdigit():
            try:
                ipaddress.ip_address(possible_ip)
                return True
            except:
                return False


def suspicious_tld(domain):
    # Verificam daca TLD-ul unui domeniu.

    safe_tlds = {
        "com", "org", "net", "edu", "gov", "mil", "int",
        "co", "us", "uk", "de", "fr", "ca", "au", "nl",
        "es", "it", "ch", "se", "no", "fi", "dk",
        "ro", "eu", "io", "ai", "me", "dev", "app"
    }

    parts = domain.lower().split(".")

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
    # validare certificat SSL

    try:
        from ssl import CertificateError
        try:
            from ssl import match_hostname
        except ImportError:
            from backports.ssl_match_hostname import match_hostname
    except ImportError:
        raise ImportError("You need to install backports.ssl_match_hostname")

    result = {
        "status": "invalid",
        "issuer": None,
        "subject": None,
        "expires_in_days": 0,
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

            # problem with port
            socket.getaddrinfo(domain, 80, proto=socket.AF_INET)
            s.settimeout(4)
            s.connect((domain, 443))
            cert = s.getpeercert()

        if not cert:
            result["reason"] = "Could not retrieve SSL certificate"
            return result

        # extract additional fields
        result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        result["subject"] = dict(x[0] for x in cert.get("subject", []))

        if not is_ip:
            try:
                match_hostname(cert, domain)
            except ssl.CertificateError:
                result["reason"] = "Certificate does not match domain"
                return result

        # self-sign
        issuer_cn = result["issuer"].get("commonName", "")
        subject_cn = result["subject"].get("commonName", "")
        if issuer_cn == subject_cn:
            result["reason"] = "Self-signed certificate"
            result["status"] = "weak"
            return result

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


def get_redirect_chain(url):
    session = requests.Session()
    chain_data = []

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = session.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers=headers,
            stream=True
        )

        for hop in response.history:
            chain_data.append({
                "url": hop.url,
                "status_code": hop.status_code,
                "type": "redirect"
            })

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

    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e), "chain": chain_data}

    finally:
        session.close()


def expand_short_url(url):

    try:
        session = requests.Session()

        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        response = session.head(url, allow_redirects=True, timeout=10)
        final_url = response.url

        if final_url != url:
            return {
                "is_shortened": True,
                "original_url": url,
                "expanded_url": final_url,
                "message": "Link successfully expanded (Redirect detected)."
            }
        else:
            return {
                "is_shortened": False,
                "original_url": url,
                "expanded_url": url,
                "message": "No redirect link."
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
    # Extrage potentiale string-uri Base64 din URL, de obicei in parametrii (?token=, ?data=, ?redirect=)

    base64_candidates = []

    parsed = urlparse(url)
    query = parsed.query

    if not query:
        return base64_candidates

    for param in query.split("&"):
        if "=" not in param:
            continue
        key, value = param.split("=", 1)

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
    # base64 + decode_url

    decoded_url, double_encoded = decode_url_fully(url)
    base64_hits = extract_base64_from_url(url)

    suspicious = []

    if double_encoded:
        suspicious.append("URL contains double encoding")

    dangerous_keywords = ["login", "verify", "reset",
                          "update", "secure", "wallet", "bank"]

    for word in dangerous_keywords:
        if word in decoded_url.lower() and word not in url.lower():
            suspicious.append(f"Encoded URL contains sus word: '{word}'")

    if "<script" in decoded_url.lower():
        suspicious.append("URL contains hidden <script> code")

    if "javascript:" in decoded_url.lower():
        suspicious.append("URL uses javascript")

    if "@@" in decoded_url:
        suspicious.append("URL contains @@ (used in attacks)")

    if len(base64_hits) > 0:
        suspicious.append("URL contains Base64 payload in parameters")

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


def calculate_trust_score(url, domain, ssl_status, domain_age, tld_info, decoded_analysis, redirect_info, http_request):
    reasons = []
    penalties = 0

    # IP address
    if len(url) > 200:
        penalties += 3
        reasons.append("URL length is unusually long (possible obfuscation)")

    if is_ip_address(domain):
        penalties += 5
        reasons.append("URL is using a raw IP address instead of a domain")

    # TLD
    if tld_info["is_suspicious"]:
        penalties += 15
        reasons.append("TLD contains suspicious strings")

    # Domain age in days
    if domain_age is None:
        penalties += 5
        reasons.append("Domain creation date could not be determined")
    elif domain_age < 5:
        penalties += 25
        reasons.append("Domain is newly registered")
    elif domain_age < 30:
        penalties += 15
        reasons.append("Domain is relatively new")
    elif domain_age < 80:
        penalties += 10
        reasons.append("Domain is not very old")

    # SSL
    if ssl_status["reason"]:
        penalties += 15
        reasons.append("SSL error detected")
    else:
        if ssl_status["status"] == "invalid":
            penalties += 25
            reasons.append("SSL certificate is invalid or expired")

    # TLD (duplicate check kept for logic consistency)
    if tld_info["is_suspicious"]:
        penalties += 15
        reasons.append("TLD contains suspicious strings")

    # Redirect chain
    if redirect_info["success"]:
        hop_count = len(redirect_info["chain"])
        if hop_count > 6:
            penalties += 15
            reasons.append("URL has more than 6 redirect hops")
        elif hop_count > 4:
            penalties += 10
            reasons.append("URL has more than 4 redirect hops")
        elif hop_count > 2:
            penalties += 5
            reasons.append("URL has more than 2 redirect hops")

    # Decoded URL analysis
    if decoded_analysis["double_encoded"]:
        penalties += 10
        reasons.append("URL appears to be double-encoded")

    penalties_for_keywords = min(30, len(decoded_analysis["suspicious"]) * 10)
    if penalties_for_keywords > 0:
        penalties += penalties_for_keywords
        reasons.append("URL contains suspicious keywords")

    if len(decoded_analysis["base64_payloads"]) > 0:
        penalties += 20
        reasons.append("URL contains Base64 encoded segments")

    # HTTP request volume
    if http_request > 120:
        penalties += 35
        reasons.append(
            "URL triggers an unusually high number of HTTP requests")
    elif http_request > 60:
        penalties += 15
        reasons.append("URL triggers a large number of HTTP requests")

    score = 100 - penalties
    if score < 0:
        score = 0

    # Score to label
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

    parsed = urlparse(url)
    domain = parsed.netloc

    trust_score, trust_level, reasons = calculate_trust_score(
        url=url,
        domain=domain,
        ssl_status=get_ssl_status(domain),
        domain_age=domain_age_days(domain),
        tld_info=suspicious_tld(domain),
        decoded_analysis=analyze_decoded_url(url),
        redirect_info=get_redirect_chain(url),
        http_request=analyze_http_requests(url)
    )

    clean_url, tracking_params = url_query_params(url)
    expanded = expand_short_url(url)

    result = {
        "trust_score": trust_score,
        "trust_level": trust_level,
    }

    if clean_url:
        result["clean_url"] = clean_url

    if tracking_params:
        result["tracking_parameters"] = tracking_params

    if reasons:
        result["reasons"] = reasons

    if expanded.get("is_shortened"):
        result["expanded_url"] = expanded["expanded_url"]

    return result


def analyze_webpage_content(url):
    if not url or not isinstance(url, str):
        return {
            "status": "error",
            "safe_score": 100,
            "verdict": "UNAVAILABLE"
        }

    try:
        scanner = WebPageScanner(url)
        result = scanner.run()

        ret = {
            "status": result.get("status"),
            "safe_score": result.get("score"),
            "verdict": result.get("verdict")
        }

        if result["findings"]:
            ret["findings"] = result.get("findings")

        print(result["findings"])

        if result["technical_details"]:
            ret["technical_details"] = result.get("technical_details")

        if result["images_scanned"] != 0:
            ret["images_scanned"] = result.get("images_scanned")

        if result["suspicious_images"] != 0:
            ret["suspicious_images"] = result.get("suspicious_images")

        if result["image_links"]:
            ret["image_links"] = result.get("image_links")

        return ret

    except Exception as e:
        return {
            "status": "error2",
            "safe_score": 100,
            "verdict": "UNAVAILABLE"
        }


@app.route("/processor", methods=["GET"])
def processor():
    url = request.args.get("hoveredUrl")

    session["hovered_url"] = url

    if not url:
        return jsonify({"error": "Missing 'hoveredUrl' parameter"}), 400

    url_data = analyze_url(url)
    content_data = analyze_webpage_content(url)

    # Store in session
    session["url_data"] = url_data
    session["content_data"] = content_data

    # Redirect to details page
    return redirect(url_for("website_details"))


@app.route("/website-details", methods=['GET'])
def website_details():
    context_url_data = session.get("url_data")
    context_content_data = session.get("content_data")

    return render_template('index.html',
                           hovered_url=session.get("hovered_url"),
                           context_url_data=context_url_data,
                           context_content_data=context_content_data)


if __name__ == "__main__":
    app.run(debug=True)
