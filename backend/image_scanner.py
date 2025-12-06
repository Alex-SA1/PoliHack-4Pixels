import requests
from PIL import Image
from io import BytesIO
import re
import base64
import math
import imghdr


class ImageSecurityScanner:
    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.report = {
            "image_url": url,
            "is_malicious": False,
            "score": 0,
            "findings": []
        }

    def _add(self, score, title, desc):
        self.report["score"] += score
        self.report["findings"].append({"title": title, "description": desc})
        if score >= 20:
            self.report["is_malicious"] = True

    # steganography detection (lsb / entropy anomalies)

    def _detect_stego(self, img):
        try:
            pixels = list(img.convert("RGB").getdata())
            lsb_count = 0
            total = len(pixels) * 3

            for r, g, b in pixels[:5000]:  # sample only first 5k pixels
                lsb_count += (r & 1) + (g & 1) + (b & 1)

            ratio = lsb_count / total

            # random images should be around 0.50 LSB randomness
            if ratio < 0.40 or ratio > 0.60:
                self._add(25, "Possible Steganography",
                          f"LSB noise anomaly detected ({ratio:.2f}).")
        except:
            pass

    # detect embedded <script> or html inside image bytes
    def _check_for_scripts(self, raw):
        text = raw.decode("latin-1", errors="ignore").lower()

        if "<script" in text or "function(" in text:
            self._add(45, "🚨 Script Found Inside Image",
                      "Image contains JavaScript code (polyglot attack).")

        if "<html" in text or "<svg" in text:
            self._add(40, "🚨 HTML Found Inside Image",
                      "Image is a disguised HTML/SVG polyglot.")

        # Embedded URLs
        urls = re.findall(r"https?://[^\s\"']+", text)
        if urls:
            self._add(20, "Suspicious URLs Found in Image",
                      f"Embedded URLs: {urls[:3]}")

    # detect SVG-based attacks
    def _scan_svg(self, text):
        if "<script" in text:
            self._add(50, "🚨 Malicious SVG Script",
                      "SVG contains JavaScript execution.")

        if "onload=" in text or "onerror=" in text:
            self._add(30, "⚠ SVG Event Handler",
                      "SVG contains event handlers capable of executing JS.")

        if "fetch(" in text or "xmlhttprequest" in text:
            self._add(45, "🚨 Data Exfiltration in SVG",
                      "SVG contains network calls used for phishing/malware.")

    # ---------------------------------------------------
    # MAIN SCAN
    # ---------------------------------------------------
    def run(self):
        try:
            response = self.session.get(self.url, timeout=6)
            raw = response.content

            # 0. Detect file type
            img_type = imghdr.what(None, raw)
            self.report["file_type"] = img_type or "unknown"

            # Case: SVG (not binary)
            if self.url.lower().endswith(".svg") or "<svg" in raw.decode("latin-1", errors="ignore"):
                self._scan_svg(raw.decode('utf-8', errors='ignore'))

            # 1. Check for scripts or HTML inside binary
            self._check_for_scripts(raw)

            # 2. Load into PIL if possible
            try:
                img = Image.open(BytesIO(raw))
                self._detect_stego(img)
            except:
                self._add(5, "Not Displayable as Image",
                          "Image cannot be parsed normally.")

        except Exception as e:
            self._add(5, "Image Access Error", str(e))

        self.report["score"] = min(self.report["score"], 100)
        return self.report
