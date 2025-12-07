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
            "file_type": None,
            "is_malicious": False,
            "score": 0,
            "findings": []
        }

    def _add_finding(self, score, title, desc):
        self.report["score"] += score
        self.report["findings"].append({
            "title": title,
            "description": desc
        })
        if score >= 20:
            self.report["is_malicious"] = True

    
    def _extract_text(self, raw):
        return raw.decode("latin-1", errors="ignore")


    def _detect_fake_header(self, raw):
        text = self._extract_text(raw)

        # If content is mostly ASCII → fake image
        ascii_chars = sum(c.isascii() for c in text)
        ratio = ascii_chars / max(1, len(text))

        if ratio > 0.80:  # 80% ASCII → suspicious
            self._add_finding(
                40,
                "Fake Image Detected",
                "Payload appears to be plain text disguised as an image."
            )

        # PNG files MUST start with PNG signature
        if self.url.endswith(".png") and not raw.startswith(b"\x89PNG\r\n\x1a\n"):
            self._add_finding(
                50,
                "Invalid PNG Header",
                "Image does not contain a valid PNG header."
            )

        # JPEG must begin with FF D8
        if self.url.endswith(".jpg") or self.url.endswith(".jpeg"):
            if not raw.startswith(b"\xFF\xD8"):
                self._add_finding(
                    50,
                    "Invalid JPEG Header",
                    "Image does not contain a valid JPEG header."
                )

    def _scan_embedded_code(self, raw):
        text = self._extract_text(raw).lower()

        if "<script" in text:
            self._add_finding(
                70,
                "Embedded JavaScript",
                "<script> tag detected inside image bytes (polyglot attack)."
            )

        if "function(" in text or "alert(" in text:
            self._add_finding(
                50,
                "JavaScript Code Inside Image",
                "Image contains JS code."
            )

        if "<html" in text or "<svg" in text:
            self._add_finding(
                50,
                "HTML Payload Inside Image",
                "Image is actually HTML disguised as PNG/JPG."
            )

        urls = re.findall(r"https?://[^\s\"']+", text)
        if urls:
            self._add_finding(
                40,
                "URLs Embedded in Image",
                f"Found URLs inside image: {urls[:3]}"
            )

        # Keyword-based malicious behavior
        suspicious_keywords = [
            "steal", "malware", "phish", "attack", "payload", "send(", "fetch("
        ]
        if any(word in text for word in suspicious_keywords):
            self._add_finding(
                30,
                "Suspicious Text Payload",
                "Malicious keywords detected inside image bytes."
            )

  
    def _check_entropy(self, raw):
        freq = {}
        for b in raw:
            freq[b] = freq.get(b, 0) + 1

        entropy = 0
        length = len(raw)

        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        if entropy > 7.95:
            self._add_finding(
                15,
                "High Entropy",
                f"Entropy unusually high ({entropy:.2f})"
            )
        elif entropy < 5.5:
            self._add_finding(
                10,
                "Low Entropy",
                f"Entropy unusually low ({entropy:.2f})"
            )

    def run(self):
        try:
            response = self.session.get(self.url, timeout=5)
            raw = response.content

            # Detect file type
            img_type = imghdr.what(None, raw)
            self.report["file_type"] = img_type or "unknown"

            self._detect_fake_header(raw)

            self._scan_embedded_code(raw)

            self._check_entropy(raw)

            try:
                Image.open(BytesIO(raw))
            except:
                self._add_finding(
                    20,
                    "Unreadable Image File",
                    "Image cannot be parsed — may be intentionally malformed."
                )

        except Exception as e:
            self._add_finding(10, "Load Error", str(e))

        self.report["score"] = min(100, self.report["score"])
        return self.report
