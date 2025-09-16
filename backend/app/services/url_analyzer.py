import asyncio
import aiohttp
import urllib.parse
import dns.resolver
import whois
import ssl
import socket
import tldextract
import idna
from confusable_homoglyphs import confusables
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional
import json
import logging
from .screenshot_service import ScreenshotService
from .ml_classifier import MLClassifier

logger = logging.getLogger(__name__)


class URLAnalyzer:
    def __init__(self):
        self.session = None

    async def analyze(self, url: str, job_id: str) -> Dict[str, Any]:
        """Main analysis pipeline"""
        try:
            # Initialize session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )

            analysis_result = {
                "job_id": job_id,
                "url": url,
                "steps": {}
            }

            # Step 1: URL normalization & safety checks
            normalized_url, url_features = await self._normalize_and_check_url(url)
            analysis_result["steps"]["normalization"] = url_features

            # Step 2: DNS & WHOIS
            dns_data = await self._dns_and_whois_lookup(normalized_url)
            analysis_result["steps"]["dns_whois"] = dns_data

            # Step 3: TLS cert & host info
            cert_data = await self._tls_cert_analysis(normalized_url)
            analysis_result["steps"]["tls_cert"] = cert_data

            # Step 4: HTTP fetch and redirect chain
            http_data = await self._http_fetch_and_redirects(normalized_url)
            analysis_result["steps"]["http_analysis"] = http_data

            # Step 5: URL token analysis
            token_analysis = await self._url_token_analysis(normalized_url)
            analysis_result["steps"]["token_analysis"] = token_analysis

            # Step 6: Reputation checks
            reputation_data = await self._reputation_checks(normalized_url)
            analysis_result["steps"]["reputation"] = reputation_data

            # Step 7: Content analysis
            content_analysis = await self._content_analysis(http_data.get("html_content", ""))
            analysis_result["steps"]["content_analysis"] = content_analysis

            # Step 8: Screenshot and dynamic analysis
            screenshot_data = await self._dynamic_screenshot_analysis(normalized_url, job_id)
            analysis_result["steps"]["screenshot_analysis"] = screenshot_data

            # Step 9: Feature compilation and risk assessment
            risk_assessment = await self._compile_risk_assessment(analysis_result)
            analysis_result["risk_assessment"] = risk_assessment

            # Step 10: Generate Swedish summary
            from .llm_summarizer import LLMSummarizer
            summarizer = LLMSummarizer()
            swedish_summary = await summarizer.generate_swedish_summary(analysis_result)
            analysis_result["swedish_summary"] = swedish_summary

            return analysis_result

        except Exception as e:
            logger.error(f"Analysis failed for {url}: {e}")
            raise
        finally:
            if self.session:
                await self.session.close()

    async def _normalize_and_check_url(self, url: str) -> tuple[str, Dict[str, Any]]:
        """Step 1: URL normalization & safety checks"""
        url = url.strip()

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urllib.parse.urlparse(url)

        # Extract domain components
        extracted = tldextract.extract(parsed.netloc)

        features = {
            "original_url": url,
            "domain": extracted.domain,
            "subdomain": extracted.subdomain,
            "suffix": extracted.suffix,
            "is_ip": self._is_ip_address(parsed.netloc),
            "has_punycode": self._has_punycode(parsed.netloc),
            "url_length": len(url),
            "path_length": len(parsed.path),
            "query_length": len(parsed.query or ""),
        }

        return url, features

    async def _dns_and_whois_lookup(self, url: str) -> Dict[str, Any]:
        """Step 2: DNS & WHOIS lookup"""
        parsed = urllib.parse.urlparse(url)
        domain = tldextract.extract(parsed.netloc).registered_domain

        dns_data = {}

        try:
            # DNS lookup
            answers = dns.resolver.resolve(domain, 'A')
            dns_data["a_records"] = [str(rdata) for rdata in answers]
        except Exception as e:
            dns_data["dns_error"] = str(e)

        try:
            # WHOIS lookup
            w = whois.whois(domain)
            dns_data["creation_date"] = str(w.creation_date) if w.creation_date else None
            dns_data["registrar"] = str(w.registrar) if w.registrar else None
            dns_data["name_servers"] = w.name_servers if w.name_servers else []
        except Exception as e:
            dns_data["whois_error"] = str(e)

        return dns_data

    async def _tls_cert_analysis(self, url: str) -> Dict[str, Any]:
        """Step 3: TLS certificate analysis"""
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        cert_data = {}

        if parsed.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cert_data = {
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "not_before": cert['notBefore'],
                            "not_after": cert['notAfter'],
                            "serial_number": cert['serialNumber'],
                        }
            except Exception as e:
                cert_data["cert_error"] = str(e)

        return cert_data

    async def _http_fetch_and_redirects(self, url: str) -> Dict[str, Any]:
        """Step 4: HTTP fetch and redirect chain analysis"""
        http_data = {
            "redirect_chain": [],
            "final_url": url,
            "status_code": None,
            "headers": {},
            "html_content": "",
        }

        try:
            async with self.session.get(url, allow_redirects=False) as response:
                current_url = str(response.url)
                redirect_count = 0

                while response.status in (301, 302, 303, 307, 308) and redirect_count < 5:
                    location = response.headers.get('Location')
                    if not location:
                        break

                    http_data["redirect_chain"].append({
                        "url": current_url,
                        "status": response.status,
                        "location": location
                    })

                    current_url = urllib.parse.urljoin(current_url, location)
                    redirect_count += 1

                    response = await self.session.get(current_url, allow_redirects=False)

                http_data["final_url"] = current_url
                http_data["status_code"] = response.status
                http_data["headers"] = dict(response.headers)

                if response.status == 200:
                    html_content = await response.text()
                    http_data["html_content"] = html_content

        except Exception as e:
            http_data["http_error"] = str(e)

        return http_data

    async def _url_token_analysis(self, url: str) -> Dict[str, Any]:
        """Step 5: URL token analysis"""
        parsed = urllib.parse.urlparse(url)

        suspicious_keywords = [
            'login', 'signin', 'secure', 'verify', 'account', 'bank', 'paypal',
            'amazon', 'google', 'microsoft', 'apple', 'facebook', 'update'
        ]

        analysis = {
            "suspicious_keywords": [],
            "long_hex_tokens": [],
            "base64_patterns": [],
            "subdomain_count": len(parsed.netloc.split('.')),
            "has_homoglyphs": False,
        }

        # Check for suspicious keywords
        url_lower = url.lower()
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                analysis["suspicious_keywords"].append(keyword)

        # Check for homoglyphs
        try:
            analysis["has_homoglyphs"] = confusables.is_confusable(parsed.netloc, greedy=True)
        except:
            pass

        return analysis

    async def _reputation_checks(self, url: str) -> Dict[str, Any]:
        """Step 6: Reputation checks"""
        # Placeholder for reputation checks
        # In a real implementation, you would check against:
        # - PhishTank API
        # - VirusTotal API
        # - Google Safe Browsing API
        # - Local blocklists

        return {
            "phishtank_result": None,
            "virustotal_result": None,
            "safebrowsing_result": None,
            "reputation_score": 50,  # Neutral score
        }

    async def _content_analysis(self, html_content: str) -> Dict[str, Any]:
        """Step 7: Content analysis"""
        if not html_content:
            return {"content_error": "No HTML content available"}

        try:
            soup = BeautifulSoup(html_content, 'html.parser')

            analysis = {
                "title": soup.title.string if soup.title else "",
                "forms": [],
                "external_links": [],
                "suspicious_elements": [],
            }

            # Analyze forms
            for form in soup.find_all('form'):
                form_data = {
                    "action": form.get('action', ''),
                    "method": form.get('method', 'get').lower(),
                    "inputs": []
                }

                for input_tag in form.find_all('input'):
                    input_data = {
                        "type": input_tag.get('type', 'text'),
                        "name": input_tag.get('name', ''),
                    }
                    form_data["inputs"].append(input_data)

                analysis["forms"].append(form_data)

            # Check for login forms
            has_login_form = any(
                any(inp["name"].lower() in ["username", "email", "password"]
                    for inp in form["inputs"])
                for form in analysis["forms"]
            )
            analysis["has_login_form"] = has_login_form

            return analysis

        except Exception as e:
            return {"content_analysis_error": str(e)}

    async def _compile_risk_assessment(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Step 9: Compile risk assessment with ML classification"""
        risk_score = 0
        evidence = []

        # Get ML classification
        try:
            classifier = MLClassifier()
            ml_result = classifier.classify(analysis_result["url"], analysis_result)
            ml_score = ml_result.get("phishing_score", 0) * 100  # Convert to 0-100 scale
            risk_score += ml_score * 0.6  # ML contributes 60% to final score

            if ml_result.get("classification") == "phishing":
                evidence.append(f"ML classifier detected phishing patterns (confidence: {ml_result.get('confidence', 0):.0f}%)")
            elif ml_result.get("classification") == "suspicious":
                evidence.append(f"ML classifier flagged as suspicious (confidence: {ml_result.get('confidence', 0):.0f}%)")

        except Exception as e:
            logger.error(f"ML classification failed: {e}")
            ml_score = 0

        # Analyze various risk factors (heuristic rules contribute 40%)
        steps = analysis_result.get("steps", {})

        # URL structure risks (reduced weights since ML contributes 60%)
        url_analysis = steps.get("normalization", {})
        if url_analysis.get("is_ip"):
            risk_score += 12  # Reduced from 30
            evidence.append("URL uses IP address instead of domain name")

        if url_analysis.get("has_punycode"):
            risk_score += 8  # Reduced from 20
            evidence.append("URL contains punycode (internationalized domain)")

        if url_analysis.get("url_length", 0) > 100:
            risk_score += 4  # Reduced from 10
            evidence.append("Unusually long URL")

        # Redirect chain risks
        http_analysis = steps.get("http_analysis", {})
        redirect_count = len(http_analysis.get("redirect_chain", []))
        if redirect_count > 2:
            risk_score += 6 * redirect_count  # Reduced from 15
            evidence.append(f"Multiple redirects detected ({redirect_count} redirects)")

        # Content risks
        content_analysis = steps.get("content_analysis", {})
        if content_analysis.get("has_login_form"):
            risk_score += 10  # Reduced from 25
            evidence.append("Contains login form")

        # Token analysis risks
        token_analysis = steps.get("token_analysis", {})
        suspicious_count = len(token_analysis.get("suspicious_keywords", []))
        if suspicious_count > 0:
            risk_score += 4 * suspicious_count  # Reduced from 10
            evidence.append(f"Contains suspicious keywords: {', '.join(token_analysis.get('suspicious_keywords', []))}")

        # Screenshot analysis risks
        screenshot_analysis = steps.get("screenshot_analysis", {})
        phishing_indicators = screenshot_analysis.get("phishing_indicators", [])
        for indicator in phishing_indicators:
            if "external domain" in indicator:
                risk_score += 16  # Reduced from 40
            elif "login form" in indicator:
                risk_score += 12  # Reduced from 30
            elif "external scripts" in indicator:
                risk_score += 6  # Reduced from 15
            evidence.append(indicator)

        # Determine verdict
        if risk_score >= 70:
            verdict = "dangerous"
        elif risk_score >= 40:
            verdict = "suspicious"
        else:
            verdict = "safe"

        confidence = min(95, max(60, 100 - abs(risk_score - 50)))

        return {
            "verdict": verdict,
            "confidence": confidence,
            "risk_score": risk_score,
            "evidence": evidence[:6]  # Limit to top 6 evidence points
        }

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        try:
            socket.inet_aton(hostname)
            return True
        except socket.error:
            return False

    def _has_punycode(self, hostname: str) -> bool:
        """Check if hostname contains punycode"""
        try:
            decoded = idna.decode(hostname.encode('ascii'))
            return decoded != hostname
        except:
            return False

    async def _dynamic_screenshot_analysis(self, url: str, job_id: str) -> Dict[str, Any]:
        """Step 8: Dynamic screenshot and browser analysis"""
        screenshot_data = {}

        try:
            async with ScreenshotService() as screenshot_service:
                screenshot_result = await screenshot_service.capture_screenshot_and_analyze(url, job_id)
                screenshot_data.update(screenshot_result)

                # Additional security analysis based on dynamic content
                forms = screenshot_result.get("forms_detected", [])
                external_resources = screenshot_result.get("external_resources", [])

                # Analyze forms for phishing indicators
                phishing_indicators = []
                for form in forms:
                    if form.get("action") and not form["action"].startswith(urllib.parse.urlparse(url).netloc):
                        phishing_indicators.append("Form posts to external domain")

                    # Check for common login form patterns
                    input_types = [inp.get("type", "") for inp in form.get("inputs", [])]
                    if "password" in input_types and "email" in [inp.get("name", "").lower() for inp in form.get("inputs", [])]:
                        phishing_indicators.append("Contains login form with email/password fields")

                # Analyze external resources
                external_script_count = len([r for r in external_resources if r.get("type") == "script" and r.get("external")])
                if external_script_count > 5:
                    phishing_indicators.append(f"High number of external scripts ({external_script_count})")

                screenshot_data["phishing_indicators"] = phishing_indicators
                screenshot_data["analysis_success"] = True

        except Exception as e:
            logger.error(f"Screenshot analysis failed: {e}")
            screenshot_data = {
                "analysis_success": False,
                "error": str(e),
                "phishing_indicators": []
            }

        return screenshot_data