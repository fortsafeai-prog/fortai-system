import asyncio
import base64
import os
from typing import Dict, Any, Optional
from playwright.async_api import async_playwright
import logging

logger = logging.getLogger(__name__)


class ScreenshotService:
    """Service for taking screenshots and dynamic analysis using Playwright"""

    def __init__(self):
        self.browser = None
        self.context = None

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        # Use sandbox settings for security
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-default-apps',
                '--disable-translate',
                '--disable-background-timer-throttling',
                '--disable-renderer-backgrounding',
                '--disable-backgrounding-occluded-windows',
                '--disable-ipc-flooding-protection'
            ]
        )
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def capture_screenshot_and_analyze(self, url: str, job_id: str, timeout: int = 10000) -> Dict[str, Any]:
        """
        Capture screenshot and perform dynamic analysis

        Args:
            url: URL to analyze
            job_id: Job ID for saving artifacts
            timeout: Page load timeout in milliseconds

        Returns:
            Dict containing screenshot data and dynamic analysis results
        """
        result = {
            "screenshot_base64": None,
            "screenshot_path": None,
            "dom_snapshot": None,
            "network_requests": [],
            "console_logs": [],
            "forms_detected": [],
            "external_resources": [],
            "javascript_errors": [],
            "page_title": "",
            "meta_description": "",
            "viewport_content": "",
            "load_time_ms": 0
        }

        page = None

        try:
            page = await self.context.new_page()

            # Set up event listeners for security analysis
            network_requests = []
            console_logs = []
            js_errors = []

            # Monitor network requests
            page.on("request", lambda request: network_requests.append({
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type
            }))

            # Monitor console logs
            page.on("console", lambda msg: console_logs.append({
                "type": msg.type,
                "text": msg.text
            }))

            # Monitor JavaScript errors
            page.on("pageerror", lambda error: js_errors.append({
                "message": str(error),
                "stack": getattr(error, 'stack', None)
            }))

            # Navigate to page with timeout
            start_time = asyncio.get_event_loop().time()

            await page.goto(url, timeout=timeout, wait_until='domcontentloaded')

            # Wait a bit for dynamic content to load
            await page.wait_for_timeout(2000)

            end_time = asyncio.get_event_loop().time()
            load_time = int((end_time - start_time) * 1000)

            # Take screenshot
            screenshot_bytes = await page.screenshot(
                full_page=True,
                type='png'
            )

            # Convert to base64 for storage/transmission
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')

            # Get page title and meta
            title = await page.title()
            meta_description = await page.evaluate("""
                () => {
                    const meta = document.querySelector('meta[name="description"]');
                    return meta ? meta.getAttribute('content') : '';
                }
            """)

            # Get DOM snapshot (sanitized)
            dom_content = await page.content()

            # Analyze forms for potential phishing indicators
            forms = await page.evaluate("""
                () => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    return forms.map(form => ({
                        action: form.action,
                        method: form.method,
                        target: form.target,
                        inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                            type: input.type,
                            name: input.name,
                            placeholder: input.placeholder,
                            required: input.required
                        }))
                    }));
                }
            """)

            # Get external resources
            external_resources = await page.evaluate("""
                () => {
                    const resources = [];

                    // Check scripts
                    document.querySelectorAll('script[src]').forEach(script => {
                        resources.push({
                            type: 'script',
                            src: script.src,
                            external: !script.src.startsWith(window.location.origin)
                        });
                    });

                    // Check stylesheets
                    document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
                        resources.push({
                            type: 'stylesheet',
                            href: link.href,
                            external: !link.href.startsWith(window.location.origin)
                        });
                    });

                    // Check images
                    document.querySelectorAll('img[src]').forEach(img => {
                        if (img.src.startsWith('http')) {
                            resources.push({
                                type: 'image',
                                src: img.src,
                                external: !img.src.startsWith(window.location.origin)
                            });
                        }
                    });

                    return resources;
                }
            """)

            # Get visible text content for analysis
            viewport_text = await page.evaluate("""
                () => {
                    function getVisibleText(element) {
                        const style = window.getComputedStyle(element);
                        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                            return '';
                        }

                        let text = '';
                        for (const child of element.childNodes) {
                            if (child.nodeType === Node.TEXT_NODE) {
                                text += child.textContent;
                            } else if (child.nodeType === Node.ELEMENT_NODE) {
                                text += getVisibleText(child);
                            }
                        }
                        return text;
                    }

                    return getVisibleText(document.body).slice(0, 2000); // Limit to first 2000 chars
                }
            """)

            # Build result
            result.update({
                "screenshot_base64": screenshot_base64,
                "dom_snapshot": dom_content[:10000] if dom_content else "",  # Limit size
                "network_requests": network_requests[:50],  # Limit number
                "console_logs": console_logs[:20],
                "forms_detected": forms,
                "external_resources": external_resources[:30],
                "javascript_errors": js_errors[:10],
                "page_title": title,
                "meta_description": meta_description,
                "viewport_content": viewport_text,
                "load_time_ms": load_time
            })

        except asyncio.TimeoutError:
            logger.warning(f"Page load timeout for {url}")
            result["error"] = "Page load timeout"

        except Exception as e:
            logger.error(f"Screenshot capture failed for {url}: {e}")
            result["error"] = str(e)

        finally:
            if page:
                await page.close()

        return result

    async def save_screenshot_to_file(self, screenshot_base64: str, job_id: str, filename: str = "screenshot.png") -> str:
        """Save screenshot to file system"""
        try:
            # Create artifacts directory if it doesn't exist
            artifacts_dir = f"/tmp/artifacts/{job_id}"
            os.makedirs(artifacts_dir, exist_ok=True)

            # Save screenshot
            screenshot_path = os.path.join(artifacts_dir, filename)
            screenshot_bytes = base64.b64decode(screenshot_base64)

            with open(screenshot_path, 'wb') as f:
                f.write(screenshot_bytes)

            return screenshot_path

        except Exception as e:
            logger.error(f"Failed to save screenshot: {e}")
            return None