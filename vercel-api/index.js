// Vercel serverless function
let puppeteer;
let chrome;

try {
  puppeteer = require('puppeteer-core');
  chrome = require('chrome-aws-lambda');
} catch (e) {
  console.log('Using fallback mode without screenshots');
}

// Import the server logic
const crypto = require('crypto');

// In-memory storage for jobs (will reset on each function call)
const jobs = new Map();

async function captureScreenshot(targetUrl, timeoutMs = 10000) {
    if (!puppeteer || !chrome) {
        return {
            screenshot_base64: null,
            page_title: `Analysis for ${targetUrl}`,
            screenshot_success: false,
            note: "Screenshots not available in this environment"
        };
    }

    let browser;
    try {
        console.log(`Capturing screenshot for: ${targetUrl}`);

        // Use chrome-aws-lambda for Vercel
        browser = await puppeteer.launch({
            args: chrome.args,
            defaultViewport: chrome.defaultViewport,
            executablePath: await chrome.executablePath,
            headless: chrome.headless,
        });

        const page = await browser.newPage();

        await page.setViewport({
            width: 1280,
            height: 720,
            deviceScaleFactor: 1
        });

        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        try {
            await page.goto(targetUrl, {
                waitUntil: 'networkidle2',
                timeout: timeoutMs
            });

            await page.waitForTimeout(2000);

            const screenshot = await page.screenshot({
                type: 'png',
                fullPage: false,
                encoding: 'base64'
            });

            const title = await page.title() || 'No title';

            console.log(`Screenshot captured successfully for ${targetUrl}`);

            return {
                screenshot_base64: screenshot,
                page_title: title,
                screenshot_success: true,
                note: "Real screenshot captured on Vercel"
            };

        } catch (pageError) {
            console.error(`Page navigation failed for ${targetUrl}:`, pageError.message);
            return {
                screenshot_base64: null,
                page_title: `Failed to load: ${targetUrl}`,
                screenshot_success: false,
                note: `Navigation failed: ${pageError.message}`
            };
        }

    } catch (error) {
        console.error(`Screenshot capture failed for ${targetUrl}:`, error.message);
        return {
            screenshot_base64: null,
            page_title: `Error capturing: ${targetUrl}`,
            screenshot_success: false,
            note: `Screenshot failed: ${error.message}`
        };
    } finally {
        if (browser) {
            try {
                await browser.close();
            } catch (closeError) {
                console.error('Error closing browser:', closeError.message);
            }
        }
    }
}

// Main handler
module.exports = async function handler(req, res) {
    const { method, url } = req;
    const parsedUrl = new URL(url, `https://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    // Routes
    if (pathname === '/' && method === 'GET') {
        res.setHeader('Content-Type', 'text/html');
        res.status(200).send(`
            <!DOCTYPE html>
            <html>
            <head><title>ForTAI - Vercel Edition</title></head>
            <body>
                <h1>🛡️ ForTAI - AI URL Security Analysis</h1>
                <p><a href="/chat">Start Analysis / Starta Analys</a></p>
            </body>
            </html>
        `);
        return;
    }

    if (pathname === '/chat' && method === 'GET') {
        res.setHeader('Content-Type', 'text/html');
        res.status(200).send(`
            <!DOCTYPE html>
            <html>
            <head><title>ForTAI Chat</title></head>
            <body>
                <h1>🛡️ ForTAI Chat Interface</h1>
                <input type="url" id="urlInput" placeholder="Enter URL...">
                <button onclick="analyze()">Analyze</button>
                <div id="result"></div>

                <script>
                async function analyze() {
                    const url = document.getElementById('urlInput').value;
                    const response = await fetch('/api/analyze', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({url})
                    });
                    const result = await response.json();
                    document.getElementById('result').innerHTML =
                        '<h3>Result:</h3><pre>' + JSON.stringify(result, null, 2) + '</pre>';
                }
                </script>
            </body>
            </html>
        `);
        return;
    }

    if (pathname === '/api/analyze' && method === 'POST') {
        try {
            const { url: targetUrl } = req.body;

            // Basic URL analysis
            let riskScore = 0;
            const evidence = [];

            try {
                const urlObj = new URL(targetUrl);

                if (urlObj.hostname.match(/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/)) {
                    riskScore += 30;
                    evidence.push("URL uses IP address instead of domain name");
                }

                if (targetUrl.length > 100) {
                    riskScore += 15;
                    evidence.push("Unusually long URL");
                }

            } catch (error) {
                riskScore += 40;
                evidence.push("Invalid URL structure");
            }

            // Determine verdict
            let verdict, confidence;
            if (riskScore >= 60) {
                verdict = "dangerous";
                confidence = 90;
            } else if (riskScore >= 30) {
                verdict = "suspicious";
                confidence = 75;
            } else {
                verdict = "safe";
                confidence = 85;
                if (evidence.length === 0) {
                    evidence.push("No significant security risks detected");
                }
            }

            // Capture screenshot
            const screenshotData = await captureScreenshot(targetUrl);

            const result = {
                url: targetUrl,
                verdict,
                confidence,
                evidence: evidence.slice(0, 4),
                artifacts: screenshotData,
                status: 'completed'
            };

            res.status(200).json(result);

        } catch (error) {
            res.status(500).json({ error: error.message });
        }
        return;
    }

    // 404
    res.status(404).json({ error: 'Not Found' });
}