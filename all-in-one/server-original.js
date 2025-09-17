const http = require('http');
const url = require('url');
const crypto = require('crypto');
const puppeteer = require('puppeteer');

const PORT = process.env.PORT || 8080;

// In-memory storage for jobs
const jobs = new Map();
const ANALYSIS_DELAY = 3000;

function generateJobId() {
    return crypto.randomUUID();
}

async function captureScreenshot(targetUrl, timeoutMs = 10000) {
    let browser;
    try {
        console.log(`Capturing screenshot for: ${targetUrl}`);

        browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--single-process',
                '--disable-gpu',
                '--memory-pressure-off',
                '--max_old_space_size=4096'
            ]
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
                note: "Real screenshot captured"
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

async function analyzeUrl(targetUrl) {
    console.log(`Analyzing: ${targetUrl}`);

    let riskScore = 0;
    const evidence = [];

    try {
        const urlObj = new URL(targetUrl);

        // Basic analysis
        if (urlObj.hostname.match(/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/)) {
            riskScore += 30;
            evidence.push("URL uses IP address instead of domain name");
        }

        if (targetUrl.length > 100) {
            riskScore += 15;
            evidence.push("Unusually long URL");
        }

        const suspiciousKeywords = ['phishing', 'malicious', 'fake', 'scam', 'verify', 'suspend'];
        for (const keyword of suspiciousKeywords) {
            if (targetUrl.toLowerCase().includes(keyword)) {
                riskScore += 25;
                evidence.push(`URL contains suspicious keyword: "${keyword}"`);
                break;
            }
        }

        const shorteners = ['bit.ly', 'tinyurl', 'short.ly', 't.co'];
        for (const shortener of shorteners) {
            if (urlObj.hostname.includes(shortener)) {
                riskScore += 20;
                evidence.push("Uses URL shortener service");
                break;
            }
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
            evidence.push("Domain appears legitimate");
            evidence.push("No suspicious URL patterns found");
        }
    }

    const verdictMap = {
        "safe": "Säker",
        "suspicious": "Misstänkt",
        "dangerous": "Farlig"
    };

    const actionMap = {
        "safe": "Länken verkar säker att besöka.",
        "suspicious": "Var försiktig. Granska länken manuellt innan du besöker den.",
        "dangerous": "Blockera denna länk. Den kan vara skadlig eller innehålla bedrägerier."
    };

    const domain = targetUrl ? new URL(targetUrl).hostname : 'okänd domän';
    const swedishSummary = `Bedömning: ${verdictMap[verdict]}. Säkerhetsnivå: ${confidence}%. Domän: ${domain}. ${actionMap[verdict]}`;

    // Capture real screenshot
    const screenshotData = await captureScreenshot(targetUrl);

    return {
        verdict,
        confidence,
        evidence: evidence.slice(0, 4),
        swedish_summary: swedishSummary,
        artifacts: screenshotData
    };
}

const landingPageHtml = `<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForTAI - AI-driven URL Säkerhetsanalys</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
        header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 1rem 0;
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
        }
        .nav-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 1.8rem;
            font-weight: bold;
            color: white;
            text-decoration: none;
        }
        .nav-links {
            display: flex;
            list-style: none;
            gap: 2rem;
        }
        .nav-links a {
            color: white;
            text-decoration: none;
            font-weight: 500;
            transition: opacity 0.3s;
        }
        .nav-links a:hover { opacity: 0.8; }
        .hero {
            text-align: center;
            padding: 150px 0 100px 0;
            color: white;
        }
        .hero h1 {
            font-size: 3.5rem;
            margin-bottom: 1rem;
            background: linear-gradient(45deg, #fff, #f0f0f0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .hero p {
            font-size: 1.2rem;
            margin-bottom: 2rem;
            opacity: 0.9;
        }
        .cta-button {
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            padding: 15px 40px;
            font-size: 1.1rem;
            font-weight: 600;
            text-decoration: none;
            border-radius: 50px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }
        .cta-button:hover {
            background: rgba(255, 255, 255, 0.3);
            border-color: rgba(255, 255, 255, 0.5);
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }
        .features {
            background: white;
            padding: 100px 0;
        }
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 3rem;
            margin-top: 3rem;
        }
        .feature-card {
            text-align: center;
            padding: 2rem;
            border-radius: 15px;
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.1);
        }
        .feature-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            display: block;
        }
        .feature-card h3 {
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: #333;
        }
        .feature-card p {
            color: #666;
            line-height: 1.6;
        }
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 40px 0;
        }
        @media (max-width: 768px) {
            .hero h1 { font-size: 2.5rem; }
            .hero p { font-size: 1rem; }
            .nav-links { display: none; }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="nav-container">
                <a href="/" class="logo">🛡️ ForTAI</a>
                <ul class="nav-links">
                    <li><a href="#features">Funktioner</a></li>
                    <li><a href="/chat">Starta analys</a></li>
                </ul>
            </div>
        </div>
    </header>

    <main>
        <section class="hero">
            <div class="container">
                <h1>AI-driven URL Säkerhetsanalys</h1>
                <p>Avancerad säkerhetsanalys av webbsidor med artificiell intelligens. Upptäck phishing, malware och andra hot innan de når dig.</p>
                <a href="/chat" class="cta-button">
                    🚀 Starta analys nu
                </a>
            </div>
        </section>

        <section id="features" class="features">
            <div class="container">
                <h2 style="text-align: center; font-size: 2.5rem; margin-bottom: 1rem;">Varför välja ForTAI?</h2>
                <p style="text-align: center; font-size: 1.1rem; color: #666; margin-bottom: 3rem;">
                    Vårt AI-system analyserar webbsidor på djupet för att identifiera säkerhetsrisker
                </p>

                <div class="features-grid">
                    <div class="feature-card">
                        <span class="feature-icon">🔍</span>
                        <h3>Djupanalys</h3>
                        <p>Avancerad analys av URL-struktur, innehåll och säkerhetscertifikat för att identifiera potentiella hot.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">🤖</span>
                        <h3>AI-driven</h3>
                        <p>Maskininlärning och AI-teknologi för att upptäcka nya och okända hot som traditionella metoder missar.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">⚡</span>
                        <h3>Snabb analys</h3>
                        <p>Få resultat inom sekunder. Perfekt för att snabbt verifiera länkar innan du klickar på dem.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">🇸🇪</span>
                        <h3>Svenska</h3>
                        <p>Helt på svenska med tydliga förklaringar och rekommendationer som är lätta att förstå.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">📱</span>
                        <h3>Mobilanpassad</h3>
                        <p>Fungerar perfekt på alla enheter - dator, surfplatta och mobiltelefon. Analysera var som helst.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">🆓</span>
                        <h3>Gratis</h3>
                        <p>Använd ForTAI kostnadsfritt utan registrering. Vi tror att cybersäkerhet ska vara tillgängligt för alla.</p>
                    </div>
                </div>

                <div style="text-align: center; margin-top: 4rem;">
                    <a href="/chat" class="cta-button">
                        Testa ForTAI nu - Det är gratis! 🚀
                    </a>
                </div>
            </div>
        </section>
    </main>

    <footer class="footer">
        <div class="container">
            <p>&copy; 2025 ForTAI. AI-driven cybersäkerhet för alla.</p>
            <p style="margin-top: 10px; opacity: 0.8;">
                <a href="/chat" style="color: #ffd700;">Starta din första analys här</a>
            </p>
        </div>
    </footer>
</body>
</html>`;

const chatPageHtml = `<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForTAI - Chat Interface</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .back-link {
            position: fixed;
            top: 20px;
            left: 20px;
            background: rgba(255,255,255,0.9);
            color: #667eea;
            padding: 10px 15px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: bold;
            backdrop-filter: blur(10px);
            transition: all 0.3s;
        }
        .back-link:hover {
            background: white;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .chat-container {
            width: 90%;
            max-width: 800px;
            height: 80vh;
            background: white;
            border-radius: 20px;
            display: flex;
            flex-direction: column;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .chat-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
        }
        .chat-messages {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            background: #f8f9fa;
        }
        .message {
            display: flex;
            margin-bottom: 20px;
            align-items: flex-start;
        }
        .message.bot { justify-content: flex-start; }
        .message.user { justify-content: flex-end; }
        .message-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            margin: 0 10px;
        }
        .message.bot .message-avatar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .message.user .message-avatar {
            background: #28a745;
            color: white;
        }
        .message-content {
            max-width: 70%;
            padding: 15px 20px;
            border-radius: 18px;
            line-height: 1.5;
        }
        .message.bot .message-content {
            background: white;
            border: 1px solid #e0e0e0;
            margin-right: auto;
        }
        .message.user .message-content {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin-left: auto;
        }
        .chat-input {
            display: flex;
            padding: 20px;
            background: white;
            border-top: 1px solid #e0e0e0;
        }
        .chat-input input {
            flex: 1;
            padding: 15px 20px;
            border: 1px solid #ddd;
            border-radius: 25px;
            font-size: 1rem;
            outline: none;
        }
        .chat-input button {
            margin-left: 10px;
            padding: 15px 25px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1rem;
        }
        .chat-input button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .verdict.safe { color: #28a745; font-weight: bold; }
        .verdict.suspicious { color: #ffc107; font-weight: bold; }
        .verdict.dangerous { color: #dc3545; font-weight: bold; }
        .loading { color: #666; font-style: italic; }
        @media (max-width: 768px) {
            .chat-container { width: 95%; height: 90vh; }
            .message-content { max-width: 85%; }
        }
    </style>
</head>
<body>
    <a href="/" class="back-link">← Tillbaka till huvudsidan</a>

    <div class="chat-container">
        <div class="chat-header">
            <h1>🛡️ ForTAI - AI Säkerhetsanalys</h1>
            <p>Klistra in en URL för djupgående säkerhetsanalys</p>
        </div>

        <div class="chat-messages" id="messages">
            <div class="message bot">
                <div class="message-avatar">🤖</div>
                <div class="message-content">
                    Hej! Klistra in en URL nedan så gör jag en djupanalys av länken för att kontrollera om den är säker.
                    <br><br>
                    <strong>Exempel:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li>https://google.com</li>
                        <li>https://github.com</li>
                        <li>https://example.com</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="chat-input">
            <input type="url" id="urlInput" placeholder="https://example.com" />
            <button onclick="analyzeUrl()" id="sendButton">Analysera</button>
        </div>
    </div>

    <script>
        let isAnalyzing = false;

        function addMessage(content, type = 'bot') {
            const messagesContainer = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = \`message \${type}\`;

            const avatar = type === 'bot' ? '🤖' : '👤';

            messageDiv.innerHTML = \`
                <div class="message-avatar">\${avatar}</div>
                <div class="message-content">\${content}</div>
            \`;

            messagesContainer.appendChild(messageDiv);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }

        async function analyzeUrl() {
            const urlInput = document.getElementById('urlInput');
            const sendButton = document.getElementById('sendButton');
            const url = urlInput.value.trim();

            if (!url || isAnalyzing) return;

            try {
                new URL(url.startsWith('http') ? url : \`https://\${url}\`);
            } catch (e) {
                addMessage('❌ Vänligen ange en giltig URL. Exempel: https://example.com eller example.com');
                return;
            }

            addMessage(\`Analysera: \${url}\`, 'user');

            urlInput.value = '';
            isAnalyzing = true;
            sendButton.disabled = true;
            sendButton.textContent = 'Analyserar...';

            addMessage('<div class="loading">Analyserar URL... Vänta ett ögonblick.</div>');

            try {
                // Start analysis
                const analyzeResponse = await fetch('/api/analyze/url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                if (!analyzeResponse.ok) {
                    throw new Error('Failed to start analysis');
                }

                const analyzeData = await analyzeResponse.json();
                const jobId = analyzeData.job_id;

                // Poll for results
                let attempts = 0;
                const maxAttempts = 15;

                const pollResults = async () => {
                    if (attempts >= maxAttempts) {
                        throw new Error('Analysis timeout');
                    }

                    const resultResponse = await fetch(\`/api/results/\${jobId}\`);

                    if (!resultResponse.ok) {
                        throw new Error('Failed to get results');
                    }

                    const result = await resultResponse.json();

                    if (result.status === 'completed') {
                        const verdictIcons = {
                            'safe': '✅',
                            'suspicious': '⚠️',
                            'dangerous': '❌'
                        };

                        const verdictTexts = {
                            'safe': 'Säker',
                            'suspicious': 'Misstänkt',
                            'dangerous': 'Farlig'
                        };

                        let resultHtml = \`
                            <div style="margin: 15px 0;">
                                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                                    <span style="font-size: 1.5rem;">\${verdictIcons[result.verdict] || '❓'}</span>
                                    <span class="verdict \${result.verdict}">\${verdictTexts[result.verdict] || 'Okänd'}</span>
                                    <span>(\${result.confidence}%)</span>
                                </div>
                                <p style="margin-bottom: 15px; font-weight: 500;">
                                    \${result.swedish_summary || 'Analys slutförd.'}
                                </p>
                        \`;

                        if (result.evidence && result.evidence.length > 0) {
                            resultHtml += '<div><strong>Analysresultat:</strong><ul style="margin: 10px 0; padding-left: 20px;">';
                            result.evidence.forEach(evidence => {
                                resultHtml += \`<li>\${evidence}</li>\`;
                            });
                            resultHtml += '</ul></div>';
                        }

                        // Add screenshot if available
                        if (result.artifacts && result.artifacts.screenshot_base64) {
                            resultHtml += \`
                                <div style="margin: 15px 0;">
                                    <strong>📸 Skärmbild av webbsidan:</strong>
                                    <div style="margin-top: 10px; border: 2px solid #ddd; border-radius: 8px; overflow: hidden;">
                                        <img src="data:image/png;base64,\${result.artifacts.screenshot_base64}"
                                             style="width: 100%; height: auto; max-width: 500px; display: block;"
                                             alt="Screenshot av \${result.artifacts.page_title}">
                                    </div>
                                    <div style="font-size: 0.8rem; color: #888; margin-top: 5px;">
                                        Titel: \${result.artifacts.page_title}
                                    </div>
                                </div>
                            \`;
                        } else if (result.artifacts && result.artifacts.note) {
                            resultHtml += \`
                                <div style="margin: 15px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; font-size: 0.9rem; color: #666;">
                                    📸 Skärmbild: \${result.artifacts.note}
                                </div>
                            \`;
                        }

                        resultHtml += \`
                            <div style="margin-top: 15px; font-size: 0.9rem; color: #666; word-break: break-all;">
                                <strong>Analyserad URL:</strong> \${result.url}
                            </div>
                        </div>\`;

                        addMessage(resultHtml);
                    } else if (result.status === 'failed') {
                        throw new Error(result.error || 'Analysis failed');
                    } else {
                        attempts++;
                        setTimeout(pollResults, 1000);
                    }
                };

                await pollResults();

            } catch (error) {
                console.error('Analysis error:', error);
                addMessage(\`❌ Kunde inte analysera URL: \${error.message}. Försök igen om en stund.\`);
            } finally {
                isAnalyzing = false;
                sendButton.disabled = false;
                sendButton.textContent = 'Analysera';
            }
        }

        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !isAnalyzing) {
                analyzeUrl();
            }
        });

        document.getElementById('urlInput').focus();
    </script>
</body>
</html>`;

const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const method = req.method;

    // CORS headers
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json'
    };

    if (method === 'OPTIONS') {
        res.writeHead(200, corsHeaders);
        res.end();
        return;
    }

    // Routes
    if (pathname === '/' && method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(landingPageHtml);
        return;
    }

    if (pathname === '/chat' && method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(chatPageHtml);
        return;
    }

    // Health check
    if (pathname === '/health' && method === 'GET') {
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({
            status: "healthy",
            service: "ForTAI All-in-One"
        }));
        return;
    }

    // API - Start analysis
    if (pathname === '/api/analyze/url' && method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const data = JSON.parse(body);
                const jobId = generateJobId();

                jobs.set(jobId, {
                    id: jobId,
                    url: data.url,
                    status: 'processing',
                    created_at: new Date().toISOString()
                });

                // Analyze in background
                setTimeout(async () => {
                    try {
                        const result = await analyzeUrl(data.url);
                        jobs.set(jobId, {
                            ...jobs.get(jobId),
                            status: 'completed',
                            ...result,
                            completed_at: new Date().toISOString()
                        });
                    } catch (error) {
                        jobs.set(jobId, {
                            ...jobs.get(jobId),
                            status: 'failed',
                            error: error.message
                        });
                    }
                }, ANALYSIS_DELAY);

                res.writeHead(200, corsHeaders);
                res.end(JSON.stringify({ job_id: jobId, status: 'queued' }));
            } catch (error) {
                res.writeHead(400, corsHeaders);
                res.end(JSON.stringify({ error: 'Invalid JSON' }));
            }
        });
        return;
    }

    // API - Get results
    if (pathname.startsWith('/api/results/') && method === 'GET') {
        const jobId = pathname.split('/').pop();
        const job = jobs.get(jobId);

        if (!job) {
            res.writeHead(404, corsHeaders);
            res.end(JSON.stringify({ error: 'Job not found' }));
            return;
        }

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify(job));
        return;
    }

    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end('<h1>404 - Page Not Found</h1><p><a href="/">Go to ForTAI Home</a></p>');
});

server.listen(PORT, () => {
    console.log(`ForTAI All-in-One running on port ${PORT}`);
    console.log(`Landing page: http://localhost:${PORT}/`);
    console.log(`Chat page: http://localhost:${PORT}/chat`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));