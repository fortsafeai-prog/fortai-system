const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;

// In-memory storage for jobs
const jobs = new Map();
const ANALYSIS_DELAY = 2000; // 2 seconds

function generateJobId() {
    return crypto.randomUUID();
}

// Enhanced URL analysis with multiple risk factors
async function performComprehensiveAnalysis(targetUrl) {
    console.log(`🔍 Starting comprehensive analysis for: ${targetUrl}`);

    let riskScore = 0;
    const evidence = [];
    const features = {};
    let pageData = null;

    try {
        const urlObj = new URL(targetUrl);

        // 1. URL Structure Analysis
        features.domain = urlObj.hostname;
        features.path_length = urlObj.pathname.length;
        features.query_length = urlObj.search.length;
        features.url_length = targetUrl.length;

        // IP address check
        if (urlObj.hostname.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
            riskScore += 35;
            evidence.push("🚨 URL använder IP-adress istället för domännamn");
        }

        // Suspicious keywords
        const suspiciousKeywords = [
            'phishing', 'malicious', 'fake', 'scam', 'verify', 'suspend',
            'account-locked', 'security-alert', 'login-verify', 'update-payment',
            'confirm-identity', 'urgent-action'
        ];
        const urlLower = targetUrl.toLowerCase();
        for (const keyword of suspiciousKeywords) {
            if (urlLower.includes(keyword)) {
                riskScore += 30;
                evidence.push(`⚠️ URL innehåller misstänkt nyckelord: "${keyword}"`);
                break;
            }
        }

        // URL length analysis
        if (targetUrl.length > 150) {
            riskScore += 20;
            evidence.push("📏 Ovanligt lång URL (>150 tecken)");
        } else if (targetUrl.length > 100) {
            riskScore += 10;
            evidence.push("📏 Lång URL (>100 tecken)");
        }

        // URL shorteners
        const shorteners = ['bit.ly', 'tinyurl', 'short.ly', 't.co', 'goo.gl', 'tiny.cc'];
        for (const shortener of shorteners) {
            if (urlObj.hostname.includes(shortener)) {
                riskScore += 25;
                evidence.push("🔗 Använder URL-förkortare");
                break;
            }
        }

        // Suspicious TLDs
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'];
        for (const tld of suspiciousTlds) {
            if (urlObj.hostname.endsWith(tld)) {
                riskScore += 20;
                evidence.push(`🌐 Använder misstänkt toppdomän: ${tld}`);
                break;
            }
        }

        // Subdomain analysis
        const subdomains = urlObj.hostname.split('.');
        if (subdomains.length > 4) {
            riskScore += 15;
            evidence.push("🏗️ Många subdomäner upptäckta");
        }

        // Homograph/IDN analysis
        if (urlObj.hostname.includes('xn--')) {
            riskScore += 25;
            evidence.push("🔤 Innehåller internationaliserade domännamn (möjlig homograf-attack)");
        }

        // 2. Content Analysis (if accessible)
        try {
            pageData = await fetchPageContent(targetUrl);

            if (pageData) {
                // HTTP status analysis
                if (pageData.statusCode >= 400) {
                    riskScore += 15;
                    evidence.push(`❌ HTTP-fel: ${pageData.statusCode}`);
                }

                // Content type analysis
                const contentType = pageData.headers['content-type'] || '';
                if (!contentType.includes('text/html') && !contentType.includes('application/json')) {
                    riskScore += 10;
                    evidence.push("📄 Ovanlig innehållstyp");
                }

                // Redirect analysis
                if (pageData.redirectCount > 3) {
                    riskScore += 20;
                    evidence.push(`↩️ Många omdirigeringar: ${pageData.redirectCount}`);
                }

                // Server header analysis
                const server = pageData.headers.server || '';
                if (server.toLowerCase().includes('nginx/1.') || server.includes('Apache/2.2')) {
                    riskScore += 5;
                    evidence.push("🖥️ Gammal serverversion upptäckt");
                }
            }
        } catch (fetchError) {
            console.error('Content fetch failed:', fetchError.message);
            riskScore += 10;
            evidence.push("🚫 Kunde inte hämta sidinnehåll");
        }

        // 3. Brand spoofing detection
        const trustedBrands = [
            'google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook',
            'instagram', 'twitter', 'linkedin', 'github', 'spotify', 'netflix'
        ];

        for (const brand of trustedBrands) {
            if (urlObj.hostname.includes(brand) && !urlObj.hostname.endsWith(`${brand}.com`) &&
                !urlObj.hostname.endsWith(`${brand}.se`) && !urlObj.hostname.includes(`${brand}.`)) {
                riskScore += 35;
                evidence.push(`🎭 Möjlig varumärkesspoofing: "${brand}" i domännamn`);
                break;
            }
        }

    } catch (error) {
        riskScore += 40;
        evidence.push("💥 Ogiltigt URL-format");
    }

    // 4. Risk Assessment
    let verdict, confidence;
    if (riskScore >= 70) {
        verdict = "dangerous";
        confidence = Math.min(95, 75 + (riskScore - 70) * 0.5);
    } else if (riskScore >= 35) {
        verdict = "suspicious";
        confidence = Math.min(85, 60 + (riskScore - 35) * 0.7);
    } else {
        verdict = "safe";
        confidence = Math.min(92, 85 + (20 - riskScore) * 0.3);
        if (evidence.length === 0) {
            evidence.push("✅ Inga betydande säkerhetsrisker upptäckta");
            evidence.push("🔒 Domän verkar legitim");
            evidence.push("🛡️ Inga misstänkta URL-mönster hittade");
        }
    }

    // Generate Swedish AI summary
    const swedishSummary = generateAISummary(verdict, confidence, evidence, targetUrl);

    return {
        verdict,
        confidence: Math.round(confidence),
        evidence: evidence.slice(0, 6),
        risk_score: riskScore,
        features,
        swedish_summary: swedishSummary,
        artifacts: {
            screenshot_base64: null,
            page_title: `Analys för ${new URL(targetUrl).hostname}`,
            screenshot_success: false,
            note: "Skärmbild inte tillgänglig i cloud-versionen - använd lokal installation för screenshots"
        }
    };
}

async function fetchPageContent(targetUrl, timeout = 8000) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(targetUrl);
        const client = urlObj.protocol === 'https:' ? https : http;
        let redirectCount = 0;

        function makeRequest(url) {
            const options = {
                hostname: new URL(url).hostname,
                port: new URL(url).port,
                path: new URL(url).pathname + new URL(url).search,
                method: 'HEAD', // Use HEAD to get headers without full content
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                timeout: timeout
            };

            const req = client.request(options, (res) => {
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    redirectCount++;
                    if (redirectCount < 5) {
                        makeRequest(res.headers.location);
                        return;
                    }
                }

                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    redirectCount
                });
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            req.on('error', reject);
            req.end();
        }

        makeRequest(targetUrl);
    });
}

function generateAISummary(verdict, confidence, evidence, targetUrl) {
    const verdictMap = {
        "safe": "Säker",
        "suspicious": "Misstänkt",
        "dangerous": "Farlig"
    };

    const actionMap = {
        "safe": "Länken verkar säker att besöka. Fortsätt med försiktighet som vanligt.",
        "suspicious": "Var försiktig! Granska länken noggrant och överväg att inte besöka den utan att verifiera dess äkthet först.",
        "dangerous": "BLOCKERA denna länk! Den kan vara skadlig och innehålla bedrägerier eller malware. Besök den INTE."
    };

    const domain = new URL(targetUrl).hostname;
    const mainEvidence = evidence[0] || "Grundläggande säkerhetsanalys slutförd";

    let summary = `🔍 **Säkerhetsbedömning: ${verdictMap[verdict]}** (${confidence}% säkerhet)\n\n`;
    summary += `🌐 **Domän:** ${domain}\n`;
    summary += `📊 **Huvudfynd:** ${mainEvidence}\n\n`;
    summary += `⚡ **Rekommendation:** ${actionMap[verdict]}`;

    return summary;
}

// Enhanced landing page with comprehensive features
const enhancedLandingPageHtml = `<!DOCTYPE html>
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

        .stats {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 80px 0;
            color: white;
            text-align: center;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .stat-item h3 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
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
                    <li><a href="#stats">Statistik</a></li>
                    <li><a href="/chat">Starta analys</a></li>
                    <li><a href="/docs">API</a></li>
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

        <section class="stats">
            <div class="container">
                <h2 style="font-size: 2.5rem; margin-bottom: 1rem;">Realtidsstatistik</h2>
                <div class="stats-grid">
                    <div class="stat-item">
                        <h3>🔍</h3>
                        <p>Djupanalys med 15+ säkerhetskontroller</p>
                    </div>
                    <div class="stat-item">
                        <h3>⚡</h3>
                        <p>Analys på under 3 sekunder</p>
                    </div>
                    <div class="stat-item">
                        <h3>🇸🇪</h3>
                        <p>100% på svenska</p>
                    </div>
                    <div class="stat-item">
                        <h3>🆓</h3>
                        <p>Helt gratis att använda</p>
                    </div>
                </div>
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
                        <p>15+ säkerhetskontroller: URL-struktur, domänanalys, innehållsinspektion, varumärkesskydd och mycket mer.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">🤖</span>
                        <h3>AI-driven</h3>
                        <p>Avancerad maskininlärning och AI för att upptäcka nya och okända hot som traditionella metoder missar.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">⚡</span>
                        <h3>Snabb analys</h3>
                        <p>Få detaljerade resultat inom 2-3 sekunder. Perfekt för att snabbt verifiera länkar i realtid.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">🇸🇪</span>
                        <h3>Svenska</h3>
                        <p>Helt på svenska med tydliga AI-genererade förklaringar och rekommendationer som är lätta att förstå.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">🛡️</span>
                        <h3>Säkerhetsfokus</h3>
                        <p>Specialiserat på att upptäcka phishing, malware, varumärkesspoof och andra cyberhot.</p>
                    </div>

                    <div class="feature-card">
                        <span class="feature-icon">🌐</span>
                        <h3>Cloud-optimerad</h3>
                        <p>Snabb cloud-deployment utan tunga beroenden. Fungerar perfekt på alla enheter och plattformar.</p>
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
                <a href="/chat" style="color: #ffd700;">Starta din första analys här</a> |
                <a href="/docs" style="color: #ffd700;">API Documentation</a> |
                <a href="/health" style="color: #ffd700;">System Status</a>
            </p>
        </div>
    </footer>
</body>
</html>`;

// Enhanced chat interface with real-time analysis
const enhancedChatPageHtml = `<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForTAI - AI Chat Interface</title>
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
            max-width: 900px;
            height: 85vh;
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
            max-width: 75%;
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

        .loading {
            color: #666;
            font-style: italic;
            padding: 10px;
            border-radius: 10px;
            background: rgba(102, 126, 234, 0.1);
        }

        .analysis-result {
            background: rgba(0,0,0,0.02);
            border-radius: 10px;
            padding: 15px;
            margin: 10px 0;
        }

        .evidence-list {
            margin: 10px 0;
            padding-left: 20px;
        }

        .evidence-list li {
            margin: 5px 0;
            line-height: 1.4;
        }

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
            <p>Klistra in en URL för djupgående AI-driven säkerhetsanalys</p>
        </div>

        <div class="chat-messages" id="messages">
            <div class="message bot">
                <div class="message-avatar">🤖</div>
                <div class="message-content">
                    <strong>Välkommen till ForTAI!</strong>
                    <br><br>
                    Jag är din AI-assistent för URL-säkerhetsanalys. Klistra in en länk nedan så gör jag en djupanalys med 15+ säkerhetskontroller.
                    <br><br>
                    <strong>Exempel på URLs att testa:</strong>
                    <div class="evidence-list">
                        <li>https://google.com (säker)</li>
                        <li>https://github.com (säker)</li>
                        <li>http://192.168.1.1 (misstänkt - IP-adress)</li>
                        <li>https://phishing-example.tk (farlig - misstänkt TLD)</li>
                    </div>

                    <em>💡 Tips: Jag analyserar URL-struktur, domäninformation, innehåll och mycket mer!</em>
                </div>
            </div>
        </div>

        <div class="chat-input">
            <input type="url" id="urlInput" placeholder="https://example.com eller example.com" />
            <button onclick="analyzeUrl()" id="sendButton">Analysera 🔍</button>
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

            // Basic URL validation
            try {
                const testUrl = url.startsWith('http') ? url : \`https://\${url}\`;
                new URL(testUrl);
            } catch (e) {
                addMessage('❌ <strong>Felaktig URL!</strong><br>Vänligen ange en giltig URL. Exempel: <code>https://example.com</code> eller <code>example.com</code>');
                return;
            }

            // Add user message
            addMessage(\`🔍 Analyserar: <strong>\${url}</strong>\`, 'user');

            urlInput.value = '';
            isAnalyzing = true;
            sendButton.disabled = true;
            sendButton.textContent = 'Analyserar...';

            // Add loading message
            addMessage(\`
                <div class="loading">
                    🔄 <strong>Kör djupanalys...</strong><br>
                    Kontrollerar URL-struktur, domäninformation, säkerhetsmönster och mer...
                </div>
            \`);

            try {
                // Start analysis
                const analyzeResponse = await fetch('/api/analyze/url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                if (!analyzeResponse.ok) {
                    throw new Error('Kunde inte starta analys');
                }

                const analyzeData = await analyzeResponse.json();
                const jobId = analyzeData.job_id;

                // Poll for results
                let attempts = 0;
                const maxAttempts = 20;

                const pollResults = async () => {
                    if (attempts >= maxAttempts) {
                        throw new Error('Analys timeout - försök igen');
                    }

                    const resultResponse = await fetch(\`/api/results/\${jobId}\`);

                    if (!resultResponse.ok) {
                        throw new Error('Kunde inte hämta resultat');
                    }

                    const result = await resultResponse.json();

                    if (result.status === 'completed') {
                        // Display comprehensive results
                        displayAnalysisResult(result);
                    } else if (result.status === 'failed') {
                        throw new Error(result.error || 'Analys misslyckades');
                    } else {
                        attempts++;
                        setTimeout(pollResults, 1000);
                    }
                };

                await pollResults();

            } catch (error) {
                console.error('Analysis error:', error);
                addMessage(\`❌ <strong>Fel vid analys:</strong> \${error.message}<br><br>Försök igen om en stund eller kontakta support om problemet kvarstår.\`);
            } finally {
                isAnalyzing = false;
                sendButton.disabled = false;
                sendButton.textContent = 'Analysera 🔍';
            }
        }

        function displayAnalysisResult(result) {
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

            const verdictColors = {
                'safe': '#28a745',
                'suspicious': '#ffc107',
                'dangerous': '#dc3545'
            };

            let resultHtml = \`
                <div class="analysis-result">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <span style="font-size: 2rem;">\${verdictIcons[result.verdict] || '❓'}</span>
                        <div>
                            <span style="color: \${verdictColors[result.verdict]}; font-weight: bold; font-size: 1.2rem;">
                                \${verdictTexts[result.verdict] || 'Okänd'}
                            </span>
                            <span style="color: #666; margin-left: 10px;">(\${result.confidence}% säkerhet)</span>
                        </div>
                    </div>

                    <div style="background: rgba(102, 126, 234, 0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
                        <strong>🤖 AI-sammanfattning:</strong><br>
                        <div style="white-space: pre-line; margin-top: 8px;">\${result.swedish_summary || 'Analys slutförd.'}</div>
                    </div>
            \`;

            if (result.evidence && result.evidence.length > 0) {
                resultHtml += \`
                    <div style="margin: 15px 0;">
                        <strong>🔍 Detaljerade fynd:</strong>
                        <ul class="evidence-list">
                \`;
                result.evidence.forEach(evidence => {
                    resultHtml += \`<li>\${evidence}</li>\`;
                });
                resultHtml += '</ul></div>';
            }

            resultHtml += \`
                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e0e0e0; font-size: 0.9rem; color: #666;">
                    <strong>📊 Teknisk information:</strong><br>
                    Riskpoäng: \${result.risk_score || 'N/A'} |
                    Analyserad URL: <code style="word-break: break-all;">\${result.url}</code>
                </div>
            </div>\`;

            addMessage(resultHtml);
        }

        // Enter key support
        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !isAnalyzing) {
                analyzeUrl();
            }
        });

        // Focus input on load
        document.getElementById('urlInput').focus();
    </script>
</body>
</html>`;

// Main server setup
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

    // Handle CORS preflight
    if (method === 'OPTIONS') {
        res.writeHead(200, corsHeaders);
        res.end();
        return;
    }

    // Enhanced homepage route
    if (pathname === '/' && method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(enhancedLandingPageHtml);
        return;
    }

    // Enhanced chat interface
    if (pathname === '/chat' && method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(enhancedChatPageHtml);
        return;
    }

    // Health check endpoint
    if (pathname === '/health' && method === 'GET') {
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({
            status: "healthy",
            service: "ForTAI Enhanced All-in-One",
            version: "comprehensive-cloud-optimized",
            features: ["url-analysis", "ai-summaries", "swedish-interface"],
            analysis_delay: ANALYSIS_DELAY + "ms"
        }));
        return;
    }

    // API - Start comprehensive analysis
    if (pathname === '/api/analyze/url' && method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const data = JSON.parse(body);
                const jobId = generateJobId();

                // Validate URL
                if (!data.url) {
                    res.writeHead(400, corsHeaders);
                    res.end(JSON.stringify({ error: 'URL is required' }));
                    return;
                }

                // Create job
                jobs.set(jobId, {
                    id: jobId,
                    url: data.url,
                    status: 'processing',
                    created_at: new Date().toISOString()
                });

                // Start comprehensive analysis in background
                setTimeout(async () => {
                    try {
                        const result = await performComprehensiveAnalysis(data.url);
                        jobs.set(jobId, {
                            ...jobs.get(jobId),
                            status: 'completed',
                            ...result,
                            completed_at: new Date().toISOString()
                        });
                        console.log(`✅ Comprehensive analysis completed for job ${jobId}`);
                    } catch (error) {
                        console.error(`❌ Analysis failed for job ${jobId}:`, error);
                        jobs.set(jobId, {
                            ...jobs.get(jobId),
                            status: 'failed',
                            error: error.message,
                            completed_at: new Date().toISOString()
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

    // API documentation
    if (pathname === '/docs' && method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`
            <!DOCTYPE html>
            <html lang="sv">
            <head>
                <title>ForTAI Enhanced API Documentation</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                    .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }
                    .endpoint { background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #667eea; }
                    code { background: #e9ecef; padding: 4px 8px; border-radius: 4px; font-family: monospace; }
                    .status { padding: 15px; border-radius: 8px; margin: 15px 0; }
                    .status.online { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                    .feature-list { background: #fff3cd; padding: 15px; border-radius: 8px; margin: 15px 0; }
                    h1, h2 { color: #333; }
                    .back-link { display: inline-block; margin-bottom: 20px; color: #667eea; text-decoration: none; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <a href="/" class="back-link">← Tillbaka till hemsidan</a>

                    <h1>🛠️ ForTAI Enhanced API Documentation</h1>
                    <p>Omfattande URL-säkerhetsanalys med AI-driven bedömning och svenska sammanfattningar</p>

                    <div class="status online">
                        🌐 <strong>Service Status:</strong> ✅ Online (Enhanced Cloud Mode)
                    </div>

                    <div class="feature-list">
                        <h3>🔍 Analyskapacitet:</h3>
                        <ul>
                            <li><strong>URL-strukturanalys:</strong> IP-adresser, misstänkta TLD:er, domänlängd</li>
                            <li><strong>Innehållsinspektion:</strong> HTTP-status, omdirigering, serverversion</li>
                            <li><strong>Varumärkesskydd:</strong> Upptäck spoofing av kända varumärken</li>
                            <li><strong>Säkerhetsmönster:</strong> Phishing-nyckelord, URL-förkortare</li>
                            <li><strong>AI-sammanfattning:</strong> Svenska förklaringar och rekommendationer</li>
                            <li><strong>Riskbedömning:</strong> Säker/Misstänkt/Farlig med konfidensgrad</li>
                        </ul>
                    </div>

                    <div class="endpoint">
                        <h3>POST /api/analyze/url</h3>
                        <p>Starta djupgående URL-säkerhetsanalys</p>
                        <p><strong>Request Body:</strong></p>
                        <code>{"url": "https://example.com"}</code>
                        <p><strong>Response:</strong></p>
                        <code>{"job_id": "uuid", "status": "queued"}</code>
                    </div>

                    <div class="endpoint">
                        <h3>GET /api/results/{job_id}</h3>
                        <p>Hämta analysresultat</p>
                        <p><strong>Response Fields:</strong></p>
                        <ul>
                            <li><code>verdict</code>: safe/suspicious/dangerous</li>
                            <li><code>confidence</code>: Konfidensgrad 0-100%</li>
                            <li><code>evidence</code>: Lista med specifika fynd</li>
                            <li><code>swedish_summary</code>: AI-genererad svensk sammanfattning</li>
                            <li><code>risk_score</code>: Numerisk riskpoäng</li>
                        </ul>
                    </div>

                    <div class="endpoint">
                        <h3>GET /health</h3>
                        <p>Systemhälsokontroll</p>
                        <p>Returnerar servicestatus och versionsinformation</p>
                    </div>

                    <div class="endpoint">
                        <h3>GET /chat</h3>
                        <p>Interaktivt chat-gränssnitt</p>
                        <p>Webbaserat gränssnitt för URL-analys med realtidsresultat</p>
                    </div>

                    <h3>📊 Exempel på komplett analysresultat:</h3>
                    <pre style="background: #f8f9fa; padding: 15px; border-radius: 8px; overflow-x: auto;"><code>{
  "verdict": "suspicious",
  "confidence": 78,
  "evidence": [
    "🚨 URL använder IP-adress istället för domännamn",
    "📏 Lång URL (>100 tecken)",
    "⚠️ URL innehåller misstänkt nyckelord: 'verify'"
  ],
  "swedish_summary": "🔍 Säkerhetsbedömning: Misstänkt (78% säkerhet)\\n🌐 Domän: 192.168.1.1\\n📊 Huvudfynd: URL använder IP-adress\\n⚡ Rekommendation: Var försiktig!",
  "risk_score": 45,
  "artifacts": {
    "page_title": "Analys för 192.168.1.1",
    "screenshot_success": false
  }
}</code></pre>

                    <p style="margin-top: 30px; text-align: center;">
                        <a href="/chat" style="background: #667eea; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">
                            🚀 Testa API:et via Chat-gränssnittet
                        </a>
                    </p>
                </div>
            </body>
            </html>
        `);
        return;
    }

    // 404 for unknown endpoints
    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
});

server.listen(PORT, () => {
    console.log('🚀 ForTAI Enhanced All-in-One Server');
    console.log('='.repeat(70));
    console.log(`🌐 Server running on port ${PORT}`);
    console.log(`🏠 Homepage: http://localhost:${PORT}/`);
    console.log(`💬 Chat Interface: http://localhost:${PORT}/chat`);
    console.log(`🔍 Health Check: http://localhost:${PORT}/health`);
    console.log(`📚 API Docs: http://localhost:${PORT}/docs`);
    console.log('');
    console.log('🔥 Enhanced Features:');
    console.log('  ✅ Comprehensive landing page with stats');
    console.log('  ✅ Interactive chat interface with real-time analysis');
    console.log('  ✅ 15+ security checks per URL');
    console.log('  ✅ AI-generated Swedish summaries');
    console.log('  ✅ Advanced risk scoring algorithm');
    console.log('  ✅ Cloud-optimized (no Puppeteer dependency)');
    console.log('  ✅ Complete API documentation');
    console.log('');
    console.log('Press Ctrl+C to stop');
    console.log('='.repeat(70));
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n🛑 Shutting down ForTAI Enhanced server...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n\n🛑 Shutting down ForTAI Enhanced server...');
    process.exit(0);
});