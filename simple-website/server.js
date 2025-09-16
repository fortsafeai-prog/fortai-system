const http = require('http');

const PORT = process.env.PORT || 8080;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

const htmlContent = `<!DOCTYPE html>
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
                <a href="#" class="logo">🛡️ ForTAI</a>
                <ul class="nav-links">
                    <li><a href="#features">Funktioner</a></li>
                    <li><a href="${FRONTEND_URL}" target="_blank">Starta analys</a></li>
                </ul>
            </div>
        </div>
    </header>

    <main>
        <section class="hero">
            <div class="container">
                <h1>AI-driven URL Säkerhetsanalys</h1>
                <p>Avancerad säkerhetsanalys av webbsidor med artificiell intelligens. Upptäck phishing, malware och andra hot innan de når dig.</p>
                <a href="${FRONTEND_URL}" target="_blank" class="cta-button">
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
                    <a href="${FRONTEND_URL}" target="_blank" class="cta-button">
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
                <a href="${FRONTEND_URL}" target="_blank" style="color: #ffd700;">Starta din första analys här</a>
            </p>
        </div>
    </footer>
</body>
</html>`;

const server = http.createServer((req, res) => {
    res.writeHead(200, {
        'Content-Type': 'text/html',
        'Access-Control-Allow-Origin': '*'
    });
    res.end(htmlContent);
});

server.listen(PORT, () => {
    console.log(`ForTAI Simple Website running on port ${PORT}`);
    console.log(`Frontend URL: ${FRONTEND_URL}`);
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));