const http = require('http');
const url = require('url');
const crypto = require('crypto');

const PORT = 8000;

// In-memory storage for demo jobs
const jobs = new Map();

// Mock analysis pipeline delay
const ANALYSIS_DELAY = 3000; // 3 seconds

function generateJobId() {
    return crypto.randomUUID();
}

function mockAnalysisResult(url) {
    // Simple heuristic scoring for demo
    let riskScore = 0;
    const evidence = [];

    // Check URL patterns
    if (url.includes('phishing') || url.includes('malicious')) {
        riskScore += 60;
        evidence.push("URL contains suspicious keywords");
    }

    if (url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
        riskScore += 30;
        evidence.push("URL uses IP address instead of domain name");
    }

    if (url.length > 100) {
        riskScore += 20;
        evidence.push("Unusually long URL");
    }

    if (url.includes('bit.ly') || url.includes('tinyurl')) {
        riskScore += 25;
        evidence.push("Uses URL shortener service");
    }

    // Determine verdict
    let verdict, confidence;
    if (riskScore >= 60) {
        verdict = "dangerous";
        confidence = Math.min(95, 70 + riskScore);
        evidence.push("ML classifier detected high-risk patterns");
    } else if (riskScore >= 30) {
        verdict = "suspicious";
        confidence = Math.min(85, 60 + riskScore);
        evidence.push("Multiple risk indicators detected");
    } else {
        verdict = "safe";
        confidence = Math.min(90, 80 + (10 - riskScore));
        evidence.push("No significant risk indicators found");
        evidence.push("Valid domain structure");
        evidence.push("No suspicious redirects detected");
    }

    return {
        verdict,
        confidence: Math.round(confidence),
        evidence: evidence.slice(0, 4), // Limit to 4 evidence points
        artifacts: {
            screenshot_base64: generateMockScreenshot(),
            page_title: `Mock Analysis for ${new URL(url).hostname}`,
        },
        swedish_summary: generateSwedishSummary(verdict, confidence, evidence[0])
    };
}

function generateMockScreenshot() {
    // Generate a simple base64 encoded 1x1 pixel PNG (transparent)
    return "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==";
}

function generateSwedishSummary(verdict, confidence, evidence) {
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

    return `Bedömning: ${verdictMap[verdict]}. Säkerhetsnivå: ${confidence}%. ${evidence ? evidence + '. ' : ''}${actionMap[verdict]}`;
}

const server = http.createServer((req, res) => {
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

    // Health check endpoint
    if (pathname === '/health' && method === 'GET') {
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({ status: "healthy", service: "ForTAI Mock Backend" }));
        return;
    }

    // Start analysis endpoint
    if (pathname === '/api/analyze/url' && method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const jobId = generateJobId();

                // Create job
                jobs.set(jobId, {
                    id: jobId,
                    url: data.url,
                    status: 'processing',
                    created_at: new Date().toISOString()
                });

                // Simulate analysis after delay
                setTimeout(() => {
                    const result = mockAnalysisResult(data.url);
                    jobs.set(jobId, {
                        ...jobs.get(jobId),
                        status: 'completed',
                        ...result,
                        completed_at: new Date().toISOString()
                    });
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

    // Get results endpoint
    if (pathname.startsWith('/api/results/') && method === 'GET') {
        const jobId = pathname.split('/').pop();
        const job = jobs.get(jobId);

        if (!job) {
            res.writeHead(404, corsHeaders);
            res.end(JSON.stringify({ error: 'Job not found' }));
            return;
        }

        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({
            job_id: job.id,
            status: job.status,
            url: job.url,
            verdict: job.verdict,
            confidence: job.confidence,
            evidence: job.evidence,
            artifacts: job.artifacts,
            swedish_summary: job.swedish_summary,
            timestamp: job.completed_at || job.created_at
        }));
        return;
    }

    // API documentation redirect
    if (pathname === '/docs' && method === 'GET') {
        res.writeHead(200, { ...corsHeaders, 'Content-Type': 'text/html' });
        res.end(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>ForTAI Mock API Documentation</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .endpoint { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
                    code { background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
                </style>
            </head>
            <body>
                <h1>🛠️ ForTAI Mock API Documentation</h1>
                <p>This is a demonstration backend for ForTAI URL analysis.</p>

                <div class="endpoint">
                    <h3>POST /api/analyze/url</h3>
                    <p>Start URL analysis</p>
                    <code>{"url": "https://example.com"}</code>
                </div>

                <div class="endpoint">
                    <h3>GET /api/results/{job_id}</h3>
                    <p>Get analysis results</p>
                </div>

                <div class="endpoint">
                    <h3>GET /health</h3>
                    <p>Health check</p>
                </div>

                <p><strong>Note:</strong> This is a mock backend for demonstration. For full functionality, deploy with Docker Compose.</p>
                <p><a href="http://localhost:8080">← Back to ForTAI Website</a></p>
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
    console.log('='.repeat(60));
    console.log('🔧 ForTAI Mock Backend Server');
    console.log('='.repeat(60));
    console.log(`Mock backend running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`API docs: http://localhost:${PORT}/docs`);
    console.log('');
    console.log('📊 Mock API endpoints:');
    console.log('  - POST /api/analyze/url');
    console.log('  - GET /api/results/{job_id}');
    console.log('  - GET /health');
    console.log('  - GET /docs');
    console.log('');
    console.log('🎯 Features:');
    console.log('  - Simulated 3-second analysis delay');
    console.log('  - Heuristic URL risk scoring');
    console.log('  - Swedish language summaries');
    console.log('  - Mock screenshot artifacts');
    console.log('');
    console.log('Press Ctrl+C to stop');
    console.log('='.repeat(60));
});

process.on('SIGINT', () => {
    console.log('\n\n🛑 Mock backend stopped');
    process.exit(0);
});