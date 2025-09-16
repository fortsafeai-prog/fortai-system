const http = require('http');
const url = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 8000;

// In-memory storage for jobs
const jobs = new Map();
const ANALYSIS_DELAY = 3000;

function generateJobId() {
    return crypto.randomUUID();
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

        const suspiciousKeywords = ['phishing', 'malicious', 'fake', 'scam'];
        for (const keyword of suspiciousKeywords) {
            if (targetUrl.toLowerCase().includes(keyword)) {
                riskScore += 25;
                evidence.push(`URL contains suspicious keyword: "${keyword}"`);
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
        }
    }

    const verdictMap = {
        "safe": "Säker",
        "suspicious": "Misstänkt",
        "dangerous": "Farlig"
    };

    const domain = targetUrl ? new URL(targetUrl).hostname : 'okänd domän';
    const swedishSummary = `Bedömning: ${verdictMap[verdict]}. Säkerhetsnivå: ${confidence}%. Domän: ${domain}. ${evidence[0] || 'Analys slutförd.'}`;

    return {
        verdict,
        confidence,
        evidence: evidence.slice(0, 3),
        swedish_summary: swedishSummary,
        artifacts: {
            screenshot_base64: null,
            page_title: `Analysis for ${domain}`,
            screenshot_success: false,
            note: "Cloud version - analysis without screenshots"
        }
    };
}

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

    // Health check
    if (pathname === '/health' && method === 'GET') {
        res.writeHead(200, corsHeaders);
        res.end(JSON.stringify({
            status: "healthy",
            service: "ForTAI Simple Backend"
        }));
        return;
    }

    // Start analysis
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

    // Get results
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

    res.writeHead(404, corsHeaders);
    res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => {
    console.log(`ForTAI Simple Backend running on port ${PORT}`);
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));