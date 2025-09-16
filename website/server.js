const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 8080;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000';

// MIME types
const mimeTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'text/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon'
};

function serveFile(filePath, res) {
    const ext = path.extname(filePath);
    const contentType = mimeTypes[ext] || 'text/plain';

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/html' });
            res.end('<h1>404 - File Not Found</h1>');
            return;
        }

        // Replace localhost URLs in HTML files with deployed URLs
        if (ext === '.html') {
            data = data.replace(/http:\/\/localhost:3000/g, FRONTEND_URL);
            data = data.replace(/http:\/\/localhost:8000/g, BACKEND_URL);
        }

        res.writeHead(200, {
            'Content-Type': contentType,
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        });
        res.end(data);
    });
}

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    let pathname = parsedUrl.pathname;

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(200, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        });
        res.end();
        return;
    }

    // Default to index.html
    if (pathname === '/' || pathname === '') {
        pathname = '/index.html';
    }

    // Handle status endpoint
    if (pathname === '/status') {
        const status = {
            website: "online",
            timestamp: new Date().toISOString(),
            version: "1.0.0",
            services: {
                frontend: FRONTEND_URL,
                backend: BACKEND_URL,
                docs: `${BACKEND_URL}/docs`,
                minio: "http://localhost:9001"
            }
        };

        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        });
        res.end(JSON.stringify(status, null, 2));
        return;
    }

    // Serve file
    const filePath = path.join(__dirname, pathname);
    serveFile(filePath, res);
});

server.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('🚀 ForTAI Landing Website Server');
    console.log('='.repeat(60));
    console.log(`Starting server on port ${PORT}...`);
    console.log(`Website URL: http://localhost:${PORT}`);
    console.log(`Status API: http://localhost:${PORT}/status`);
    console.log('');
    console.log('This website connects to:');
    console.log('  - Frontend (Chat UI): http://localhost:3000');
    console.log('  - Backend API: http://localhost:8000');
    console.log('  - API Documentation: http://localhost:8000/docs');
    console.log('  - MinIO Console: http://localhost:9001');
    console.log('');
    console.log('Press Ctrl+C to stop the server');
    console.log('='.repeat(60));
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n🛑 Server stopped by user');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n\n🛑 Server stopped');
    process.exit(0);
});