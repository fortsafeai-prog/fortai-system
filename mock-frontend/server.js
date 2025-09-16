const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000';

const server = http.createServer((req, res) => {
    // Serve index.html for all requests
    const filePath = path.join(__dirname, 'index.html');

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Server Error');
            return;
        }

        // Inject backend URL into the HTML
        const htmlWithBackendUrl = data.replace(
            '<head>',
            `<head><script>window.BACKEND_URL = '${BACKEND_URL}';</script>`
        );

        res.writeHead(200, {
            'Content-Type': 'text/html',
            'Access-Control-Allow-Origin': '*'
        });
        res.end(htmlWithBackendUrl);
    });
});

server.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('💬 ForTAI Mock Frontend Server');
    console.log('='.repeat(60));
    console.log(`Mock frontend running on port ${PORT}`);
    console.log(`Chat Interface: http://localhost:${PORT}`);
    console.log('');
    console.log('🎯 Features:');
    console.log('  - Chat-based URL analysis interface');
    console.log('  - Real-time analysis progress');
    console.log('  - Swedish language interface');
    console.log('  - Screenshot display');
    console.log('  - Evidence presentation');
    console.log('');
    console.log('Press Ctrl+C to stop');
    console.log('='.repeat(60));
});

process.on('SIGINT', () => {
    console.log('\n\n🛑 Mock frontend stopped');
    process.exit(0);
});