const http = require('http');

const PORT = process.env.PORT || 3000;
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000';

const htmlContent = `<!DOCTYPE html>
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
    </style>
</head>
<body>
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
        const BACKEND_URL = '${BACKEND_URL}';
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
                const analyzeResponse = await fetch(\`\${BACKEND_URL}/api/analyze/url\`, {
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

                    const resultResponse = await fetch(\`\${BACKEND_URL}/api/results/\${jobId}\`);

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

                        let resultHtml = \`
                            <div style="margin: 15px 0;">
                                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                                    <span style="font-size: 1.5rem;">\${verdictIcons[result.verdict] || '❓'}</span>
                                    <span class="verdict \${result.verdict}">\${result.verdict}</span>
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
                addMessage(\`❌ Kunde inte analysera URL: \${error.message}. Kontrollera att backend-servern är tillgänglig.\`);
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

const server = http.createServer((req, res) => {
    res.writeHead(200, {
        'Content-Type': 'text/html',
        'Access-Control-Allow-Origin': '*'
    });
    res.end(htmlContent);
});

server.listen(PORT, () => {
    console.log(`ForTAI Simple Frontend running on port ${PORT}`);
    console.log(`Backend URL: ${BACKEND_URL}`);
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));