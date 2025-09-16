# ForTAI MVP - Technical Specification

## Architecture Overview

The ForTAI MVP is built as a microservices architecture using Docker containers, designed for scalability and security.

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend │    │  FastAPI Backend│    │  Worker Process │
│   (Port 3000)   │◄──►│   (Port 8000)   │◄──►│   (Background)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Data Layer    │
                    │                 │
                    │ PostgreSQL:5432 │
                    │ Redis:6379      │
                    │ MinIO:9000      │
                    └─────────────────┘
```

## Backend Architecture

### Core Services

1. **URL Analyzer Service** (`app/services/url_analyzer.py`)
   - Main orchestrator for the analysis pipeline
   - Coordinates all analysis steps
   - Handles error recovery and fallbacks

2. **Screenshot Service** (`app/services/screenshot_service.py`)
   - Uses Playwright for dynamic page rendering
   - Captures full-page screenshots
   - Analyzes DOM structure and forms
   - Sandboxed execution for security

3. **ML Classifier** (`app/services/ml_classifier.py`)
   - Random Forest classifier for phishing detection
   - Feature extraction from URL and content
   - Text analysis for phishing keywords
   - Fallback rule-based classification

4. **LLM Summarizer** (`app/services/llm_summarizer.py`)
   - OpenAI GPT integration for Swedish summaries
   - Fallback summary generation
   - Context-aware explanations

### Analysis Pipeline

#### Step 1: URL Normalization
```python
def _normalize_and_check_url(url: str) -> Tuple[str, Dict]:
    # Add https if missing
    # Parse and validate URL structure
    # Check for punycode and homographs
    # Extract basic features
```

#### Step 2: DNS & WHOIS Analysis
```python
async def _dns_and_whois_lookup(url: str) -> Dict:
    # DNS A/AAAA record lookup
    # Domain age calculation
    # Registrar information
    # Privacy protection detection
```

#### Step 3: TLS Certificate Analysis
```python
async def _tls_cert_analysis(url: str) -> Dict:
    # Certificate validity check
    # Issuer verification
    # Hostname matching
    # Self-signed detection
```

#### Step 4: HTTP Analysis
```python
async def _http_fetch_and_redirects(url: str) -> Dict:
    # Follow redirect chains (max 5)
    # Capture HTTP headers
    # Extract HTML content
    # Record response times
```

#### Step 5: Token Analysis
```python
async def _url_token_analysis(url: str) -> Dict:
    # Suspicious keyword detection
    # Base64 blob identification
    # Long token patterns
    # Banking/service impersonation
```

#### Step 6: Reputation Checks
```python
async def _reputation_checks(url: str) -> Dict:
    # PhishTank lookup (if API key available)
    # VirusTotal lookup (if API key available)
    # Local blocklist checking
    # Crowdsourced feeds integration
```

#### Step 7: Content Analysis
```python
async def _content_analysis(html: str) -> Dict:
    # Form detection and analysis
    # External resource enumeration
    # Meta tag extraction
    # Inline script analysis
```

#### Step 8: Screenshot Analysis
```python
async def _dynamic_screenshot_analysis(url: str, job_id: str) -> Dict:
    # Playwright page rendering
    # Full-page screenshot capture
    # Form action analysis
    # External script detection
    # Network request monitoring
```

#### Step 9: ML Classification
```python
def classify(url: str, analysis_data: Dict) -> Dict:
    # Feature vector creation (15 URL features)
    # Text content analysis
    # Random Forest prediction
    # Confidence calculation
```

#### Step 10: Risk Assessment
```python
async def _compile_risk_assessment(analysis_result: Dict) -> Dict:
    # ML score (60% weight)
    # Heuristic rules (40% weight)
    # Evidence compilation
    # Verdict determination
```

## Security Features

### Sandboxing
- Playwright runs in isolated Docker container
- No access to host filesystem
- Restricted network access
- CPU and memory limits enforced

### Input Validation
```python
# URL validation regex
URL_PATTERN = re.compile(
    r'^https?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
    r'localhost|'  # localhost
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
```

### Timeouts and Limits
- Page load timeout: 10 seconds
- HTTP request timeout: 30 seconds
- Screenshot size limit: 5MB
- HTML content limit: 10KB for storage

## Database Schema

### AnalysisJob Table
```sql
CREATE TABLE analysis_jobs (
    id VARCHAR PRIMARY KEY,
    url TEXT NOT NULL,
    user_id VARCHAR,
    status VARCHAR DEFAULT 'queued',
    verdict VARCHAR,
    confidence FLOAT,
    evidence JSON,
    artifacts JSON,
    analysis_data JSON,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);
```

## API Specification

### POST /api/analyze/url
**Request:**
```json
{
    "url": "https://example.com",
    "user_id": "optional-user-id"
}
```

**Response:**
```json
{
    "job_id": "uuid-string",
    "status": "queued"
}
```

### GET /api/results/{job_id}
**Response:**
```json
{
    "job_id": "uuid-string",
    "status": "completed",
    "url": "https://example.com",
    "verdict": "safe|suspicious|dangerous",
    "confidence": 87.5,
    "evidence": [
        "ML classifier confidence: 85%",
        "Valid TLS certificate",
        "No suspicious redirects"
    ],
    "artifacts": {
        "screenshot_base64": "data:image/png;base64,...",
        "page_title": "Example Site"
    },
    "swedish_summary": "Bedömning: Säker. Säkerhetsnivå: 88%...",
    "timestamp": "2025-09-16T12:34:56Z"
}
```

## ML Model Features

### URL Features (15 total)
1. URL length
2. Domain length
3. Path length
4. Query parameter length
5. Number of dots
6. Number of hyphens
7. Number of underscores
8. Number of slashes
9. Is IP address (boolean)
10. Has many subdomains (boolean)
11. Uses URL shortener (boolean)
12. Contains IP in path (boolean)
13. Domain age in days
14. Redirect count
15. Has login form (boolean)

### Text Features
- TF-IDF vectorization of page content
- Phishing keyword scoring
- Brand impersonation detection

### Scoring Algorithm
```
final_score = (ml_phishing_score * 0.6) + (heuristic_score * 0.4)

if final_score >= 0.7: verdict = "dangerous"
elif final_score >= 0.4: verdict = "suspicious"
else: verdict = "safe"
```

## Frontend Architecture

### Components
- `LandingPage.jsx` - Initial welcome screen
- `ChatInterface.jsx` - Main chat UI with URL input
- `AnalysisResult.jsx` - Results display with screenshot
- `ProgressIndicator.jsx` - Real-time analysis progress

### State Management
- React hooks for local state
- Socket.IO for real-time updates
- Axios for API communication

### Features
- Swedish language interface
- Base64 screenshot display
- Evidence list presentation
- Responsive design

## Deployment Configuration

### Docker Compose Services
- **api**: FastAPI backend (port 8000)
- **worker**: Background analysis worker
- **frontend**: React development server (port 3000)
- **db**: PostgreSQL database (port 5432)
- **redis**: Redis cache (port 6379)
- **minio**: S3-compatible storage (ports 9000, 9001)

### Environment Variables
```bash
DATABASE_URL=postgresql://fortai_user:fortai_pass@db:5432/fortai_db
REDIS_URL=redis://redis:6379
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=fortai_access
MINIO_SECRET_KEY=fortai_secret123
OPENAI_API_KEY=optional_openai_key
VIRUSTOTAL_API_KEY=optional_vt_key
PHISHTANK_API_KEY=optional_pt_key
```

## Performance Targets

- **Analysis time**: < 10 seconds average
- **Throughput**: 10+ concurrent analyses
- **Accuracy**: > 85% precision on phishing dataset
- **Availability**: 99.9% uptime target

## Error Handling

### Graceful Degradation
- Screenshot failure → Continue with static analysis
- ML failure → Fall back to heuristic rules
- LLM failure → Use template-based summary
- External API failure → Continue without reputation data

### Logging
```python
logger.error(f"Screenshot analysis failed for {url}: {e}")
logger.warning(f"Page load timeout for {url}")
logger.info(f"Analysis completed for {job_id} in {duration}s")
```

## Future Enhancements

1. **Improved ML Model**
   - Train on larger phishing datasets
   - Deep learning models (BERT for text)
   - Ensemble methods

2. **Advanced Features**
   - PDF report generation
   - Bulk URL analysis
   - API rate limiting
   - User authentication

3. **Monitoring**
   - Prometheus metrics
   - Grafana dashboards
   - Alerting on failures

This technical specification provides the foundation for the ForTAI MVP implementation.