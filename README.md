# ForTAI - URL Analysis MVP

En webbaserad MVP för avancerad länkanalys med AI-driven säkerhetsbedömning.

## Funktioner

- **Automatisk URL-analys**: Djupgående granskning av länkar med AI
- **Säkerhetsbedömning**: Klassificering som säker/misstänkt/farlig
- **Evidensrapporter**: Detaljerade bevispunkter för varje analys
- **Chat-liknande UI**: Intuitiv användarupplevelse
- **Real-time progress**: Live-uppdateringar under analys

## Arkitektur

- **Frontend**: React + Vite med chat UI
- **Backend**: FastAPI med async processing
- **Database**: PostgreSQL för jobbdata
- **Worker**: Celery för bakgrundsanalys
- **Storage**: MinIO för artifacts
- **AI**: OpenAI GPT för svenska sammanfattningar

## Analysprocess

1. **URL normalisering** - Validering och säkerhetskontroller
2. **DNS & WHOIS** - Domäninformation och ålder
3. **TLS-certifikat** - Verifiering och validitet
4. **HTTP-analys** - Headers och omdirigeringskedjor
5. **Token-analys** - Upptäckt av misstänkta mönster
6. **Rykteskontroll** - Kontroll mot kända hot-databaser
7. **Innehållsanalys** - Granskning av HTML-struktur
8. **Screenshot-analys** - Dynamisk rendering med Playwright
9. **ML-klassificering** - Avancerad riskbedömning med Random Forest
10. **LLM-summering** - Svensk sammanfattning av resultat

## Installation

### Förutsättningar

- Docker och Docker Compose
- Node.js 18+ (för lokal utveckling)
- Python 3.11+ (för lokal utveckling)

### Snabbstart

1. **Klona projektet**:
   ```bash
   git clone <repository-url>
   cd ForTAI.1
   ```

2. **Starta med Docker Compose**:
   ```bash
   docker-compose up --build
   ```

3. **Öppna webbläsaren**:
   - Frontend: http://localhost:3000
   - API: http://localhost:8000
   - MinIO Console: http://localhost:9001

### Miljövariabler

Skapa en `.env`-fil i `backend/` mappen:

```env
DATABASE_URL=postgresql://fortai_user:fortai_pass@db:5432/fortai_db
REDIS_URL=redis://redis:6379
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=fortai_access
MINIO_SECRET_KEY=fortai_secret123
OPENAI_API_KEY=your_openai_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
PHISHTANK_API_KEY=your_phishtank_api_key_here
```

## API Endpoints

### Starta analys
```http
POST /api/analyze/url
Content-Type: application/json

{
  "url": "https://example.com",
  "user_id": "optional-user-id"
}
```

### Hämta resultat
```http
GET /api/results/{job_id}
```

### Hämta artifacts
```http
GET /api/artifacts/{artifact_id}
```

## Utveckling

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Worker

```bash
cd backend
celery -A app.worker worker --loglevel=info
```

## Säkerhet

- **Sandboxing**: All extern fetch körs i isolerade containers
- **Timeouts**: Begränsade tider för alla nätverksoperationer
- **Input validation**: Rigorös validering av alla URL:er
- **Error handling**: Graceful hantering av alla fel

## Testning

### Exempel-URL:er för testning

**Säkra:**
- https://www.google.com
- https://github.com
- https://www.wikipedia.org

**Misstänkta/farliga (för test):**
- URL:er med IP-adresser
- Långa omdirigeringskedjor
- Nyregistrerade domäner

## Prestandamål

- Analystid: < 10 sekunder genomsnitt
- Precision: > 85% på phishing-uppsättning
- Låg falskt positiv-rate i pilot

## Roadmap

### Fas 1 (MVP) ✅
- [x] Grundläggande URL-analys
- [x] Chat UI med svensk språkstöd
- [x] ML-baserad riskmotör med RandomForest
- [x] Docker-setup med alla tjänster
- [x] Screenshot-analys med Playwright
- [x] LLM-integration för svenska sammanfattningar
- [x] WebSocket för real-time progress
- [x] Komplett analyskedja (DNS, TLS, HTTP, innehåll)

### Fas 2 (Förbättringar)
- [ ] Förbättrad ML-klassificerare med träningsdata
- [ ] PDF/CSV export funktionalitet
- [ ] Förbättrad artifact viewer
- [ ] VirusTotal och PhishTank integration
- [ ] Avancerad innehållsanalys

### Fas 3 (Pilotfas)
- [ ] Pilot med 3-5 företag
- [ ] Datasamling och förbättring
- [ ] Performance-optimering
- [ ] GDPR-compliance

## Licensiering

Detta projekt är utvecklat för ForTAI som en MVP för länkanalys.

## Support

För teknisk support eller frågor, kontakta utvecklingsteamet.