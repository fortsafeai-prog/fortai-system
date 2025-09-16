# ForTAI Deployment Guide

This guide shows you how to deploy and access the complete ForTAI system.

## 🌐 Quick Start - Landing Website

### Option 1: Windows
```bash
# Double-click the file or run in command prompt:
start-website.bat
```

### Option 2: Linux/Mac
```bash
chmod +x start-website.sh
./start-website.sh
```

### Option 3: Manual Python
```bash
cd website
python server.py
```

**Access the website at: http://localhost:8080**

## 🐳 Full System Deployment (Docker)

### Prerequisites
- Docker and Docker Compose installed
- 8GB+ RAM recommended
- Ports 3000, 8000, 8080, 5432, 6379, 9000, 9001 available

### 1. Start the Complete System
```bash
# Make startup script executable
chmod +x start.sh

# Start all services
./start.sh
```

### 2. Access Points

| Service | URL | Description |
|---------|-----|-------------|
| **Landing Website** | http://localhost:8080 | Main entry point with links to all services |
| **Chat Interface** | http://localhost:3000 | React frontend for URL analysis |
| **Backend API** | http://localhost:8000 | FastAPI server |
| **API Documentation** | http://localhost:8000/docs | Interactive Swagger docs |
| **MinIO Console** | http://localhost:9001 | File storage management |

### 3. Verify Services
```bash
# Check all services are running
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 🔧 Configuration

### Environment Variables
Create `backend/.env` file:
```env
# Database
DATABASE_URL=postgresql://fortai_user:fortai_pass@db:5432/fortai_db

# Redis
REDIS_URL=redis://redis:6379

# MinIO
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=fortai_access
MINIO_SECRET_KEY=fortai_secret123

# Optional API Keys (for enhanced analysis)
OPENAI_API_KEY=your_openai_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
PHISHTANK_API_KEY=your_phishtank_api_key_here
```

## 🧪 Testing the System

### 1. Using the Landing Website
1. Open http://localhost:8080
2. Click "Starta Analys" or use the demo section
3. Enter a URL to test
4. View results in the chat interface

### 2. Direct API Testing
```bash
# Start analysis
curl -X POST "http://localhost:8000/api/analyze/url" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://google.com"}'

# Get results (use job_id from above)
curl "http://localhost:8000/api/results/{job_id}"
```

### 3. Example URLs for Testing

**Safe URLs:**
- https://www.google.com
- https://github.com
- https://stackoverflow.com

**URLs that trigger security features:**
- URLs with IP addresses
- Very long URLs
- URLs with suspicious keywords
- Sites with login forms

## 🔍 System Architecture

```
┌─────────────────┐    ┌─────────────────┐
│  Landing Website│    │  React Frontend │
│   (Port 8080)   │    │   (Port 3000)   │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────────────────────┼──────────────┐
                                 │              │
                    ┌─────────────────┐    ┌─────────────────┐
                    │  FastAPI Backend│    │  Worker Process │
                    │   (Port 8000)   │◄──►│   (Background)  │
                    └─────────────────┘    └─────────────────┘
                             │
                    ┌─────────────────┐
                    │   Data Layer    │
                    │                 │
                    │ PostgreSQL:5432 │
                    │ Redis:6379      │
                    │ MinIO:9000/9001 │
                    └─────────────────┘
```

## 🛠️ Development Setup

### Backend Development
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend Development
```bash
cd frontend
npm install
npm run dev
```

### Website Development
```bash
cd website
python server.py
```

## 🚀 Production Deployment

### Cloud Deployment (AWS/GCP/Azure)
1. **Container Registry**: Push images to your cloud registry
2. **Database**: Use managed PostgreSQL service
3. **Storage**: Use cloud object storage instead of MinIO
4. **Load Balancer**: Set up HTTPS and load balancing
5. **Environment**: Configure production environment variables

### Example Docker Compose for Production
```yaml
version: '3.8'
services:
  api:
    image: your-registry/fortai-backend:latest
    environment:
      - DATABASE_URL=postgresql://user:pass@your-db-host:5432/fortai
      - REDIS_URL=redis://your-redis-host:6379
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    ports:
      - "8000:8000"

  frontend:
    image: your-registry/fortai-frontend:latest
    environment:
      - VITE_API_URL=https://your-api-domain.com
    ports:
      - "3000:3000"

  website:
    image: your-registry/fortai-website:latest
    ports:
      - "8080:8080"
```

## 📊 Monitoring

### Health Checks
- Backend: http://localhost:8000/health
- Frontend: http://localhost:3000
- Website: http://localhost:8080/status

### Logs
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f api
docker-compose logs -f worker
```

### Performance Metrics
- Average analysis time: < 10 seconds
- Concurrent analyses: 10+
- Memory usage: ~2GB for full stack
- Storage: Screenshots and artifacts in MinIO

## 🔒 Security Considerations

### Production Security
1. **HTTPS**: Always use HTTPS in production
2. **API Keys**: Store in secure environment variables
3. **Database**: Use connection encryption
4. **Networks**: Isolate database networks
5. **Sandboxing**: Playwright runs in isolated containers

### Firewall Configuration
```bash
# Allow only necessary ports
ufw allow 80    # HTTP
ufw allow 443   # HTTPS
ufw allow 22    # SSH (if needed)
```

## 🔧 Troubleshooting

### Common Issues

**Docker Issues:**
```bash
# Rebuild containers
docker-compose down
docker-compose up --build

# Clear volumes
docker-compose down -v
```

**Port Conflicts:**
```bash
# Check port usage
netstat -tulpn | grep :8000

# Kill process using port
sudo kill -9 $(lsof -ti:8000)
```

**Database Issues:**
```bash
# Reset database
docker-compose down
docker volume rm fortai1_postgres_data
docker-compose up
```

### Getting Help
1. Check logs: `docker-compose logs`
2. Verify environment variables in `backend/.env`
3. Ensure all required ports are available
4. Check Docker daemon is running

## 📈 Scaling

### Horizontal Scaling
- Deploy multiple worker instances
- Use load balancer for API endpoints
- Scale database with read replicas

### Performance Optimization
- Enable Redis caching
- Optimize Playwright screenshots
- Use CDN for static assets
- Implement request rate limiting

---

**Need help?** Check the logs and ensure all services are running properly.
**Ready to start?** Run `./start-website.sh` to launch the landing page!