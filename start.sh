#!/bin/bash

echo "Starting ForTAI URL Analysis MVP..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f backend/.env ]; then
    echo "Creating .env file from example..."
    cp backend/.env.example backend/.env
    echo "Please edit backend/.env with your API keys if you have them."
fi

# Build and start services
echo "Building and starting services..."
docker-compose up --build -d

echo ""
echo "ForTAI is starting up..."
echo ""
echo "Services will be available at:"
echo "  - Frontend (Chat UI): http://localhost:3000"
echo "  - Backend API: http://localhost:8000"
echo "  - API Documentation: http://localhost:8000/docs"
echo "  - MinIO Console: http://localhost:9001"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
echo ""
echo "Waiting for services to be ready..."

# Wait for services to be healthy
sleep 10

# Check if services are running
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ Backend API is ready"
else
    echo "⚠️  Backend API is not ready yet, may need more time"
fi

if curl -s http://localhost:3000 > /dev/null; then
    echo "✅ Frontend is ready"
else
    echo "⚠️  Frontend is not ready yet, may need more time"
fi

echo ""
echo "🚀 ForTAI MVP is ready! Open http://localhost:3000 to start analyzing URLs."