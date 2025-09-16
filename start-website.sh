#!/bin/bash

echo "🌐 Starting ForTAI Landing Website..."
echo ""

# Check if Python is available
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "❌ Python is not installed or not in PATH"
    echo "Please install Python 3.x to run the website server"
    exit 1
fi

echo "✅ Using Python: $PYTHON_CMD"
echo ""

# Navigate to website directory
cd "$(dirname "$0")/website"

# Start the server
echo "🚀 Starting website server..."
echo "📱 Open your browser and go to: http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

$PYTHON_CMD server.py