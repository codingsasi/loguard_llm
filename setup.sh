#!/bin/bash
# LoguardLLM Setup Script

set -e

echo "🛡️  LoguardLLM Setup"
echo "===================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✓ Docker is running"
echo ""

# Build and start containers
echo "📦 Building Docker containers..."
docker-compose build

echo ""
echo "🚀 Starting services..."
docker-compose up -d

echo ""
echo "⏳ Waiting for Ollama to be ready..."
sleep 10

# Pull LLM models
echo ""
echo "📥 Pulling LLM models (this may take a while)..."
echo "   - mistral:7b-instruct (~4GB)"
docker exec loguard_ollama ollama pull mistral:7b-instruct

echo "   - nomic-embed-text (~274MB)"
docker exec loguard_ollama ollama pull nomic-embed-text

# Run Django migrations
echo ""
echo "🗄️  Running database migrations..."
docker exec loguard_app python manage.py migrate

# Create superuser prompt
echo ""
echo "👤 Create admin user for Django dashboard"
docker exec -it loguard_app python manage.py createsuperuser

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Access dashboard: http://localhost:8000/admin"
echo "   2. Configure settings in Django admin"
echo "   3. Run analyzer: docker exec -it loguard_app python manage.py run_analyzer --help"
echo ""
echo "📖 See README.md for detailed usage instructions"
