.PHONY: install run-api run-scheduler docker-up docker-down lint clean help

# Default target
help:
	@echo "AI Threat Intel - Available Commands"
	@echo "====================================="
	@echo ""
	@echo "  make install        Install Python dependencies"
	@echo "  make run-api        Start the API server (localhost:8000)"
	@echo "  make run-scheduler  Start the feed scheduler"
	@echo "  make docker-up      Start all services with Docker"
	@echo "  make docker-down    Stop Docker services"
	@echo "  make lint           Run code linting"
	@echo "  make clean          Clean up cache files"
	@echo ""

# Install dependencies
install:
	pip install -r requirements.txt

# Run API server locally
run-api:
	python -m uvicorn unified_api_server:app --reload --host 0.0.0.0 --port 8000

# Run the feed scheduler
run-scheduler:
	python -m threat_intel_aggregator.main

# Docker commands
docker-up:
	docker-compose up --build -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Linting (optional - requires ruff)
lint:
	@command -v ruff >/dev/null 2>&1 && ruff check . || echo "Install ruff: pip install ruff"

# Clean up
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
