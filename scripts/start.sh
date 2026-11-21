#!/bin/bash

# Embedded Linux Network IDS
# FastAPI Dashboard Startup Script

PROJECT_DIR="$HOME/embedded-ids"
PYTHON="$PROJECT_DIR/.venv/bin/python"

echo "======================================"
echo " Embedded Linux Network IDS"
echo " Starting FastAPI Dashboard"
echo "======================================"

cd "$PROJECT_DIR" || exit 1

if [ ! -x "$PYTHON" ]; then
    echo "ERROR: Python virtual environment not found!"
    exit 1
fi

exec "$PYTHON" -m uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 8000
