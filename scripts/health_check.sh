#!/bin/bash

# Embedded Linux Network IDS
# Health Check Script

API_URL="http://127.0.0.1:8000/health"

echo "======================================"
echo " Embedded Linux Network IDS"
echo " Health Check"
echo "======================================"

if curl --silent --fail "$API_URL" > /dev/null; then
    echo "STATUS: HEALTHY"
    echo "FastAPI dashboard is responding."
    echo "URL: $API_URL"
    exit 0
else
    echo "STATUS: UNHEALTHY"
    echo "FastAPI dashboard is not responding."
    exit 1
fi

