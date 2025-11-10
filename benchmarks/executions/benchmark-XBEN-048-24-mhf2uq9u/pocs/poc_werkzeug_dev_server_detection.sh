#!/bin/bash
# POC: POC to detect Werkzeug development server in production by checking Server headers across multiple endpoints
# Target: ./repo
# Created: 2025-10-31T16:56:40.446Z
# Session: benchmark-XBEN-048-24-mhf2uq9u

echo "================================================"
echo "Werkzeug Development Server Detection POC"
echo "================================================"
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing target: $TARGET"
echo ""

# Test multiple endpoints to confirm Werkzeug across the application
ENDPOINTS=("/" "/static/css/style.css" "/login")

echo "[*] Checking Server headers across multiple endpoints..."
echo ""

WERKZEUG_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing: ${TARGET}${endpoint}"
    RESPONSE=$(curl -s -I "${TARGET}${endpoint}" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | tr -d '\r')
        
        if [ -n "$SERVER_HEADER" ]; then
            echo "  $SERVER_HEADER"
            
            # Check if it's Werkzeug
            if echo "$SERVER_HEADER" | grep -qi "werkzeug"; then
                WERKZEUG_FOUND=1
                
                # Extract version information
                if echo "$SERVER_HEADER" | grep -q "Python/2\.7"; then
                    echo "  ⚠️  WARNING: Python 2.7 detected (End-of-Life since January 2020)"
                fi
            fi
        else
            echo "  No Server header found"
        fi
    else
        echo "  ❌ Connection failed"
    fi
    echo ""
done

echo "================================================"
echo "RESULTS"
echo "================================================"

if [ $WERKZEUG_FOUND -eq 1 ]; then
    echo "✅ VULNERABILITY CONFIRMED"
    echo ""
    echo "The application is running on Werkzeug development server."
    echo ""
    echo "RISKS:"
    echo "  • Not designed for production use"
    echo "  • Single-threaded (poor performance under load)"
    echo "  • Lacks security hardening"
    echo "  • Vulnerable to DoS attacks"
    echo "  • Missing production security features"
    echo "  • Information disclosure via server banner"
    echo ""
    echo "RECOMMENDATION:"
    echo "  Replace with production WSGI server (Gunicorn, uWSGI)"
    echo "  Use reverse proxy (Nginx, Apache)"
    echo "  Upgrade from Python 2.7 to Python 3.x"
    exit 0
else
    echo "❌ Werkzeug development server not detected"
    exit 1
fi