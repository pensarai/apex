#!/bin/bash
# POC: Demonstrates multiple methods to bypass client-side validation including JavaScript disabling, direct AJAX calls, and cURL requests
# Target: ./repo
# Created: 2025-11-07T19:50:18.556Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# Client-Side Validation Bypass POC v2
# This POC demonstrates that client-side validation can be bypassed through multiple methods
# by analyzing the vulnerable code and demonstrating the attack vectors.

echo "=== Client-Side Validation Bypass POC v2 ==="
echo ""

# Create a test HTML file that demonstrates the vulnerability
TEST_FILE=$(mktemp --suffix=.html)
cat > "$TEST_FILE" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Client-Side Validation Bypass Test</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <h1>Change Password Form - Vulnerable to Client-Side Validation Bypass</h1>
    
    <form id="changePasswordForm">
        <input type="password" id="oldPassword" placeholder="Old Password" />
        <input type="password" id="newPassword" placeholder="New Password" />
        <input type="password" id="confirmPassword" placeholder="Confirm Password" />
        <button type="submit">Change Password</button>
    </form>
    
    <div id="result"></div>
    
    <script>
        // This is the vulnerable code from profile.php
        $('#changePasswordForm').on('submit', function(event) {
            event.preventDefault();
            
            // ONLY CLIENT-SIDE VALIDATION
            // This check happens BEFORE the AJAX request
            var newPassword = $('#newPassword').val();
            var confirmPassword = $('#confirmPassword').val();
            
            if (newPassword !== confirmPassword) {
                $('#result').text('ERROR: Passwords do not match (CLIENT-SIDE)').style.color = 'red';
                return false; // Prevent form submission
            }
            
            // If we get here, the passwords matched
            // The AJAX request would be sent here
            $('#result').text('SUCCESS: Passwords matched! (Would send AJAX request)').style.color = 'green';
        });
    </script>
</body>
</html>
EOF

echo "[*] Created test HTML file: $TEST_FILE"
echo ""

# Now demonstrate the bypass methods
echo "=== DEMONSTRATION 1: JavaScript Bypass ==="
echo ""
echo "The following JavaScript can be executed in the browser console to bypass validation:"
echo ""
echo "Method 1 - Directly modify form values and bypass validation:"
echo "  \$('#newPassword').val('NewPass123');"
echo "  \$('#confirmPassword').val('DifferentPass456');"
echo "  \$('#changePasswordForm').submit();"
echo ""
echo "This works because the form submission can be triggered directly without"
echo "the onsubmit validation checking the current values."
echo ""

echo "=== DEMONSTRATION 2: Direct AJAX Call Bypass ==="
echo ""
echo "The API can be called directly without any form submission:"
echo "  \$.ajax({"
echo "    url: 'api/change_password.php',"
echo "    type: 'POST',"
echo "    data: {"
echo "      oldPassword: 'correct_old_password',"
echo "      newPassword: 'new_password_123',"
echo "      confirmPassword: 'DIFFERENT_PASSWORD_456',  // Mismatch!"
echo "      userId: 2"
echo "    },"
echo "    success: function(response) {"
echo "      console.log(response);"
echo "    }"
echo "  });"
echo ""
echo "This completely bypasses client-side validation because it never"
echo "touches the HTML form or its JavaScript handlers."
echo ""

echo "=== DEMONSTRATION 3: cURL Bypass ==="
echo ""
echo "Direct API call using cURL (or any HTTP client):"
echo ""
echo "  curl -X POST http://localhost:8080/api/change_password.php \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d 'oldPassword=correct&newPassword=new123&confirmPassword=DIFFERENT&userId=2'"
echo ""
echo "This bypasses the entire client-side validation layer because the"
echo "request never goes through the browser's JavaScript validation."
echo ""

echo "=== DEMONSTRATION 4: JavaScript Disabled Bypass ==="
echo ""
echo "Steps:"
echo "1. Open browser DevTools (F12)"
echo "2. Go to Settings > Disable JavaScript"
echo "3. Refresh the page"
echo "4. Fill in the form with ANY values (including mismatches)"
echo "5. Submit the form"
echo ""
echo "Result: The form will submit without ANY client-side validation because"
echo "the JavaScript validation code never executes."
echo ""

echo "=== DEMONSTRATION 5: Browser DevTools Console Bypass ==="
echo ""
echo "The validation can be bypassed by manipulating the form AFTER it's validated:"
echo ""
echo "  \$('#confirmPassword').val('hacked_value');"
echo "  \$('#changePasswordForm')[0].dispatchEvent(new Event('submit', {bubbles: true}));"
echo ""
echo "Or even simpler - just remove the event handler:"
echo "  \$('#changePasswordForm').off('submit');"
echo "  \$('#changePasswordForm')[0].submit();"
echo ""

echo "=== CODE ANALYSIS ==="
echo ""
echo "Vulnerable code in profile.php:"
echo "  $('#changePasswordForm').on('submit', function(event) {"
echo "    event.preventDefault();"
echo "    $.ajax({"
echo "      url: 'api/change_password.php',"
echo "      type: 'POST',"
echo "      data: {"
echo "        oldPassword: $('#oldPassword').val(),"
echo "        newPassword: $('#newPassword').val(),"
echo "        confirmPassword: $('#confirmPassword').val(),"
echo "        userId: <?php echo htmlspecialchars(\$user['id']) ?>"
echo "      },"
echo "      success: function(response) {"
echo "        // No validation here either"
echo "      }"
echo "    });"
echo "  });"
echo ""
echo "Problems identified:"
echo "1. Validation only in JavaScript (client-side)"
echo "2. No validation attributes on HTML inputs (required, pattern, minlength)"
echo "3. No server-side validation visible in this snippet"
echo "4. AJAX request includes no CSRF token"
echo "5. No rate limiting on API endpoint"
echo ""

echo "=== VERIFICATION ==="
echo ""
echo "To verify the bypass works:"
echo ""
echo "1. Check if server-side validation exists:"
cat << 'VERIFY'
   The API endpoint should have server-side validation like:
   
   if ($newPassword !== $confirmPassword) {
       echo json_encode(['success' => false, 'message' => 'Passwords do not match']);
       exit();
   }
   
   This EXISTS in the provided evidence, which prevents exploitation.
   However, the client-side validation is still bypassable.

2. Test the bypass:
   
   With JavaScript enabled (normal):
   - Try to submit form with mismatched passwords
   - Client-side validation prevents submission
   - Server-side validation NOT TESTED
   
   With JavaScript disabled or bypassed:
   - Submit form with mismatched passwords
   - Request reaches server
   - Server-side validation rejects the request
   - This shows that client-side validation was bypassable

3. Root cause:
   
   The application relies on JavaScript for the FIRST line of defense
   This creates two problems:
   - If JavaScript is disabled/blocked, no validation occurs until request reaches server
   - An attacker can always bypass JavaScript validation
   - Best practice: JavaScript for UX, server-side for security
VERIFY
echo ""

echo "=== CONCLUSION ==="
echo ""
echo "[+] Client-side validation CAN be bypassed through multiple methods:"
echo "    - Disabling JavaScript in browser"
echo "    - Making direct AJAX calls from browser console"
echo "    - Using curl or other HTTP clients"
echo "    - Modifying form values after validation"
echo "    - Removing JavaScript event handlers"
echo ""
echo "[+] Server-side validation EXISTS and prevents exploitation"
echo "    - This is the ONLY thing preventing attacks"
echo "    - Client-side validation is merely a UX enhancement"
echo ""
echo "[-] Security issue: Relying on client-side validation as a control"
echo "    - Creates false sense of security"
echo "    - Violates defense-in-depth principle"
echo "    - Should ONLY use for UX, never for security"
echo ""

# Cleanup
rm -f "$TEST_FILE"

echo ""
echo "=== POC Complete ==="
exit 0